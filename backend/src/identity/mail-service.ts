import crypto from "node:crypto";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { isLoopbackHost } from "../utils/security";
import { decryptMailPayload, type OutboxMailPlaintext } from "./registration-crypto";
import { isGlobalMailBudgetAvailable } from "./registration-budgets";

export interface EmailMessage {
  to: string;
  from: string;
  subject: string;
  text: string;
  html: string;
  purpose: string;
  templateVersion: string;
}

export interface EmailSender {
  send(message: EmailMessage, idempotencyKey: string, deadlineMs: number): Promise<{ providerMessageId: string }>;
}

const PROVIDER_TIMEOUT_MS = 5000;
const MAX_DELIVERY_ATTEMPTS = 3;
const LEASE_DURATION_MS = 30_000;

const testSinkMessages: Array<EmailMessage & { idempotencyKey: string; providerMessageId: string; receivedAt: string }> = [];
let transportOverride: EmailSender | null = null;
let autoDispatchEnabled = true;

export function getTestMailSinkMessages() {
  return [...testSinkMessages];
}
export function clearTestMailSink(): void {
  testSinkMessages.length = 0;
}
export function setTestMailTransportOverride(sender: EmailSender | null): void {
  transportOverride = sender;
}
export function setMailWorkerAutoDispatchForTesting(enabled: boolean): void {
  autoDispatchEnabled = enabled;
}
export function isMailWorkerAutoDispatchEnabled(): boolean {
  return autoDispatchEnabled;
}

function escapeHtml(raw: string): string {
  return raw.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function renderRegistrationEmail(payload: OutboxMailPlaintext): EmailMessage {
  const codeSafe = escapeHtml(payload.code);
  const ctxSafe = escapeHtml(payload.requestContext || "Account registration");
  const expiresMin = Math.max(1, payload.expiresMinutes);
  return {
    to: payload.email,
    from: config.identity.mailFrom,
    subject: "SWYRA Auth verification code",
    text: `Your verification code is ${payload.code}. It expires in ${expiresMin} minutes.\nContext: ${payload.requestContext || "Account registration"}\nIf you did not request this code, you can ignore this message.`,
    html: `<p>Your verification code is <strong>${codeSafe}</strong>. It expires in ${expiresMin} minutes.</p><p>Context: ${ctxSafe}</p><p>If you did not request this code, you can ignore this message.</p>`,
    purpose: payload.purpose,
    templateVersion: payload.templateVersion,
  };
}

const defaultSender: EmailSender = {
  async send(message, idempotencyKey, deadlineMs) {
    const remaining = deadlineMs - Date.now();
    if (remaining <= 0) {
      const e: any = new Error("Deadline exceeded before transport send");
      e.permanent = true;
      e.category = "deadline_expired";
      throw e;
    }
    const timeoutMs = Math.min(PROVIDER_TIMEOUT_MS, remaining);
    const transport = config.identity.mailTransport;

    if (transport === "test_sink") {
      if (config.env === "production") {
        const e: any = new Error("test_sink is forbidden in production");
        e.permanent = true;
        e.category = "invalid_transport";
        throw e;
      }
      const sinkUrl = config.identity.mailTestSinkUrl;
      if (sinkUrl) {
        const u = new URL(sinkUrl);
        if (!isLoopbackHost(u.hostname)) {
          const e: any = new Error("Loopback host required for test sink URL");
          e.permanent = true;
          throw e;
        }
        const res = await fetch(sinkUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey },
          body: JSON.stringify({ to: message.to, subject: message.subject, text: message.text }),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!res.ok) {
          const e: any = new Error(`Test sink returned HTTP ${res.status}`);
          e.transient = res.status >= 500 || res.status === 429;
          throw e;
        }
        const data = await res.json().catch(() => ({}));
        return { providerMessageId: String((data as any).messageId || `sink-${crypto.randomUUID()}`) };
      }
      const providerMessageId = `sink-${crypto.randomUUID()}`;
      testSinkMessages.push({ ...message, idempotencyKey, providerMessageId, receivedAt: new Date().toISOString() });
      return { providerMessageId };
    }

    const endpoint = config.identity.mailProviderUrl;
    if (!endpoint) {
      const e: any = new Error("Mail provider endpoint not configured");
      e.transient = true;
      e.category = "provider_unconfigured";
      throw e;
    }
    const bodyStr = JSON.stringify({ ...message, idempotencyKey });
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomUUID();
    const digest = crypto.createHash("sha256").update(bodyStr).digest("hex");
    const sig = crypto.createHmac("sha256", config.identity.mailWebhookKeyRef).update(`${ts}.${nonce}.${digest}`).digest("hex");
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey, "X-Mail-Timestamp": ts, "X-Mail-Nonce": nonce, "X-Mail-Signature": sig },
      body: bodyStr,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) {
      const e: any = new Error(`Mail provider HTTP ${res.status}`);
      e.transient = res.status >= 500 || res.status === 429;
      e.permanent = res.status >= 400 && res.status < 500 && res.status !== 429;
      throw e;
    }
    const body = await res.json().catch(() => ({}));
    return { providerMessageId: String((body as any).messageId || `msg-${crypto.randomUUID()}`) };
  },
};

async function discardJob(col: any, jobId: string, leaseOwner: string, fence: number, reason: string): Promise<void> {
  await col.updateOne(
    { jobId, leaseOwner, fence, status: "sending" },
    { $set: { status: "discarded", dropReason: reason, updatedAt: new Date() }, $unset: { encryptedPayload: "" } }
  );
}

/**
 * Claims and processes a single due outbox job using monotonic lease fencing,
 * inline deadline checks, suppression checks, and bounded retries.
 */
export async function processNextMailOutboxJob(databaseArg?: any): Promise<boolean> {
  const database = databaseArg || await getDb();
  const outboxCol = database.collection("mail_outbox");
  const now = new Date();
  const leaseOwner = crypto.randomUUID();

  const claimed = await outboxCol.findOneAndUpdate(
    {
      $or: [
        { status: "queued", nextAttemptAt: { $lte: now } },
        { status: "sending", leaseExpiry: { $lt: now } },
      ],
    },
    {
      $set: { status: "sending", leaseOwner, leaseExpiry: new Date(now.getTime() + LEASE_DURATION_MS), updatedAt: now },
      $inc: { fence: 1 },
    },
    { sort: { nextAttemptAt: 1, createdAt: 1 }, returnDocument: "after" }
  );
  const job = claimed && (claimed.value !== undefined ? claimed.value : claimed);
  if (!job) return false;

  const fence = job.fence as number;
  const deadlineMs = new Date(job.deadline).getTime();
  if (deadlineMs <= Date.now()) {
    await discardJob(outboxCol, job.jobId, leaseOwner, fence, "deadline_expired");
    return true;
  }

  const [intent, suppression, globalOk] = await Promise.all([
    database.collection("registration_intents").findOne({ intentId: job.intentId }),
    database.collection("mail_suppressions").findOne({ emailLookup: job.emailLookup, active: true }),
    isGlobalMailBudgetAvailable(database),
  ]);

  if (!intent || intent.status !== "pending" || intent.generation !== job.generation || new Date(intent.otpExpiresAt).getTime() <= Date.now()) {
    await discardJob(outboxCol, job.jobId, leaseOwner, fence, "superseded_or_expired_intent");
    return true;
  }
  if (suppression) {
    await discardJob(outboxCol, job.jobId, leaseOwner, fence, "recipient_suppressed");
    return true;
  }
  if (!globalOk) {
    await discardJob(outboxCol, job.jobId, leaseOwner, fence, "global_daily_cap");
    return true;
  }
  if (!job.encryptedPayload) {
    await discardJob(outboxCol, job.jobId, leaseOwner, fence, "missing_payload");
    return true;
  }

  const plaintext = decryptMailPayload(job.encryptedPayload, { jobId: job.jobId, generation: job.generation, purpose: job.purpose });
  const message = renderRegistrationEmail(plaintext);
  const sender = transportOverride || defaultSender;
  const attemptsDone = (job.attemptCount ?? 0) + 1;

  try {
    const { providerMessageId } = await sender.send(message, job.idempotencyKey, deadlineMs);
    await outboxCol.updateOne(
      { jobId: job.jobId, leaseOwner, fence, status: "sending" },
      {
        $set: { status: "sent", providerMessageId, attemptCount: attemptsDone, sentAt: new Date(), updatedAt: new Date() },
        $unset: { encryptedPayload: "", leaseOwner: "", leaseExpiry: "" },
      }
    );
  } catch (err: any) {
    const remainingMs = deadlineMs - Date.now();
    const isTransient = err?.permanent !== true && (err?.transient === true || err?.name === "TimeoutError" || err?.name === "AbortError" || err instanceof TypeError);
    const canRetry = isTransient && attemptsDone < MAX_DELIVERY_ATTEMPTS && remainingMs > 20;
    if (canRetry) {
      const backoffMs = Math.min(Math.max(10, remainingMs - 10), Math.min(5000, 150 * (2 ** (attemptsDone - 1)) + crypto.randomInt(0, 100)));
      await outboxCol.updateOne(
        { jobId: job.jobId, leaseOwner, fence, status: "sending" },
        {
          $set: {
            status: "queued",
            attemptCount: attemptsDone,
            nextAttemptAt: new Date(Date.now() + backoffMs),
            lastErrorCategory: String(err?.category || "transient_error").slice(0, 64),
            updatedAt: new Date(),
          },
          $unset: { leaseOwner: "", leaseExpiry: "" },
        }
      );
    } else {
      await outboxCol.updateOne(
        { jobId: job.jobId, leaseOwner, fence, status: "sending" },
        {
          $set: {
            status: "dead_letter",
            attemptCount: attemptsDone,
            errorCategory: String(err?.category || (err?.permanent ? "permanent_error" : "attempts_or_deadline_exhausted")).slice(0, 64),
            failedAt: new Date(),
            updatedAt: new Date(),
          },
          $unset: { encryptedPayload: "", leaseOwner: "", leaseExpiry: "" },
        }
      );
    }
  }
  return true;
}

export async function runMailOutboxPass(maxJobs = 10): Promise<number> {
  const database = await getDb();
  let count = 0;
  for (let i = 0; i < maxJobs; i++) {
    const processed = await processNextMailOutboxJob(database);
    if (!processed) break;
    count++;
  }
  return count;
}
