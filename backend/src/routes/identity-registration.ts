import crypto from "node:crypto";
import type { Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { getDb } from "../db/mongo";
import { ensureTtlIndexes } from "../db/indexes";
import { config } from "../config";
import { getTrustedClientIp, hasDangerousMongoKeys } from "../utils/security";
import {
  normalizeRegistrationEmail,
  computeEmailLookup,
  computeBrowserBindingHash,
  generateOtpCode,
  computeOtpVerifier,
  encryptMailPayload,
  encryptContactEmail,
  decryptContactEmail,
} from "../identity/registration-crypto";
import { reserveMailSendBudgets } from "../identity/registration-budgets";
import { runMailOutboxPass, isMailWorkerAutoDispatchEnabled } from "../identity/mail-service";
import {
  BROWSER_COOKIE,
  PROOF_COOKIE,
  cookieSecurityOpts,
  getRequestId,
  runInTxnIfSupported,
} from "./identity-registration-shared";

export async function handleRegistrationStart(c: Context): Promise<Response> {
  const requestId = getRequestId(c);
  if (config.identity.registrationMode !== "verified") {
    return c.json({ error: "registration_disabled", code: "ERR_REGISTRATION_DISABLED", requestId }, 403);
  }
  const body = await c.req.raw.clone().json().catch(() => null);
  if (!body || typeof body !== "object" || hasDangerousMongoKeys(body)) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_BODY", requestId }, 400);
  }
  const email = normalizeRegistrationEmail(body.email);
  const termsVersion = typeof body.acceptedTermsVersion === "string" ? body.acceptedTermsVersion.trim() : "";
  if (!email || !termsVersion) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }

  let rawBrowser = getCookie(c, BROWSER_COOKIE);
  if (!rawBrowser) {
    rawBrowser = crypto.randomBytes(24).toString("base64url");
    setCookie(c, BROWSER_COOKIE, rawBrowser, cookieSecurityOpts(config.identity.intentTtlSeconds));
  }
  const browserBindingHash = computeBrowserBindingHash(rawBrowser);
  const emailLookup = computeEmailLookup(email);
  const idempotencyHeader = c.req.header("idempotency-key")?.trim();
  const clientIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);

  await ensureTtlIndexes();
  const database = await getDb();

  if (idempotencyHeader) {
    const idemLookup = `start:${browserBindingHash}:${idempotencyHeader}`;
    const existingIntent = await database.collection("registration_intents").findOne({ idempotencyKey: idemLookup });
    if (existingIntent?.intentId) {
      return c.json({
        accepted: true, intentId: existingIntent.intentId,
        expiresInSeconds: config.identity.intentTtlSeconds,
        codeExpiresInSeconds: config.identity.otpTtlSeconds,
        resendCooldownSeconds: config.identity.mailResendSeconds,
        requestId,
      }, 202);
    }
  }

  const nowMs = Date.now();
  const now = new Date(nowMs);
  const intentTtlSec = config.identity.intentTtlSeconds;
  const otpTtlSec = config.identity.otpTtlSeconds;
  const expiresAt = new Date(nowMs + intentTtlSec * 1000);
  const otpExpiresAt = new Date(Math.min(nowMs + otpTtlSec * 1000, expiresAt.getTime()));
  const intentId = crypto.randomBytes(16).toString("base64url");
  const code = generateOtpCode();
  const jobId = crypto.randomUUID();
  const outboxIdempotencyKey = idempotencyHeader ? `start:${browserBindingHash}:${idempotencyHeader}` : `job:${jobId}`;

  try {
    const txOutcome = await runInTxnIfSupported(database, async (session) => {
      const budget = await reserveMailSendBudgets(database, { emailLookup, clientIp, browserBindingHash, nowMs }, session);
      if (!budget.allowed) {
        return { throttled: true as const, retryAfterSeconds: budget.retryAfterSeconds ?? 60 };
      }
      const suppressed = await database.collection("mail_suppressions").findOne({ emailLookup, active: true }, session ? { session } : {});
      const otpVerifier = computeOtpVerifier({ purpose: "registration", intentId, generation: 1, emailLookup, code });
      await database.collection("registration_intents").insertOne({
        intentId, emailLookup,
        idempotencyKey: idempotencyHeader ? outboxIdempotencyKey : undefined,
        encryptedEmail: encryptContactEmail(email, { intentId, emailLookup }),
        browserBindingHash, purpose: "registration", termsVersion,
        oauthTransactionId: typeof body.oauthTransactionId === "string" ? body.oauthTransactionId.slice(0, 128) : null,
        invitationHandle: typeof body.invitationHandle === "string" ? body.invitationHandle.slice(0, 128) : null,
        status: "pending", generation: 1, otpVerifier, otpExpiresAt, attemptCount: 0, resendCount: 0,
        lastSentAt: now, expiresAt, createdAt: now, updatedAt: now,
      }, session ? { session } : {});

      if (!suppressed) {
        const encryptedPayload = encryptMailPayload({
          email, code, purpose: "registration", templateVersion: "v1",
          requestContext: "Verify your email address to prepare account registration",
          expiresMinutes: Math.max(1, Math.round(otpTtlSec / 60)),
        }, { jobId, generation: 1, purpose: "registration" });
        await database.collection("mail_outbox").insertOne({
          jobId, operationId: requestId, idempotencyKey: outboxIdempotencyKey, purpose: "registration",
          templateVersion: "v1", emailLookup, encryptedPayload, intentId, generation: 1,
          deadline: otpExpiresAt, status: "queued", attemptCount: 0, fence: 0, nextAttemptAt: now, createdAt: now, updatedAt: now,
        }, session ? { session } : {});
      }
      return { throttled: false as const };
    });

    if (txOutcome.throttled) {
      c.header("Retry-After", String(txOutcome.retryAfterSeconds));
      return c.json({ error: "rate_limited", code: "ERR_MAIL_RATE_LIMITED", retryAfterSeconds: txOutcome.retryAfterSeconds, requestId }, 429);
    }
  } catch (err: any) {
    console.error("[REG_START] Storage/budget reservation failed:", err?.message || err);
    return c.json({ error: "service_unavailable", code: "ERR_MAIL_UNAVAILABLE", retryAfterSeconds: 60, requestId }, 503);
  }

  if (isMailWorkerAutoDispatchEnabled()) {
    void runMailOutboxPass(5).catch(() => {});
  }

  return c.json({
    accepted: true, intentId, expiresInSeconds: intentTtlSec, codeExpiresInSeconds: otpTtlSec,
    resendCooldownSeconds: config.identity.mailResendSeconds, requestId,
  }, 202);
}

export async function handleRegistrationResend(c: Context): Promise<Response> {
  const requestId = getRequestId(c);
  if (config.identity.registrationMode !== "verified") {
    return c.json({ error: "registration_disabled", code: "ERR_REGISTRATION_DISABLED", requestId }, 403);
  }
  const rawBrowser = getCookie(c, BROWSER_COOKIE);
  const body = await c.req.raw.clone().json().catch(() => null);
  const intentId = typeof body?.intentId === "string" ? body.intentId.trim() : "";
  const email = body?.email !== undefined ? normalizeRegistrationEmail(body.email) : undefined;
  if (!rawBrowser || !intentId || (body?.email !== undefined && !email)) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_REQUEST", requestId }, 400);
  }

  const browserBindingHash = computeBrowserBindingHash(rawBrowser);
  const clientIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
  await ensureTtlIndexes();
  const database = await getDb();
  const nowMs = Date.now();
  const now = new Date(nowMs);
  setCookie(c, PROOF_COOKIE, "", cookieSecurityOpts(0, "/api/identity"));

  try {
    const txOutcome = await runInTxnIfSupported(database, async (session) => {
      const opt = session ? { session } : {};
      const intent = await database.collection("registration_intents").findOne({ intentId, browserBindingHash }, opt);
      if (!intent) return { kind: "not_found" as const };
      if (nowMs >= new Date(intent.expiresAt).getTime() || (intent.status !== "pending" && intent.status !== "verified")) {
        return { kind: "expired" as const };
      }
      if (email && computeEmailLookup(email) !== intent.emailLookup) {
        return { kind: "email_mismatch" as const };
      }

      const budget = await reserveMailSendBudgets(database, { emailLookup: intent.emailLookup, clientIp, browserBindingHash, nowMs }, session);
      if (!budget.allowed) return { kind: "throttled" as const, retryAfterSeconds: budget.retryAfterSeconds ?? 60 };

      const nextGen = (intent.generation ?? 1) + 1;
      const otpExpiresAt = new Date(Math.min(nowMs + config.identity.otpTtlSeconds * 1000, new Date(intent.expiresAt).getTime()));
      const nextCode = generateOtpCode();
      const nextVerifier = computeOtpVerifier({ purpose: "registration", intentId, generation: nextGen, emailLookup: intent.emailLookup, code: nextCode });

      await database.collection("registration_intents").updateOne(
        { intentId, browserBindingHash, generation: intent.generation },
        {
          $set: { status: "pending", generation: nextGen, otpVerifier: nextVerifier, otpExpiresAt, attemptCount: 0, lastSentAt: now, updatedAt: now },
          $inc: { resendCount: 1 },
          $unset: { proofDigest: "", proofExpiresAt: "", verifiedAt: "" },
        },
        opt
      );

      await database.collection("mail_outbox").updateMany(
        { intentId, generation: { $lt: nextGen }, status: "queued" },
        { $set: { status: "discarded", dropReason: "superseded_by_resend", updatedAt: now }, $unset: { encryptedPayload: "" } },
        opt
      );

      const suppressed = await database.collection("mail_suppressions").findOne({ emailLookup: intent.emailLookup, active: true }, opt);
      if (!suppressed) {
        const jobId = crypto.randomUUID();
        const targetEmail = email || (intent.encryptedEmail ? decryptContactEmail(intent.encryptedEmail, { intentId, emailLookup: intent.emailLookup }) : null);
        if (targetEmail) {
          const encryptedPayload = encryptMailPayload({
            email: targetEmail, code: nextCode, purpose: "registration", templateVersion: "v1",
            requestContext: "Verify your email address (resent code)",
            expiresMinutes: Math.max(1, Math.round(config.identity.otpTtlSeconds / 60)),
          }, { jobId, generation: nextGen, purpose: "registration" });
          await database.collection("mail_outbox").insertOne({
            jobId, operationId: requestId, idempotencyKey: `resend:${intentId}:${nextGen}`, purpose: "registration",
            templateVersion: "v1", emailLookup: intent.emailLookup, encryptedPayload, intentId, generation: nextGen,
            deadline: otpExpiresAt, status: "queued", attemptCount: 0, fence: 0, nextAttemptAt: now, createdAt: now, updatedAt: now,
          }, opt);
        }
      }
      return { kind: "ok" as const };
    });

    if (txOutcome.kind === "not_found") return c.json({ error: "not_found", code: "ERR_INTENT_NOT_FOUND", requestId }, 404);
    if (txOutcome.kind === "email_mismatch") return c.json({ error: "invalid_request", code: "ERR_START_NEW_INTENT_FOR_EMAIL", requestId }, 400);
    if (txOutcome.kind === "expired") return c.json({ error: "expired", code: "ERR_INTENT_EXPIRED", requestId }, 400);
    if (txOutcome.kind === "throttled") {
      c.header("Retry-After", String(txOutcome.retryAfterSeconds));
      return c.json({ error: "rate_limited", code: "ERR_MAIL_RATE_LIMITED", retryAfterSeconds: txOutcome.retryAfterSeconds, requestId }, 429);
    }
  } catch (err: any) {
    console.error("[REG_RESEND] Storage/budget failure:", err?.message || err);
    return c.json({ error: "service_unavailable", code: "ERR_MAIL_UNAVAILABLE", retryAfterSeconds: 60, requestId }, 503);
  }

  if (isMailWorkerAutoDispatchEnabled()) {
    void runMailOutboxPass(5).catch(() => {});
  }
  return c.json({ accepted: true, intentId, resendCooldownSeconds: config.identity.mailResendSeconds, requestId }, 202);
}
