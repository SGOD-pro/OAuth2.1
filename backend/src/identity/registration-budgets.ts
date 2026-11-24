import crypto from "node:crypto";
import { config } from "../config";

const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;
const THIRTY_MINUTES_MS = 30 * 60 * 1000;
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

export interface BudgetCheckResult {
  allowed: boolean;
  retryAfterSeconds?: number;
  reason?: string;
}

function hashBucket(scope: string, rawKey: string): string {
  return crypto.createHash("sha256").update(`${scope}:${rawKey}`).digest("hex").slice(0, 32);
}

async function consumeFixedWindowCounter(
  database: any,
  key: string,
  limit: number,
  windowMs: number,
  nowMs: number,
  session?: any
): Promise<{ allowed: boolean; retryAfterSeconds: number }> {
  const now = new Date(nowMs);
  const cutoff = new Date(nowMs - windowMs);
  const expiresAt = new Date(nowMs + windowMs);
  const col = database.collection("mail_budgets");
  const opt = session ? { session } : {};

  const existing = await col.findOne({ _id: key }, opt);
  if (!existing) {
    try {
      await col.insertOne({ _id: key, count: 1, windowStartedAt: now, expiresAt }, opt);
      return { allowed: true, retryAfterSeconds: 0 };
    } catch (err: any) {
      if (err?.code !== 11000 || session) throw err;
      // Concurrent first-request winner inserted outside a transaction; fall through cleanly
      const raced = await col.findOne({ _id: key });
      const racedStart = raced?.windowStartedAt ? new Date(raced.windowStartedAt).getTime() : nowMs;
      const updated = await col.findOneAndUpdate(
        { _id: key, count: { $lt: limit } },
        { $inc: { count: 1 }, $set: { expiresAt } },
        { returnDocument: "after" }
      );
      const doc = updated && (updated.value !== undefined ? updated.value : updated);
      if (!doc) {
        return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((racedStart + windowMs - nowMs) / 1000)) };
      }
      return { allowed: true, retryAfterSeconds: 0 };
    }
  }

  const startedMs = existing.windowStartedAt ? new Date(existing.windowStartedAt).getTime() : 0;
  if (startedMs <= cutoff.getTime()) {
    await col.updateOne({ _id: key }, { $set: { count: 1, windowStartedAt: now, expiresAt } }, opt);
    return { allowed: true, retryAfterSeconds: 0 };
  }

  const updated = await col.findOneAndUpdate(
    { _id: key, count: { $lt: limit } },
    { $inc: { count: 1 }, $set: { expiresAt } },
    { returnDocument: "after", ...opt }
  );
  const doc = updated && (updated.value !== undefined ? updated.value : updated);
  if (!doc) {
    const retryAfterSeconds = Math.max(1, Math.ceil((startedMs + windowMs - nowMs) / 1000));
    return { allowed: false, retryAfterSeconds };
  }
  return { allowed: true, retryAfterSeconds: 0 };
}

/**
 * Atomically reserves distributed send budgets within the same MongoDB transaction as
 * registration intent and mail_outbox writes. Fails closed on backing store failure.
 */
export async function reserveMailSendBudgets(
  database: any,
  params: { emailLookup: string; clientIp: string; browserBindingHash: string; nowMs?: number },
  session?: any
): Promise<BudgetCheckResult> {
  const nowMs = params.nowMs ?? Date.now();
  const cooldownSec = config.identity.mailResendSeconds;
  const cooldownMs = cooldownSec * 1000;
  const cooldownKey = `cooldown:${params.emailLookup}`;
  const opt = session ? { session } : {};
  const col = database.collection("mail_budgets");

  const existingCd = await col.findOne({ _id: cooldownKey }, opt);
  if (existingCd?.lastSentAt && new Date(existingCd.lastSentAt).getTime() > nowMs - cooldownMs) {
    const retry = Math.max(1, Math.ceil((new Date(existingCd.lastSentAt).getTime() + cooldownMs - nowMs) / 1000));
    return { allowed: false, retryAfterSeconds: retry, reason: "mailbox_cooldown" };
  }
  if (!existingCd) {
    await col.insertOne(
      { _id: cooldownKey, lastSentAt: new Date(nowMs), expiresAt: new Date(nowMs + cooldownMs * 2) },
      opt
    );
  } else {
    await col.updateOne(
      { _id: cooldownKey },
      { $set: { lastSentAt: new Date(nowMs), expiresAt: new Date(nowMs + cooldownMs * 2) } },
      opt
    );
  }

  const checks: Array<{ key: string; limit: number; windowMs: number; reason: string }> = [
    { key: `mb15:${params.emailLookup}`, limit: 3, windowMs: FIFTEEN_MINUTES_MS, reason: "mailbox_15m" },
    { key: `mbday:${params.emailLookup}`, limit: 10, windowMs: ONE_DAY_MS, reason: "mailbox_daily" },
    { key: `ip15:${hashBucket("ip", params.clientIp || "unknown")}`, limit: 10, windowMs: FIFTEEN_MINUTES_MS, reason: "ip_15m" },
    { key: `br15:${hashBucket("browser", params.browserBindingHash)}`, limit: 5, windowMs: FIFTEEN_MINUTES_MS, reason: "browser_15m" },
    { key: "global:daily", limit: config.identity.globalMailDailyBudget, windowMs: ONE_DAY_MS, reason: "global_daily" },
  ];

  for (const check of checks) {
    const r = await consumeFixedWindowCounter(database, check.key, check.limit, check.windowMs, nowMs, session);
    if (!r.allowed) {
      return { allowed: false, retryAfterSeconds: r.retryAfterSeconds, reason: check.reason };
    }
  }
  return { allowed: true };
}

/**
 * Checks whether the deployment-wide daily mail cap allows dispatching another message.
 */
export async function isGlobalMailBudgetAvailable(database: any): Promise<boolean> {
  const existing = await database.collection("mail_budgets").findOne({ _id: "global:daily" });
  if (!existing) return true;
  const cutoff = Date.now() - ONE_DAY_MS;
  if (existing.windowStartedAt && new Date(existing.windowStartedAt).getTime() <= cutoff) return true;
  return (existing.count ?? 0) <= config.identity.globalMailDailyBudget;
}

/**
 * Consumes one guess from the aggregate per-mailbox verification budget (10 guesses / 30 min).
 * Never resets when an OTP generation is resent.
 */
export async function consumeVerifyAttemptBudget(database: any, emailLookup: string, nowMs = Date.now()): Promise<BudgetCheckResult> {
  const r = await consumeFixedWindowCounter(database, `verify30:${emailLookup}`, 10, THIRTY_MINUTES_MS, nowMs);
  if (!r.allowed) {
    return { allowed: false, retryAfterSeconds: r.retryAfterSeconds, reason: "mailbox_verify_30m" };
  }
  return { allowed: true };
}
