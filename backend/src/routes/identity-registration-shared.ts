import crypto from "node:crypto";
import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { computeBrowserBindingHash } from "../identity/registration-crypto";

export const BROWSER_COOKIE = "swyra_reg_browser";
export const PROOF_COOKIE = "swyra_reg_proof";

export function getRequestId(c: Context): string {
  return (c.get("requestId" as never) as string) || crypto.randomUUID();
}

export function cookieSecurityOpts(maxAgeSec: number, path = "/") {
  return {
    httpOnly: true,
    sameSite: "Lax" as const,
    secure: config.env === "production",
    path,
    maxAge: Math.max(0, Math.floor(maxAgeSec)),
  };
}

export async function runInTxnIfSupported<T>(database: any, work: (session?: any) => Promise<T>): Promise<T> {
  const mongoClient = database?.client;
  if (mongoClient && typeof mongoClient.startSession === "function") {
    const session = mongoClient.startSession();
    try {
      let out!: T;
      await session.withTransaction(async () => {
        out = await work(session);
      });
      return out;
    } finally {
      await session.endSession().catch(() => {});
    }
  }
  return work(undefined);
}

export async function handleGetRegistrationConfig(c: Context): Promise<Response> {
  return c.json({
    registrationMode: config.identity.registrationMode,
    resendCooldownSeconds: config.identity.mailResendSeconds,
    otpTtlSeconds: config.identity.otpTtlSeconds,
    intentTtlSeconds: config.identity.intentTtlSeconds,
    proofTtlSeconds: config.identity.proofTtlSeconds,
  });
}

export async function handleGetRegistrationIntentStatus(c: Context): Promise<Response> {
  const requestId = getRequestId(c);
  if (config.identity.registrationMode !== "verified") {
    return c.json({ error: "registration_disabled", code: "ERR_REGISTRATION_DISABLED", requestId }, 403);
  }
  const rawBrowser = getCookie(c, BROWSER_COOKIE);
  const intentId = c.req.param("intentId");
  if (!rawBrowser || !intentId) {
    return c.json({ error: "unauthorized", code: "ERR_BROWSER_BINDING_REQUIRED", requestId }, 403);
  }
  const database = await getDb();
  const intent = await database.collection("registration_intents").findOne({
    intentId,
    browserBindingHash: computeBrowserBindingHash(rawBrowser),
  });
  if (!intent) {
    return c.json({ error: "not_found", code: "ERR_INTENT_NOT_FOUND", requestId }, 404);
  }
  const now = Date.now();
  const effectiveStatus = intent.status === "pending" && (now >= new Date(intent.expiresAt).getTime() || now >= new Date(intent.otpExpiresAt).getTime())
    ? "expired"
    : intent.status;
  return c.json({
    intentId: intent.intentId,
    status: effectiveStatus,
    expiresAt: new Date(intent.expiresAt).toISOString(),
    otpExpiresAt: new Date(intent.otpExpiresAt).toISOString(),
    resendAvailableAt: new Date(new Date(intent.lastSentAt).getTime() + config.identity.mailResendSeconds * 1000).toISOString(),
    remainingAttempts: Math.max(0, config.identity.otpMaxAttempts - (intent.attemptCount ?? 0)),
    requestId,
  });
}
