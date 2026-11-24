import crypto from "node:crypto";
import type { Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { hasDangerousMongoKeys } from "../utils/security";
import {
  computeBrowserBindingHash,
  verifyOtpVerifier,
  digestToken,
} from "../identity/registration-crypto";
import { consumeVerifyAttemptBudget } from "../identity/registration-budgets";
import { BROWSER_COOKIE, PROOF_COOKIE, cookieSecurityOpts, getRequestId } from "./identity-registration-shared";

export async function handleRegistrationVerify(c: Context): Promise<Response> {
  const requestId = getRequestId(c);
  if (config.identity.registrationMode !== "verified") {
    return c.json({ error: "registration_disabled", code: "ERR_REGISTRATION_DISABLED", requestId }, 403);
  }
  const rawBrowser = getCookie(c, BROWSER_COOKIE);
  if (!rawBrowser) {
    return c.json({ error: "unauthorized", code: "ERR_BROWSER_BINDING_REQUIRED", requestId }, 403);
  }
  const body = await c.req.raw.clone().json().catch(() => null);
  if (!body || typeof body !== "object" || hasDangerousMongoKeys(body)) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_BODY", requestId }, 400);
  }
  const intentId = typeof body.intentId === "string" ? body.intentId.trim() : "";
  const code = typeof body.code === "string" ? body.code.trim() : "";
  if (!intentId || typeof body.code !== "string") {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }

  const database = await getDb();
  const browserBindingHash = computeBrowserBindingHash(rawBrowser);
  const intentsCol = database.collection("registration_intents");
  const intent = await intentsCol.findOne({ intentId, browserBindingHash });
  if (!intent) {
    return c.json({ error: "invalid_code", code: "ERR_OTP_INVALID", requestId }, 400);
  }

  const nowMs = Date.now();
  const now = new Date(nowMs);
  if (nowMs >= new Date(intent.expiresAt).getTime() || nowMs >= new Date(intent.otpExpiresAt).getTime()) {
    if (intent.status === "pending") {
      await intentsCol.updateOne(
        { intentId, status: "pending" },
        { $set: { status: "expired", updatedAt: now }, $unset: { encryptedEmail: "", proofDigest: "", proofExpiresAt: "" } }
      );
    }
    return c.json({ error: "expired", code: "ERR_OTP_EXPIRED", requestId }, 400);
  }

  const maxAttempts = config.identity.otpMaxAttempts;
  if (intent.status !== "pending" || (intent.attemptCount ?? 0) >= maxAttempts) {
    return c.json({
      error: "invalid_code",
      code: intent.status === "exhausted" ? "ERR_OTP_EXHAUSTED" : "ERR_OTP_UNAVAILABLE",
      remainingAttempts: 0,
      requestId,
    }, 400);
  }

  const aggBudget = await consumeVerifyAttemptBudget(database, intent.emailLookup, nowMs);
  if (!aggBudget.allowed) {
    c.header("Retry-After", String(aggBudget.retryAfterSeconds ?? 60));
    return c.json({ error: "rate_limited", code: "ERR_VERIFY_RATE_LIMITED", retryAfterSeconds: aggBudget.retryAfterSeconds, requestId }, 429);
  }

  const isSyntaxValid = /^\d{6}$/.test(code);
  const isValid = isSyntaxValid && verifyOtpVerifier(intent.otpVerifier, {
    purpose: "registration", intentId, generation: intent.generation, emailLookup: intent.emailLookup, code,
  });

  if (!isValid) {
    const failedUpdate = await intentsCol.findOneAndUpdate(
      {
        intentId, browserBindingHash, status: "pending", generation: intent.generation,
        attemptCount: { $lt: maxAttempts }, otpExpiresAt: { $gt: now }, expiresAt: { $gt: now },
      },
      [
        {
          $set: {
            attemptCount: { $add: [{ $ifNull: ["$attemptCount", 0] }, 1] },
            status: { $cond: [{ $gte: [{ $add: [{ $ifNull: ["$attemptCount", 0] }, 1] }, maxAttempts] }, "exhausted", "pending"] },
            updatedAt: now,
          },
        },
      ],
      { returnDocument: "after" }
    );
    const updatedDoc = failedUpdate && (failedUpdate.value !== undefined ? failedUpdate.value : failedUpdate);
    const remaining = updatedDoc ? Math.max(0, maxAttempts - (updatedDoc.attemptCount ?? maxAttempts)) : 0;
    return c.json({ error: "invalid_code", code: remaining === 0 ? "ERR_OTP_EXHAUSTED" : "ERR_OTP_INVALID", remainingAttempts: remaining, requestId }, 400);
  }

  const rawProof = crypto.randomBytes(32).toString("base64url");
  const proofDigest = digestToken(rawProof, "proof");
  const proofExpiresAt = new Date(Math.min(nowMs + config.identity.proofTtlSeconds * 1000, new Date(intent.expiresAt).getTime()));
  const win = await intentsCol.findOneAndUpdate(
    {
      intentId, browserBindingHash, status: "pending", generation: intent.generation,
      attemptCount: { $lt: maxAttempts }, otpExpiresAt: { $gt: now }, expiresAt: { $gt: now },
    },
    { $set: { status: "verified", proofDigest, proofExpiresAt, verifiedAt: now, updatedAt: now } },
    { returnDocument: "after" }
  );
  const committedDoc = win && (win.value !== undefined ? win.value : win);
  if (!committedDoc) {
    return c.json({ error: "conflict", code: "ERR_OTP_ALREADY_CONSUMED", requestId }, 409);
  }

  const proofMaxAge = Math.max(1, Math.floor((proofExpiresAt.getTime() - nowMs) / 1000));
  setCookie(c, PROOF_COOKIE, rawProof, cookieSecurityOpts(proofMaxAge, "/api/identity"));
  return c.json({
    verified: true,
    intentId,
    proofExpiresInSeconds: proofMaxAge,
    nextStep: "complete_profile_pending_p2b",
    requestId,
  });
}
