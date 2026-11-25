import crypto from "node:crypto";
import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { ObjectId } from "mongodb";
import { makeSignature, symmetricDecrypt } from "better-auth/crypto";
import { getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { hasDangerousMongoKeys } from "../utils/security";
import { createRateLimiter } from "../middleware/rate-limit";
import { getBrowserSessionCookieName } from "../identity/browser-session-registry";
import { IdentityContextError, resolveOwnerDashboardContext } from "../identity/owner-contexts";
import { claimTotpTimeStep, releaseTotpTimeStep, TotpReplayError } from "../identity/totp-replay-guard";
import { digestToken } from "../identity/registration-crypto";

export const totpIpRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  prefix: "rl:totp:ip:",
  sensitivity: "auth",
});

export const totpSubjectRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  prefix: "rl:totp:subj:",
  sensitivity: "auth",
  keyFn: async (c: Context) => {
    const h = c.req.header("x-identity-context");
    return h ? digestToken(`totp-rl-v1:${h.trim()}`) : null;
  },
});

function getReqId(c: Context): string {
  return (c.get("requestId" as never) as string) || crypto.randomUUID();
}

async function buildBoundSessionHeaders(database: any, sessionId: string): Promise<Headers> {
  const filters: any[] = [{ id: sessionId }, { _id: sessionId }];
  if (ObjectId.isValid(sessionId)) filters.push({ _id: new ObjectId(sessionId) });
  const sessDoc = await database.collection("session").findOne({ $or: filters });
  if (!sessDoc?.token) throw new Error("ERR_SESSION_MISSING");
  const ctx = await authProvider.$context;
  const sig = await makeSignature(sessDoc.token, ctx.secret);
  const headers = new Headers();
  headers.set("cookie", `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${sessDoc.token}.${sig}`)}`);
  return headers;
}

export async function handleOwnerTotpEnable(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const body = await c.req.raw.clone().json().catch(() => null);
  if (!body || typeof body !== "object" || hasDangerousMongoKeys(body) || typeof body.password !== "string" || !body.password) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }
  const database = await getDb();
  const rawBrowserProof = getCookie(c, getBrowserSessionCookieName());
  const rawContextHandle = c.req.header("x-identity-context") || undefined;

  try {
    const { verified } = await resolveOwnerDashboardContext({
      database,
      engine: authProvider,
      rawBrowserProof,
      rawContextHandle,
    });
    const headers = await buildBoundSessionHeaders(database, verified.sessionId);
    const res = await (authProvider.api as any).enableTwoFactor({
      body: { password: body.password },
      headers,
      asResponse: true,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return c.json({ error: "request_rejected", code: data.code || "ERR_TOTP_ENABLE_FAILED", message: data.message, requestId }, res.status as any);
    }
    return c.json({ totpURI: data.totpURI, backupCodes: data.backupCodes, pending: true, requestId });
  } catch (err: any) {
    if (err instanceof IdentityContextError) {
      return c.json({ error: "unauthorized", code: err.code, message: err.message, requestId }, err.status as any);
    }
    return c.json({ error: "server_error", code: "ERR_TOTP_ENABLE_FAILED", requestId }, 500);
  }
}

export async function handleOwnerTotpVerify(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const body = await c.req.raw.clone().json().catch(() => null);
  if (!body || typeof body !== "object" || hasDangerousMongoKeys(body) || typeof body.code !== "string" || !body.code.trim()) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }
  const database = await getDb();
  const rawBrowserProof = getCookie(c, getBrowserSessionCookieName());
  const rawContextHandle = c.req.header("x-identity-context") || undefined;

  try {
    const { context, verified } = await resolveOwnerDashboardContext({
      database,
      engine: authProvider,
      rawBrowserProof,
      rawContextHandle,
    });
    const ctx = await authProvider.$context;
    const sessFilters: any[] = [{ userId: verified.userId }, ...(ObjectId.isValid(verified.userId) ? [{ userId: new ObjectId(verified.userId) }] : [])];
    const twoFactorDoc = await database.collection("twoFactor").findOne({ $or: sessFilters });
    if (!twoFactorDoc?.secret) {
      return c.json({ error: "invalid_request", code: "ERR_TOTP_NOT_PENDING", requestId }, 400);
    }
    const claimedStep = await claimTotpTimeStep({
      database,
      userId: verified.userId,
      purpose: "enroll",
    });

    const headers = await buildBoundSessionHeaders(database, verified.sessionId);
    const res = await (authProvider.api as any).verifyTOTP({
      body: { code: body.code.trim() },
      headers,
      asResponse: true,
    });
    if (!res.ok) {
      await releaseTotpTimeStep(database, verified.userId, claimedStep, "enroll");
      const errData = await res.json().catch(() => ({}));
      return c.json({ error: "unauthorized", code: errData.code || "ERR_TOTP_VERIFY_FAILED", requestId }, res.status as any);
    }

    const now = new Date();
    const rawSetCookie = res.headers.get("set-cookie") || "";
    const tokMatch = rawSetCookie.match(/(?:__Secure-)?better-auth\.session_token=([^;]+)/);
    let activeSessionId = verified.sessionId;
    if (tokMatch) {
      const rawTok = decodeURIComponent(tokMatch[1]).split(".")[0];
      const newSess = await database.collection("session").findOne({ token: rawTok }).catch(() => null);
      if (newSess) {
        activeSessionId = String(newSess.id || newSess._id);
        await database.collection("browser_session_sets").updateOne(
          { setId: context.setId, "entries.entryId": verified.entryId },
          { $set: { "entries.$.sessionId": activeSessionId, "entries.$.lastUsedAt": now } }
        );
      }
    }
    const sFilters: any[] = [{ id: activeSessionId }, { _id: activeSessionId }];
    if (ObjectId.isValid(activeSessionId)) sFilters.push({ _id: new ObjectId(activeSessionId) });
    await database.collection("session").updateOne({ $or: sFilters }, { $set: { mfaVerifiedAt: now, twoFactorVerified: true } });
    await database.collection("identity_contexts").updateOne({ contextId: context.contextId }, { $set: { revokedAt: now } });

    return c.json({ enabled: true, mfaVerifiedAt: now.toISOString(), requestId });
  } catch (err: any) {
    if (err instanceof IdentityContextError) {
      return c.json({ error: "unauthorized", code: err.code, message: err.message, requestId }, err.status as any);
    }
    if (err instanceof TotpReplayError) {
      return c.json({ error: "conflict", code: err.code, message: err.message, requestId }, err.status as any);
    }
    return c.json({ error: "server_error", code: "ERR_TOTP_VERIFY_FAILED", requestId }, 500);
  }
}

export async function handleOwnerTotpDisable(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const body = await c.req.raw.clone().json().catch(() => null);
  if (
    !body ||
    typeof body !== "object" ||
    hasDangerousMongoKeys(body) ||
    typeof body.password !== "string" ||
    !body.password ||
    typeof body.code !== "string" ||
    !body.code.trim()
  ) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }
  const database = await getDb();
  const rawBrowserProof = getCookie(c, getBrowserSessionCookieName());
  const rawContextHandle = c.req.header("x-identity-context") || undefined;

  try {
    const { verified } = await resolveOwnerDashboardContext({
      database,
      engine: authProvider,
      rawBrowserProof,
      rawContextHandle,
    });
    const ctx = await authProvider.$context;
    const sessFilters: any[] = [{ userId: verified.userId }, ...(ObjectId.isValid(verified.userId) ? [{ userId: new ObjectId(verified.userId) }] : [])];
    const twoFactorDoc = await database.collection("twoFactor").findOne({ $or: sessFilters });
    if (!twoFactorDoc?.secret) {
      return c.json({ error: "invalid_request", code: "ERR_TOTP_NOT_ENABLED", requestId }, 400);
    }
    const claimedStep = await claimTotpTimeStep({
      database,
      userId: verified.userId,
      purpose: "disable",
    });

    const headers = await buildBoundSessionHeaders(database, verified.sessionId);
    const verRes = await (authProvider.api as any).verifyTOTP({
      body: { code: body.code.trim() },
      headers,
      asResponse: true,
    });
    if (!verRes.ok) {
      await releaseTotpTimeStep(database, verified.userId, claimedStep, "disable");
      return c.json({ error: "unauthorized", code: "ERR_INVALID_TOTP", requestId }, 401);
    }
    const res = await (authProvider.api as any).disableTwoFactor({
      body: { password: body.password },
      headers,
      asResponse: true,
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      return c.json({ error: "unauthorized", code: errData.code || "ERR_TOTP_DISABLE_FAILED", requestId }, res.status as any);
    }

    // Revoke other sessions and refresh families for this user while preserving role
    const otherSessionFilter: any = { $or: sessFilters, id: { $ne: verified.sessionId } };
    if (ObjectId.isValid(verified.sessionId)) {
      otherSessionFilter._id = { $ne: new ObjectId(verified.sessionId) };
    }
    await database.collection("session").deleteMany(otherSessionFilter);
    await database.collection("oauthRefreshToken").deleteMany({ userId: verified.userId });

    return c.json({ disabled: true, requestId });
  } catch (err: any) {
    if (err instanceof IdentityContextError) {
      return c.json({ error: "unauthorized", code: err.code, message: err.message, requestId }, err.status as any);
    }
    if (err instanceof TotpReplayError) {
      return c.json({ error: "conflict", code: err.code, message: err.message, requestId }, err.status as any);
    }
    return c.json({ error: "server_error", code: "ERR_TOTP_DISABLE_FAILED", requestId }, 500);
  }
}
