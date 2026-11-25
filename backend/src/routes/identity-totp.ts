import crypto from "node:crypto";
import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { ObjectId, type Db } from "mongodb";
import { makeSignature } from "better-auth/crypto";
import { getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { hasDangerousMongoKeys } from "../utils/security";
import { createRateLimiter } from "../middleware/rate-limit";
import { getBrowserSessionCookieName, isOrdinaryRole } from "../identity/browser-session-registry";
import { extractSessionTokenFromHeaders } from "../identity/session-adapter";
import { IdentityContextError, resolveOwnerDashboardContext } from "../identity/owner-contexts";
import { claimMatchedTotpStep, releaseTotpTimeStep, TotpReplayError } from "../identity/totp-replay-guard";
import { digestToken } from "../identity/registration-crypto";

export const totpIpRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  prefix: "rl:totp:ip",
  sensitivity: "auth",
});

export const totpSubjectRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  prefix: "rl:totp:subj",
  sensitivity: "auth",
  keyFn: async (c: Context) => {
    const h = c.req.header("x-identity-context");
    return h ? digestToken(`totp-rl-v1:${h.trim()}`) : null;
  },
});

export const contextIssueIpRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  prefix: "rl:ctx:ip",
  sensitivity: "auth",
});

function getReqId(c: Context): string {
  return (c.get("requestId" as never) as string) || crypto.randomUUID();
}

function idFilters(id: string): any[] {
  const filters: any[] = [{ id }, { _id: id }];
  if (ObjectId.isValid(id) && id.length === 24) filters.push({ _id: new ObjectId(id) });
  return filters;
}

function userIdFilters(userId: string): any[] {
  const filters: any[] = [{ userId }];
  if (ObjectId.isValid(userId) && userId.length === 24) filters.push({ userId: new ObjectId(userId) });
  return filters;
}

async function enforceTotpUserRateLimit(database: Db, userId: string): Promise<void> {
  const key = `rl:totp:user:${digestToken(`totp-user-rl-v1:${userId}`)}`;
  const now = new Date();
  const res = await database.collection("rate_limits").findOneAndUpdate(
    { _id: key as any },
    { $inc: { count: 1 }, $setOnInsert: { createdAt: now } },
    { upsert: true, returnDocument: "after" }
  );
  const count = (res as any)?.count ?? (res as any)?.value?.count ?? 1;
  if (count > 20) {
    throw new IdentityContextError("ERR_RATE_LIMITED", 429, "Too many TOTP attempts for this account");
  }
}

async function buildHeadersForToken(rawSignedOrPlainToken: string, isShortSession: boolean): Promise<Headers> {
  const ctx = await authProvider.$context;
  const plainToken = rawSignedOrPlainToken.includes(".") ? rawSignedOrPlainToken.split(".")[0] : rawSignedOrPlainToken;
  const sig = await makeSignature(plainToken, ctx.secret);
  const parts = [`${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${plainToken}.${sig}`)}`];
  if (isShortSession && ctx.authCookies?.dontRememberToken?.name) {
    const dontSig = await makeSignature("true", ctx.secret);
    parts.push(`${ctx.authCookies.dontRememberToken.name}=${encodeURIComponent(`true.${dontSig}`)}`);
  }
  const headers = new Headers();
  headers.set("cookie", parts.join("; "));
  return headers;
}

async function buildBoundSessionHeaders(database: Db, sessionId: string): Promise<{ headers: Headers; isShortSession: boolean }> {
  const sessDoc = await database.collection("session").findOne({ $or: idFilters(sessionId) });
  if (!sessDoc?.token) throw new Error("ERR_SESSION_MISSING");
  const createdMs = sessDoc.createdAt ? new Date(sessDoc.createdAt).getTime() : 0;
  const expiresMs = sessDoc.expiresAt ? new Date(sessDoc.expiresAt).getTime() : 0;
  const isShortSession = createdMs > 0 && expiresMs > 0 && expiresMs - createdMs <= 2 * 24 * 3600 * 1000;
  const headers = await buildHeadersForToken(sessDoc.token, isShortSession);
  return { headers, isShortSession };
}

async function rotateBrowserSessionEntry(params: {
  database: Db;
  setId: string;
  entryId: string;
  oldSessionId: string;
  newSessionToken: string | null;
  contextId: string;
  userId: string;
  revokeOtherSessions: boolean;
}): Promise<string> {
  const { database, setId, entryId, oldSessionId, newSessionToken, contextId, userId, revokeOtherSessions } = params;
  if (!newSessionToken) {
    throw new IdentityContextError("ERR_ROTATED_SESSION_MISSING", 500, "Expected rotated session token");
  }
  const rawTok = decodeURIComponent(newSessionToken).split(".")[0];
  const newSess = await database.collection("session").findOne({ token: rawTok });
  if (!newSess) {
    throw new IdentityContextError("ERR_ROTATED_SESSION_MISSING", 500, "Rotated session missing from store");
  }
  const newSessionId = String(newSess.id || newSess._id);
  const now = new Date();
  const cas = await database.collection("browser_session_sets").updateOne(
    { setId, revokedAt: null, entries: { $elemMatch: { entryId, sessionId: oldSessionId, status: "active" } } },
    { $set: { "entries.$.sessionId": newSessionId, "entries.$.lastUsedAt": now }, $inc: { version: 1 } }
  );
  if (cas.modifiedCount === 0) {
    await database.collection("session").deleteOne({ _id: newSess._id }).catch(() => {});
    throw new IdentityContextError("ERR_ENTRY_CONCURRENTLY_CHANGED", 401, "Account entry changed concurrently");
  }
  await database.collection("identity_contexts").updateOne({ contextId }, { $set: { revokedAt: now } });
  if (revokeOtherSessions) {
    const neFilter: any = { $or: userIdFilters(userId), id: { $ne: newSessionId } };
    if (ObjectId.isValid(newSessionId) && newSessionId.length === 24) {
      neFilter._id = { $ne: new ObjectId(newSessionId) };
    } else {
      neFilter._id = { $ne: newSess._id };
    }
    await database.collection("session").deleteMany(neFilter);
  }
  return newSessionId;
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
    const { verified } = await resolveOwnerDashboardContext({ database, engine: authProvider, rawBrowserProof, rawContextHandle });
    if (!isOrdinaryRole(verified.role)) {
      return c.json({ error: "forbidden", code: "ERR_ADMIN_TOTP_ROUTE_FORBIDDEN", requestId }, 403);
    }
    await enforceTotpUserRateLimit(database, verified.userId);
    const [userDoc, twoFactorDoc] = await Promise.all([
      database.collection("user").findOne({ $or: idFilters(verified.userId) }),
      database.collection("twoFactor").findOne({ $or: userIdFilters(verified.userId) }),
    ]);
    if (userDoc?.twoFactorEnabled === true || twoFactorDoc?.verified === true) {
      return c.json({ error: "conflict", code: "ERR_TOTP_ALREADY_ENABLED", requestId }, 409);
    }
    const { headers } = await buildBoundSessionHeaders(database, verified.sessionId);
    const res = await (authProvider.api as any).enableTwoFactor({ body: { password: body.password }, headers, asResponse: true });
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

  let claimedStep: number | null = null;
  let claimedUserId: string | null = null;
  try {
    const { context, verified } = await resolveOwnerDashboardContext({ database, engine: authProvider, rawBrowserProof, rawContextHandle });
    if (!isOrdinaryRole(verified.role)) {
      return c.json({ error: "forbidden", code: "ERR_ADMIN_TOTP_ROUTE_FORBIDDEN", requestId }, 403);
    }
    await enforceTotpUserRateLimit(database, verified.userId);
    const twoFactorDoc = await database.collection("twoFactor").findOne({ $or: userIdFilters(verified.userId) });
    if (!twoFactorDoc?.secret) {
      return c.json({ error: "invalid_request", code: "ERR_TOTP_NOT_PENDING", requestId }, 400);
    }
    if (twoFactorDoc.verified === true) {
      return c.json({ error: "conflict", code: "ERR_TOTP_ALREADY_ENABLED", requestId }, 409);
    }

    const ctx = await authProvider.$context;
    claimedUserId = verified.userId;
    claimedStep = await claimMatchedTotpStep({
      database,
      userId: verified.userId,
      code: body.code.trim(),
      encryptedSecret: twoFactorDoc.secret,
      engineSecret: (ctx as any).secretConfig || ctx.secret,
    });
    if (claimedStep === null) {
      return c.json({ error: "unauthorized", code: "INVALID_TWO_FACTOR_CODE", requestId }, 401);
    }

    const { headers } = await buildBoundSessionHeaders(database, verified.sessionId);
    const res = await (authProvider.api as any).verifyTOTP({ body: { code: body.code.trim() }, headers, asResponse: true });
    if (!res.ok) {
      await releaseTotpTimeStep(database, verified.userId, claimedStep);
      const errData = await res.json().catch(() => ({}));
      return c.json({ error: "unauthorized", code: errData.code || "ERR_TOTP_VERIFY_FAILED", requestId }, res.status as any);
    }

    const now = new Date();
    const newSessionId = await rotateBrowserSessionEntry({
      database,
      setId: context.setId,
      entryId: verified.entryId,
      oldSessionId: verified.sessionId,
      newSessionToken: extractSessionTokenFromHeaders(res.headers),
      contextId: context.contextId,
      userId: verified.userId,
      revokeOtherSessions: true,
    });
    await database.collection("session").updateOne({ $or: idFilters(newSessionId) }, { $set: { mfaVerifiedAt: now, twoFactorVerified: true } });

    return c.json({ enabled: true, mfaVerifiedAt: now.toISOString(), requestId });
  } catch (err: any) {
    if (claimedUserId && claimedStep !== null && !(err instanceof TotpReplayError)) {
      await releaseTotpTimeStep(database, claimedUserId, claimedStep);
    }
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

  let claimedStep: number | null = null;
  let claimedUserId: string | null = null;
  try {
    const { context, verified } = await resolveOwnerDashboardContext({ database, engine: authProvider, rawBrowserProof, rawContextHandle });
    if (!isOrdinaryRole(verified.role)) {
      return c.json({ error: "forbidden", code: "ERR_ADMIN_TOTP_ROUTE_FORBIDDEN", requestId }, 403);
    }
    await enforceTotpUserRateLimit(database, verified.userId);
    const [userDoc, twoFactorDoc, credDoc] = await Promise.all([
      database.collection("user").findOne({ $or: idFilters(verified.userId) }),
      database.collection("twoFactor").findOne({ $or: userIdFilters(verified.userId) }),
      database.collection("account").findOne({ $or: userIdFilters(verified.userId), providerId: "credential" }),
    ]);
    if (userDoc?.twoFactorEnabled !== true || twoFactorDoc?.verified !== true || !twoFactorDoc?.secret) {
      return c.json({ error: "invalid_request", code: "ERR_TOTP_NOT_ENABLED", requestId }, 400);
    }

    const ctx = await authProvider.$context;
    const validPass = credDoc?.password
      ? await ctx.password.verify({ hash: credDoc.password, password: body.password }).catch(() => false)
      : false;
    if (!validPass) {
      return c.json({ error: "unauthorized", code: "INVALID_PASSWORD", requestId }, 401);
    }

    claimedUserId = verified.userId;
    claimedStep = await claimMatchedTotpStep({
      database,
      userId: verified.userId,
      code: body.code.trim(),
      encryptedSecret: twoFactorDoc.secret,
      engineSecret: (ctx as any).secretConfig || ctx.secret,
    });
    if (claimedStep === null) {
      return c.json({ error: "unauthorized", code: "ERR_INVALID_TOTP", requestId }, 401);
    }

    const { headers, isShortSession } = await buildBoundSessionHeaders(database, verified.sessionId);
    const verRes = await (authProvider.api as any).verifyTOTP({ body: { code: body.code.trim() }, headers, asResponse: true });
    if (!verRes.ok) {
      await releaseTotpTimeStep(database, verified.userId, claimedStep);
      return c.json({ error: "unauthorized", code: "ERR_INVALID_TOTP", requestId }, 401);
    }

    const rotatedAfterVerify = extractSessionTokenFromHeaders(verRes.headers);
    const disableHeaders = rotatedAfterVerify ? await buildHeadersForToken(rotatedAfterVerify, isShortSession) : headers;
    const res = await (authProvider.api as any).disableTwoFactor({ body: { password: body.password }, headers: disableHeaders, asResponse: true });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      return c.json({ error: "unauthorized", code: errData.code || "ERR_TOTP_DISABLE_FAILED", requestId }, res.status as any);
    }

    await rotateBrowserSessionEntry({
      database,
      setId: context.setId,
      entryId: verified.entryId,
      oldSessionId: verified.sessionId,
      newSessionToken: extractSessionTokenFromHeaders(res.headers),
      contextId: context.contextId,
      userId: verified.userId,
      revokeOtherSessions: true,
    });
    const uFilters = userIdFilters(verified.userId);
    const now = new Date();
    await Promise.all([
      database.collection("oauthRefreshToken").deleteMany({ $or: uFilters }),
      database.collection("oauthAccessToken").deleteMany({ $or: uFilters }),
      database.collection("oauth_token_families").updateMany({ $or: uFilters, status: { $ne: "revoked" } }, { $set: { status: "revoked", revokedAt: now } }),
    ]);

    return c.json({ disabled: true, requestId });
  } catch (err: any) {
    if (claimedUserId && claimedStep !== null && !(err instanceof TotpReplayError)) {
      await releaseTotpTimeStep(database, claimedUserId, claimedStep);
    }
    if (err instanceof IdentityContextError) {
      return c.json({ error: "unauthorized", code: err.code, message: err.message, requestId }, err.status as any);
    }
    if (err instanceof TotpReplayError) {
      return c.json({ error: "conflict", code: err.code, message: err.message, requestId }, err.status as any);
    }
    return c.json({ error: "server_error", code: "ERR_TOTP_DISABLE_FAILED", requestId }, 500);
  }
}
