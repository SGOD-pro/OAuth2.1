import crypto from "node:crypto";
import type { Context } from "hono";
import { ObjectId } from "mongodb";
import { getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { hasDangerousMongoKeys } from "../utils/security";
import { makeSignature } from "better-auth/crypto";

const attemptMap = new Map<string, { count: number; resetAt: number }>();

function checkRecoveryRateLimit(key: string): boolean {
  const now = Date.now();
  const rec = attemptMap.get(key);
  if (!rec || rec.resetAt <= now) {
    attemptMap.set(key, { count: 1, resetAt: now + 15 * 60 * 1000 });
    return true;
  }
  rec.count += 1;
  return rec.count <= 5;
}

export async function handleBackupCodeRecovery(c: Context): Promise<Response> {
  const requestId = (c.get("requestId" as never) as string) || crypto.randomUUID();
  const body = await c.req.raw.clone().json().catch(() => null);
  if (
    !body ||
    typeof body !== "object" ||
    hasDangerousMongoKeys(body) ||
    typeof body.email !== "string" ||
    typeof body.password !== "string" ||
    typeof body.backupCode !== "string" ||
    !body.email.trim() ||
    !body.password ||
    !body.backupCode.trim()
  ) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }

  const email = body.email.trim().toLowerCase();
  const ip = c.req.header("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  if (!checkRecoveryRateLimit(`${ip}:${email}`)) {
    return c.json({ error: "too_many_requests", code: "ERR_RATE_LIMITED", requestId }, 429);
  }

  // 1. Verify password via Better Auth engine
  let signInRes: any;
  try {
    signInRes = await authProvider.api.signInEmail({
      body: { email, password: body.password },
      asResponse: true,
    });
  } catch {
    return c.json({ error: "unauthorized", code: "ERR_INVALID_CREDENTIALS", requestId }, 401);
  }
  if (!signInRes || !signInRes.ok) {
    return c.json({ error: "unauthorized", code: "ERR_INVALID_CREDENTIALS", requestId }, 401);
  }

  const database = await getDb();
  const userDoc = await database.collection("user").findOne({ email });
  if (!userDoc) {
    return c.json({ error: "unauthorized", code: "ERR_INVALID_CREDENTIALS", requestId }, 401);
  }
  const userId = String(userDoc.id || userDoc._id);

  // 2. Verify and atomically consume single-use backup code via Better Auth TOTP engine
  const setCookies = typeof (signInRes.headers as any).getSetCookie === "function"
    ? (signInRes.headers as any).getSetCookie().join("; ")
    : (signInRes.headers.get("set-cookie") || "");
  let verifyRes: any;
  try {
    verifyRes = await (authProvider.api as any).verifyBackupCode({
      body: { code: body.backupCode.trim(), disableSession: true },
      headers: new Headers({ cookie: setCookies }),
      asResponse: true,
    });
  } catch {
    return c.json({ error: "unauthorized", code: "ERR_INVALID_BACKUP_CODE", requestId }, 401);
  }
  if (!verifyRes || !verifyRes.ok) {
    return c.json({ error: "unauthorized", code: "ERR_INVALID_BACKUP_CODE", requestId }, 401);
  }

  // 3. Atomically invalidate all old elevated sessions, bump tokenVersion, reset twoFactorEnabled, and issue restricted recovery session
  const mongoClient = (database as any).client;
  if (!mongoClient || typeof mongoClient.startSession !== "function") {
    return c.json({ error: "server_error", code: "ERR_TRANSACTION_REQUIRED", requestId }, 503);
  }

  const userFilters: any[] = [{ id: userId }, { _id: userId }];
  if (ObjectId.isValid(userId)) userFilters.push({ _id: new ObjectId(userId) });
  const sessFilters: any[] = [{ userId }, ...(ObjectId.isValid(userId) ? [{ userId: new ObjectId(userId) }] : [])];

  const rawToken = crypto.randomBytes(32).toString("base64url");
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 15 * 60 * 1000);

  const dbSession = mongoClient.startSession();
  try {
    await dbSession.withTransaction(async () => {
      await database.collection("session").deleteMany({ $or: sessFilters }, { session: dbSession });
      await database.collection("twoFactor").deleteMany({ $or: sessFilters }, { session: dbSession });
      await database.collection("user").updateOne(
        { $or: userFilters },
        { $set: { twoFactorEnabled: false }, $inc: { tokenVersion: 1 } },
        { session: dbSession }
      );
      await database.collection("session").insertOne(
        {
          id: crypto.randomUUID(),
          userId: ObjectId.isValid(userId) ? new ObjectId(userId) : userId,
          token: rawToken,
          expiresAt,
          createdAt: now,
          updatedAt: now,
          twoFactorVerified: false,
          mfaVerifiedAt: null,
          recoveryRestricted: true,
        },
        { session: dbSession }
      );
    });
  } finally {
    await dbSession.endSession();
  }

  const ctx = await authProvider.$context;
  const sig = await makeSignature(rawToken, ctx.secret);
  const cookieVal = `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${rawToken}.${sig}`)}; Path=/; HttpOnly; SameSite=Lax`;

  return new Response(
    JSON.stringify({
      recovered: true,
      setupOnly: true,
      role: userDoc.role || "user",
      scopedClientId: userDoc.scopedClientId || null,
      requestId,
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Set-Cookie": cookieVal,
      },
    }
  );
}
