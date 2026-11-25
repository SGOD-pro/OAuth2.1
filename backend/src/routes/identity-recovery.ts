import crypto from "node:crypto";
import type { Context } from "hono";
import { ObjectId } from "mongodb";
import { makeSignature, symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { hasDangerousMongoKeys } from "../utils/security";
import { config } from "../config";
import { createRateLimiter } from "../middleware/rate-limit";

export const recoveryIpRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  prefix: "rl:recovery:ip:",
  sensitivity: "auth",
});

export const recoveryAccountRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  prefix: "rl:recovery:acct:",
  sensitivity: "auth",
});

let recoveryCommitHookForTesting: (() => Promise<void> | void) | null = null;
export function setRecoveryCommitHookForTesting(hook: (() => Promise<void> | void) | null): void {
  recoveryCommitHookForTesting = hook;
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
  const submittedCode = body.backupCode.trim();

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
  const mongoClient = (database as any).client;
  if (!mongoClient || typeof mongoClient.startSession !== "function") {
    return c.json({ error: "server_error", code: "ERR_TRANSACTION_REQUIRED", requestId }, 503);
  }

  const ctx = await authProvider.$context;
  const userFilters: any[] = [{ id: userId }, { _id: userId }];
  if (ObjectId.isValid(userId)) userFilters.push({ _id: new ObjectId(userId) });
  const sessFilters: any[] = [{ userId }, ...(ObjectId.isValid(userId) ? [{ userId: new ObjectId(userId) }] : [])];

  const rawToken = crypto.randomBytes(32).toString("base64url");
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 15 * 60 * 1000);

  // 2. Atomically consume backup code, invalidate old sessions, reset TOTP, and issue restricted recovery session
  const dbSession = mongoClient.startSession();
  try {
    await dbSession.withTransaction(async () => {
      const twoFactorDoc = await database.collection("twoFactor").findOne({ $or: sessFilters }, { session: dbSession });
      if (!twoFactorDoc || typeof twoFactorDoc.backupCodes !== "string") {
        throw new Error("ERR_INVALID_BACKUP_CODE");
      }
      const decrypted = await symmetricDecrypt({ key: ctx.secret, data: twoFactorDoc.backupCodes });
      const codes: string[] = JSON.parse(decrypted);
      const idx = codes.indexOf(submittedCode);
      if (idx < 0) {
        throw new Error("ERR_INVALID_BACKUP_CODE");
      }
      const remaining = [...codes.slice(0, idx), ...codes.slice(idx + 1)];
      const reEncrypted = await symmetricEncrypt({ key: ctx.secret, data: JSON.stringify(remaining) });

      const cas = await database.collection("twoFactor").findOneAndUpdate(
        { _id: twoFactorDoc._id, backupCodes: twoFactorDoc.backupCodes },
        { $set: { backupCodes: reEncrypted } },
        { session: dbSession }
      );
      if (!cas) {
        throw new Error("ERR_INVALID_BACKUP_CODE");
      }

      if (recoveryCommitHookForTesting) {
        await recoveryCommitHookForTesting();
      }

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
  } catch (err: any) {
    if (err?.message === "ERR_INVALID_BACKUP_CODE") {
      return c.json({ error: "unauthorized", code: "ERR_INVALID_BACKUP_CODE", requestId }, 401);
    }
    return c.json({ error: "server_error", code: "ERR_RECOVERY_COMMIT_FAILED", requestId }, 500);
  } finally {
    await dbSession.endSession();
  }

  const sig = await makeSignature(rawToken, ctx.secret);
  const attrs = ctx.authCookies.sessionToken.attributes || {};
  const parts = [
    `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${rawToken}.${sig}`)}`,
    `Path=${attrs.path || "/"}`,
    "HttpOnly",
    `SameSite=${attrs.sameSite === "none" ? "None" : attrs.sameSite === "strict" ? "Strict" : "Lax"}`,
  ];
  if (config.env === "production" || attrs.secure) {
    parts.push("Secure");
  }

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
        "Set-Cookie": parts.join("; "),
      },
    }
  );
}
