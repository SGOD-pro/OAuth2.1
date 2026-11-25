import crypto from "node:crypto";
import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { ObjectId } from "mongodb";
import { client, getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { getBrowserSessionCookieName } from "../identity/browser-session-registry";
import { IdentityContextError, resolveOwnerDashboardContext } from "../identity/owner-contexts";
import { digestToken } from "../identity/registration-crypto";
import { recordEmailChangeMailForTesting } from "../identity/mail-service";

const ADMIN_ROLES = new Set(["admin", "super-admin", "super_admin", "app-admin", "app_admin"]);
const MFA_FRESH_WINDOW_MS = 5 * 60 * 1000;
const PROOF_TTL_MS = 15 * 60 * 1000;

function normalizeEmail(raw: unknown): string {
  if (typeof raw !== "string") return "";
  return raw.trim().toLowerCase();
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function buildUserIdFilters(userId: string): any[] {
  const filters: any[] = [{ userId }];
  if (ObjectId.isValid(userId) && userId.length === 24) {
    filters.push({ userId: new ObjectId(userId) });
  }
  return filters;
}

async function verifyUserPassword(database: any, userId: string, password: string): Promise<boolean> {
  if (!password) return false;
  const ctx = await authProvider.$context;
  const cred = await database.collection("account").findOne({
    $or: buildUserIdFilters(userId),
    providerId: "credential",
  });
  if (!cred?.password) return false;
  return ctx.password.verify({ hash: cred.password, password });
}

async function resolveOwnerOrError(c: Context, database: any) {
  try {
    const { context, verified } = await resolveOwnerDashboardContext({
      database,
      engine: authProvider,
      rawBrowserProof: getCookie(c, getBrowserSessionCookieName()),
      rawContextHandle: c.req.header("x-identity-context"),
      requiredPurpose: "owner_dashboard",
    });
    return { ok: true as const, userId: verified.userId, sessionId: verified.sessionId, contextId: context.contextId };
  } catch (err) {
    if (err instanceof IdentityContextError) {
      return { ok: false as const, response: c.json({ error: err.code, message: err.message }, err.status as any) };
    }
    throw err;
  }
}

export async function handleEmailChangeRequest(c: Context) {
  const database = await getDb();
  const owner = await resolveOwnerOrError(c, database);
  if (!owner.ok) return owner.response;

  const body = await c.req.json().catch(() => null);
  const newEmail = normalizeEmail(body?.newEmail);
  const password = typeof body?.password === "string" ? body.password : "";

  if (!isValidEmail(newEmail)) {
    return c.json({ error: "invalid_email", message: "Valid newEmail is required" }, 400);
  }
  if (!password) {
    return c.json({ error: "password_required", message: "Current password is required" }, 400);
  }

  const user = await database.collection("user").findOne({ _id: new ObjectId(owner.userId) });
  if (!user) return c.json({ error: "not_found" }, 404);

  if (ADMIN_ROLES.has(String(user.role || ""))) {
    if (!user.twoFactorEnabled) {
      return c.json({ error: "mfa_required", message: "Admin accounts must have TOTP enabled" }, 403);
    }
    const sess = await database.collection("session").findOne({ _id: new ObjectId(owner.sessionId) }).catch(() => null);
    const mfaAt = sess?.mfaVerifiedAt ? new Date(sess.mfaVerifiedAt).getTime() : 0;
    if (!mfaAt || Date.now() - mfaAt > MFA_FRESH_WINDOW_MS) {
      return c.json({ error: "mfa_freshness_required", message: "Recent MFA verification required" }, 403);
    }
  }

  const passwordOk = await verifyUserPassword(database, owner.userId, password);
  if (!passwordOk) {
    return c.json({ error: "invalid_password", message: "Invalid password" }, 401);
  }

  if (normalizeEmail(user.email) === newEmail) {
    return c.json({ error: "same_email", message: "New email matches current email" }, 400);
  }

  const existing = await database.collection("user").findOne({ email: newEmail });
  if (existing) {
    return c.json({ error: "email_in_use", message: "Email address is already in use" }, 409);
  }

  const rawToken = crypto.randomBytes(24).toString("base64url");
  const tokenDigest = digestToken(rawToken);
  const now = new Date();
  await database.collection("email_change_requests").insertOne({
    requestId: crypto.randomUUID(),
    userId: owner.userId,
    oldEmail: user.email,
    newEmail,
    tokenDigest,
    createdAt: now,
    expiresAt: new Date(now.getTime() + PROOF_TTL_MS),
    consumedAt: null,
  });

  recordEmailChangeMailForTesting(newEmail, "email_change_verify", `Confirm email change (token: ${rawToken})`);
  return c.json({ ok: true, pendingEmail: newEmail }, 200);
}

export async function handleEmailChangeConfirm(c: Context) {
  const database = await getDb();
  const owner = await resolveOwnerOrError(c, database);
  if (!owner.ok) return owner.response;

  const body = await c.req.json().catch(() => null);
  const rawToken = typeof body?.token === "string" ? body.token.trim() : "";
  if (!rawToken) {
    return c.json({ error: "token_required", message: "Verification token is required" }, 400);
  }

  const tokenDigest = digestToken(rawToken);
  const now = new Date();
  let oldEmail = "";
  let newEmail = "";

  const mongoSession = client.startSession();
  try {
    await mongoSession.withTransaction(async () => {
      const session = mongoSession;
      const reqDoc = await database.collection("email_change_requests").findOneAndUpdate(
        { tokenDigest, userId: owner.userId, consumedAt: null, expiresAt: { $gt: now } },
        { $set: { consumedAt: now } },
        { session, returnDocument: "after" }
      );
      if (!reqDoc) {
        throw Object.assign(new Error("Invalid, expired, or already used email change token"), { status: 409 });
      }
      oldEmail = reqDoc.oldEmail;
      newEmail = reqDoc.newEmail;

      const userObjectId = new ObjectId(owner.userId);
      const collision = await database.collection("user").findOne(
        { email: newEmail, _id: { $ne: userObjectId } },
        { session }
      );
      if (collision) {
        throw Object.assign(new Error("Email address is already in use"), { status: 409 });
      }

      const upd = await database.collection("user").updateOne(
        { _id: userObjectId },
        {
          $set: { email: newEmail, emailVerified: true, updatedAt: now },
          $inc: { sessionVersion: 1, lookupVersion: 1 },
        },
        { session }
      );
      if (upd.matchedCount === 0) {
        throw Object.assign(new Error("User not found"), { status: 404 });
      }

      const uFilters = buildUserIdFilters(owner.userId);
      await Promise.all([
        database.collection("session").deleteMany({ $or: uFilters }, { session }),
        database.collection("identity_contexts").updateMany(
          { userId: owner.userId, revokedAt: null },
          { $set: { revokedAt: now } },
          { session }
        ),
        database.collection("browser_session_sets").updateMany(
          { entries: { $elemMatch: { userId: owner.userId, status: "active" } } },
          {
            $set: {
              "entries.$[elem].status": "signed_out",
              "entries.$[elem].sessionId": null,
              "entries.$[elem].signedOutAt": now,
            },
            $inc: { version: 1 },
          },
          { session, arrayFilters: [{ "elem.userId": owner.userId, "elem.status": "active" }] }
        ),
        database.collection("oauthRefreshToken").deleteMany({ $or: uFilters }, { session }),
        database.collection("oauthAccessToken").deleteMany({ $or: uFilters }, { session }),
        database.collection("oauth_token_families").updateMany(
          { $or: uFilters, status: { $ne: "revoked" } },
          { $set: { status: "revoked", revokedAt: now } },
          { session }
        ),
      ]);
    });
  } catch (err: any) {
    if (err?.status) {
      return c.json({ error: "email_change_rejected", message: err.message }, err.status);
    }
    throw err;
  } finally {
    await mongoSession.endSession();
  }

  if (oldEmail) {
    recordEmailChangeMailForTesting(oldEmail, "email_change_notice", `Your SWYRA Auth email was changed to ${newEmail}.`);
  }
  return c.json({ ok: true, email: newEmail }, 200);
}
