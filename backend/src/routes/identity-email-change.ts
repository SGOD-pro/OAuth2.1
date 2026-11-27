import crypto from "node:crypto";
import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { ObjectId } from "mongodb";
import { client, getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { getBrowserSessionCookieName } from "../identity/browser-session-registry";
import { IdentityContextError, resolveOwnerDashboardContext } from "../identity/owner-contexts";
import { computeEmailLookup, digestToken } from "../identity/registration-crypto";
import { recordEmailChangeMailForTesting } from "../identity/mail-service";
import { AccountKeyAccessError, type AccountKeyProvider } from "../identity/account-key-provider";
import { ProtectedFieldError } from "../identity/protected-envelope";
import { writeProtectedProfileFields, type ProtectedProfileCollection } from "../identity/protected-profile-store";

export interface EmailChangeRouteDeps {
  getDb?: () => Promise<any>;
  startSession?: () => any;
  resolveOwner?: (c: Context, database: any) => Promise<
    | { ok: true; userId: string; sessionId: string; contextId: string }
    | { ok: false; response: Response }
  >;
  verifyPassword?: (database: any, userId: string, password: string) => Promise<boolean>;
  protectedProfileStore?: ProtectedProfileCollection;
  accountKeyProvider?: AccountKeyProvider;
}

export function createEmailChangeHandlers(deps: EmailChangeRouteDeps = {}) {
  return {
    requestEmailChange: (c: Context) => runEmailChangeRequest(c, deps),
    confirmEmailChange: (c: Context) => runEmailChangeConfirm(c, deps),
  };
}

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
  return runEmailChangeRequest(c, {});
}

async function runEmailChangeRequest(c: Context, deps: EmailChangeRouteDeps) {
  const database = await (deps.getDb ?? getDb)();
  const owner = await (deps.resolveOwner ?? resolveOwnerOrError)(c, database);
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

  const passwordOk = await (deps.verifyPassword ?? verifyUserPassword)(database, owner.userId, password);
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
  // Supersede any prior unconsumed requests for this user so stale requests cannot overwrite newer ones.
  await database.collection("email_change_requests").updateMany(
    { userId: owner.userId, consumedAt: null },
    { $set: { consumedAt: now, supersededAt: now } }
  );
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
  return runEmailChangeConfirm(c, {});
}

async function runEmailChangeConfirm(c: Context, deps: EmailChangeRouteDeps) {
  const database = await (deps.getDb ?? getDb)();
  const owner = await (deps.resolveOwner ?? resolveOwnerOrError)(c, database);
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

  const mongoSession = (deps.startSession ?? (() => client.startSession()))();
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
      const nextEmailLookup = computeEmailLookup(newEmail);
      const [collision, lookupCollision] = await Promise.all([
        database.collection("user").findOne(
          { email: newEmail, _id: { $ne: userObjectId } },
          { session }
        ),
        database.collection("identity_lookup").findOne(
          { kind: "email", keyVersion: 1, keyedLookup: nextEmailLookup, userId: { $ne: owner.userId } },
          { session }
        ),
      ]);
      if (collision || lookupCollision) {
        throw Object.assign(new Error("Email address is already in use"), { status: 409 });
      }

      const userDoc = await database.collection("user").findOne(
        { _id: userObjectId, email: oldEmail },
        { session }
      );
      if (!userDoc) {
        throw Object.assign(new Error("User not found or email already changed"), { status: 409 });
      }
      const nextTokenVersion = (typeof userDoc.tokenVersion === "number" ? userDoc.tokenVersion : 1) + 1;

      const upd = await database.collection("user").updateOne(
        { _id: userObjectId, email: oldEmail },
        {
          $set: { email: newEmail, emailVerified: true, updatedAt: now, tokenVersion: nextTokenVersion },
          $inc: { sessionVersion: 1, lookupVersion: 1 },
        },
        { session }
      );
      if (upd.matchedCount === 0) {
        throw Object.assign(new Error("User not found or email already changed"), { status: 409 });
      }

      await database.collection("identity_lookup").updateOne(
        { kind: "email", userId: owner.userId },
        { $set: { kind: "email", userId: owner.userId, keyVersion: 1, keyedLookup: nextEmailLookup, updatedAt: now } },
        { upsert: true, session }
      );

      if (deps.protectedProfileStore && deps.accountKeyProvider) {
        await writeProtectedProfileFields({
          store: deps.protectedProfileStore,
          provider: deps.accountKeyProvider,
          accountId: owner.userId,
          email: newEmail,
          fallbackName: String(userDoc.name || ""),
          session,
        });
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
    if (err instanceof AccountKeyAccessError) {
      const status = err.code === "provider_outage" ? 503 : err.code === "key_not_found" ? 404 : 403;
      return c.json({ error: err.code, message: err.message }, status as any);
    }
    if (err instanceof ProtectedFieldError) {
      return c.json({ error: err.code, message: err.message }, (err.code === "profile_not_found" ? 404 : 500) as any);
    }
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
