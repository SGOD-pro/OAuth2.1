import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { ObjectId } from "mongodb";
import { client, getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { getBrowserSessionCookieName } from "../identity/browser-session-registry";
import { IdentityContextError, resolveOwnerDashboardContext } from "../identity/owner-contexts";
import { computeUsernameLookup, normalizeUsername } from "../identity/registration-crypto";

const RECENT_AUTH_WINDOW_MS = 5 * 60 * 1000;

function buildUserIdFilters(userId: string): any[] {
  const filters: any[] = [{ userId }];
  if (ObjectId.isValid(userId) && userId.length === 24) {
    filters.push({ userId: new ObjectId(userId) });
  }
  return filters;
}

async function resolveOwner(c: Context, database: any) {
  try {
    const { verified } = await resolveOwnerDashboardContext({
      database,
      engine: authProvider,
      rawBrowserProof: getCookie(c, getBrowserSessionCookieName()),
      rawContextHandle: c.req.header("x-identity-context"),
      requiredPurpose: "owner_dashboard",
    });
    return { ok: true as const, userId: verified.userId, sessionId: verified.sessionId };
  } catch (err) {
    if (err instanceof IdentityContextError) {
      return { ok: false as const, response: c.json({ error: err.code, message: err.message }, err.status as any) };
    }
    throw err;
  }
}

async function requireRecentAuth(database: any, sessionId: string): Promise<boolean> {
  if (!ObjectId.isValid(sessionId)) return false;
  const sess = await database.collection("session").findOne({ _id: new ObjectId(sessionId) });
  if (!sess) return false;
  // Routine session updatedAt must not count as reauthentication.
  const refTime = Math.max(
    sess.mfaVerifiedAt ? new Date(sess.mfaVerifiedAt).getTime() : 0,
    sess.createdAt ? new Date(sess.createdAt).getTime() : 0
  );
  return refTime > 0 && Date.now() - refTime <= RECENT_AUTH_WINDOW_MS;
}

export async function handleListOwnerSessions(c: Context) {
  const database = await getDb();
  const owner = await resolveOwner(c, database);
  if (!owner.ok) return owner.response;

  const docs = await database
    .collection("session")
    .find({ $or: buildUserIdFilters(owner.userId) })
    .sort({ createdAt: -1 })
    .limit(50)
    .toArray();

  const sessions = docs.map((s: any) => {
    const id = String(s._id || s.id);
    return {
      sessionId: id,
      current: id === owner.sessionId,
      label: typeof s.userAgent === "string" && s.userAgent.trim() ? s.userAgent.slice(0, 80) : "Browser session",
      createdAt: s.createdAt ? new Date(s.createdAt).toISOString() : null,
      expiresAt: s.expiresAt ? new Date(s.expiresAt).toISOString() : null,
      status: s.expiresAt && new Date(s.expiresAt).getTime() <= Date.now() ? "expired" : "active",
    };
  });

  return c.json({ sessions }, 200);
}

export async function handleRevokeOwnerSession(c: Context) {
  const database = await getDb();
  const owner = await resolveOwner(c, database);
  if (!owner.ok) return owner.response;

  if (!(await requireRecentAuth(database, owner.sessionId))) {
    return c.json({ error: "recent_auth_required", message: "Recent authentication required" }, 403);
  }

  const targetId = c.req.param("sessionId")?.trim() || "";
  if (!targetId) return c.json({ error: "invalid_session_id" }, 400);

  const idFilters: any[] = [{ id: targetId }];
  if (ObjectId.isValid(targetId) && targetId.length === 24) {
    idFilters.push({ _id: new ObjectId(targetId) });
  }

  // Ownership check: only delete if owned by owner.userId
  const existing = await database.collection("session").findOne({ $or: idFilters });
  if (existing && String(existing.userId) !== owner.userId) {
    return c.json({ error: "not_found", message: "Session not found" }, 404);
  }

  const now = new Date();
  await Promise.all([
    database.collection("session").deleteMany({
      $and: [{ $or: idFilters }, { $or: buildUserIdFilters(owner.userId) }],
    }),
    database.collection("browser_session_sets").updateMany(
      { entries: { $elemMatch: { userId: owner.userId, sessionId: targetId, status: "active" } } },
      {
        $set: {
          "entries.$[elem].status": "signed_out",
          "entries.$[elem].sessionId": null,
          "entries.$[elem].signedOutAt": now,
        },
        $inc: { version: 1 },
      },
      { arrayFilters: [{ "elem.userId": owner.userId, "elem.sessionId": targetId, "elem.status": "active" }] }
    ),
  ]);

  return c.json({ ok: true, revoked: true, sessionId: targetId }, 200);
}

export async function handleListOwnerApps(c: Context) {
  const database = await getDb();
  const owner = await resolveOwner(c, database);
  if (!owner.ok) return owner.response;

  const uFilters = buildUserIdFilters(owner.userId);
  const [consents, families] = await Promise.all([
    database.collection("oauthConsent").find({ $or: uFilters }).toArray(),
    database.collection("oauth_token_families").find({ $or: uFilters, status: { $ne: "revoked" } }).toArray(),
  ]);

  const byClient = new Map<string, { clientId: string; scopes: string[]; status: string }>();
  for (const f of families) {
    if (f.clientId && !byClient.has(f.clientId)) {
      byClient.set(f.clientId, { clientId: f.clientId, scopes: [], status: "connected" });
    }
  }
  for (const con of consents) {
    if (!con.clientId) continue;
    const scopes = Array.isArray(con.scopes) ? con.scopes : typeof con.scopes === "string" ? con.scopes.split(" ").filter(Boolean) : [];
    byClient.set(con.clientId, { clientId: con.clientId, scopes, status: "connected" });
  }

  const clientIds = [...byClient.keys()];
  const clients = clientIds.length
    ? await database.collection("oauthClient").find({ clientId: { $in: clientIds } }).toArray()
    : [];
  const nameMap = new Map(clients.map((cl: any) => [cl.clientId, cl.name || cl.clientId]));

  const apps = [...byClient.values()].map((item) => ({
    clientId: item.clientId,
    name: nameMap.get(item.clientId) || item.clientId,
    scopes: item.scopes,
    status: item.status,
  }));

  return c.json({ apps }, 200);
}

export async function handleDisconnectOwnerApp(c: Context) {
  const database = await getDb();
  const owner = await resolveOwner(c, database);
  if (!owner.ok) return owner.response;

  if (!(await requireRecentAuth(database, owner.sessionId))) {
    return c.json({ error: "recent_auth_required", message: "Recent authentication required" }, 403);
  }

  const clientId = c.req.param("clientId")?.trim() || "";
  if (!clientId) return c.json({ error: "invalid_client_id" }, 400);

  const uFilters = buildUserIdFilters(owner.userId);
  const now = new Date();
  // Revoke owner's consent and OAuth credentials; preserve administrator-managed user_app_registrations.
  await Promise.all([
    database.collection("oauthConsent").deleteMany({ $and: [{ clientId }, { $or: uFilters }] }),
    database.collection("oauthRefreshToken").deleteMany({ $and: [{ clientId }, { $or: uFilters }] }),
    database.collection("oauthAccessToken").deleteMany({ $and: [{ clientId }, { $or: uFilters }] }),
    database.collection("oauth_token_families").updateMany(
      { $and: [{ clientId }, { $or: uFilters }, { status: { $ne: "revoked" } }] },
      { $set: { status: "revoked", revokedAt: now } }
    ),
  ]);

  return c.json({ ok: true, disconnected: true, clientId }, 200);
}

const ALLOWED_PROFILE_FIELDS = new Set(["name", "username"]);

export async function handleGetOwnerMe(c: Context) {
  const database = await getDb();
  const owner = await resolveOwner(c, database);
  if (!owner.ok) return owner.response;

  const user = await database.collection("user").findOne({ _id: new ObjectId(owner.userId) });
  if (!user) return c.json({ error: "not_found" }, 404);

  return c.json({
    userId: owner.userId,
    username: user.username ?? null,
    name: user.name ?? "",
    email: user.email ?? "",
    emailVerified: Boolean(user.emailVerified),
  }, 200);
}

export async function handlePatchOwnerMe(c: Context) {
  const database = await getDb();
  const owner = await resolveOwner(c, database);
  if (!owner.ok) return owner.response;

  const body = await c.req.json().catch(() => null);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return c.json({ error: "invalid_body", message: "JSON object required" }, 400);
  }
  for (const key of Object.keys(body)) {
    if (!ALLOWED_PROFILE_FIELDS.has(key)) {
      return c.json({ error: "forbidden_field", message: `Field '${key}' cannot be modified here` }, 400);
    }
  }

  const updates: Record<string, any> = { updatedAt: new Date() };
  let nextUsernameLookup: string | null = null;

  if ("name" in body) {
    if (typeof body.name !== "string" || body.name.trim().length < 1 || body.name.trim().length > 80) {
      return c.json({ error: "invalid_name", message: "Display name must be 1 to 80 characters" }, 400);
    }
    updates.name = body.name.trim();
  }

  if ("username" in body) {
    const parsed = normalizeUsername(body.username);
    if (!parsed) {
      return c.json({ error: "invalid_username", message: "Invalid username" }, 400);
    }
    updates.username = parsed.display;
    updates.usernameNormalized = parsed.normalized;
    nextUsernameLookup = computeUsernameLookup(parsed.normalized);
  }

  const userObjectId = new ObjectId(owner.userId);
  const mongoSession = client.startSession();
  try {
    await mongoSession.withTransaction(async () => {
      if (nextUsernameLookup) {
        const dupUser = await database.collection("user").findOne(
          {
            _id: { $ne: userObjectId },
            $or: [{ usernameNormalized: updates.usernameNormalized }, { username: updates.username }],
          },
          { session: mongoSession }
        );
        const dupLookup = await database.collection("identity_lookup").findOne(
          { kind: "username", keyVersion: 1, keyedLookup: nextUsernameLookup, userId: { $ne: owner.userId } },
          { session: mongoSession }
        );
        if (dupUser || dupLookup) {
          throw Object.assign(new Error("Username is already taken"), { status: 409, code: "username_taken" });
        }
        await database.collection("identity_lookup").updateOne(
          { kind: "username", userId: owner.userId },
          { $set: { kind: "username", userId: owner.userId, keyVersion: 1, keyedLookup: nextUsernameLookup, updatedAt: updates.updatedAt } },
          { upsert: true, session: mongoSession }
        );
      }
      await database.collection("user").updateOne({ _id: userObjectId }, { $set: updates }, { session: mongoSession });
    });
  } catch (err: any) {
    if (err?.status === 409) {
      return c.json({ error: err.code || "username_taken", message: err.message }, 409);
    }
    throw err;
  } finally {
    await mongoSession.endSession();
  }

  const updated = await database.collection("user").findOne({ _id: userObjectId });
  return c.json({
    userId: owner.userId,
    username: updated?.username ?? null,
    name: updated?.name ?? "",
    email: updated?.email ?? "",
    emailVerified: Boolean(updated?.emailVerified),
  }, 200);
}
