import { getDb } from "./mongo";
import { selfHealAppAdmins } from "../utils/admin-sync";

export interface RateLimitEntry {
  count: number;
  resetAt: number;
}

interface RateLimitDoc {
  _id: string;
  count: number;
  createdAt: Date;
}

interface OriginCacheDoc {
  _id: string;
  allowed?: boolean | null;
  cachedAt: Date;
  invalidatedAt?: Date;
  invalidatedVersion?: number;
}

export interface TokenFamilyDoc {
  _id?: any;
  familyId: string;
  clientId: string;
  userId?: string;
  activeTokenHash: string;
  consumedTokenHashes: string[];
  status: "active" | "revoked";
  createdAt: Date;
  updatedAt: Date;
  revokedAt?: Date;
}

export interface AdminAuditEvent {
  actorUserId?: string;
  actorEmail?: string;
  actorScope?: string | null;
  action: string;
  targetClientId?: string;
  targetUserId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  timestamp: Date;
}

export interface OAuthTransactionDoc {
  _id?: any;
  transactionId: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  userId?: string;
  status: "pending" | "consumed" | "expired";
  createdAt: Date;
  expiresAt: Date;
}

let indexPromise: Promise<void> | null = null;

export async function ensureTtlIndexes(): Promise<void> {
  indexPromise ??= (async () => {
    const db = await getDb();

    const safeIndex = async (col: string, spec: any, options?: any) => {
      try {
        await db.collection(col).createIndex(spec, options);
      } catch (err: any) {
        // Code 85: IndexOptionsConflict / IndexKeySpecsConflict - ignore if already exists
        if (err?.code !== 85 && err?.codeName !== "IndexOptionsConflict" && err?.code !== 86) {
          console.warn(`[INDEX] Warning creating index on ${col}:`, err?.message || err);
        }
      }
    };

    await Promise.all([
      safeIndex("rate_limits", { createdAt: 1 }, { expireAfterSeconds: 60 }),
      safeIndex("origin_cache", { cachedAt: 1 }, { expireAfterSeconds: 300 }),
      safeIndex("oauth_token_families", { familyId: 1 }, { unique: true }),
      safeIndex("oauth_token_families", { activeTokenHash: 1 }),
      safeIndex("oauth_token_families", { consumedTokenHashes: 1 }),
      safeIndex("oauth_token_families", { clientId: 1, activeTokenHash: 1 }),
      safeIndex("oauthClient", { clientId: 1 }),
      safeIndex("oauthRefreshToken", { token: 1 }),
      safeIndex("oauthAccessToken", { token: 1 }),
      safeIndex("oauthAuthorizationCode", { code: 1 }),
      safeIndex("admin_audit", { timestamp: -1 }),
      safeIndex("app_admin_revoked_tokens", { expiresAt: 1 }, { expireAfterSeconds: 0 }),
      safeIndex("user_app_registrations", { clientId: 1, userId: 1 }, { unique: true }),
      safeIndex("oauthClient", { allowedOrigins: 1, disabled: 1 }),
      safeIndex("oauthClient", { allowed_origins: 1, disabled: 1 }),
      safeIndex("oauthClient", { redirectUris: 1, disabled: 1 }),
      safeIndex("oauthClient", { redirect_uris: 1, disabled: 1 }),
      safeIndex("user", { email: 1 }),
      safeIndex("session", { token: 1 }),
      safeIndex("session", { userId: 1 }),
      safeIndex("oauth_transactions", { expiresAt: 1 }, { expireAfterSeconds: 0 }),
      safeIndex("oauth_transactions", { transactionId: 1 }, { unique: true }),
      safeIndex("oauth_transactions", { state: 1 }),
    ]);

    // Automatically synchronize app administrators into centralized user & account collections
    try {
      await selfHealAppAdmins(db);
    } catch (healErr: any) {
      console.warn("[INDEX] Warning during self-healing app_admins sync:", healErr?.message || healErr);
    }
  })();

  return indexPromise;
}

export async function recordAdminAudit(event: AdminAuditEvent): Promise<void> {
  try {
    await ensureTtlIndexes();
    const db = await getDb();
    await db.collection<AdminAuditEvent>("admin_audit").insertOne({
      ...event,
      timestamp: event.timestamp || new Date(),
    });
  } catch (err) {
    console.error("[AUDIT] Failed to record admin audit event:", err);
  }
}

let rateLimitStoreFailureSimulated = false;

export function __simulateRateLimitStoreFailure(enable: boolean): void {
  rateLimitStoreFailureSimulated = enable;
}

export async function incrementRateLimit(
  ip: string,
  now: number,
  windowMs: number,
): Promise<RateLimitEntry> {
  if (rateLimitStoreFailureSimulated) {
    throw new Error("Simulated rate limit backing store failure / database connection failure");
  }

  await ensureTtlIndexes();

  const db = await getDb();
  const createdAt = new Date(now);
  const cutoff = new Date(now - windowMs);
  const resetAt = now + windowMs;

  const result = await db.collection<RateLimitDoc>("rate_limits").findOneAndUpdate(
    { _id: `RATE#${ip}` },
    [
      {
        $set: {
          count: {
            $cond: [
              { $gt: ["$createdAt", cutoff] },
              { $add: [{ $ifNull: ["$count", 0] }, 1] },
              1,
            ],
          },
          createdAt: {
            $cond: [{ $gt: ["$createdAt", cutoff] }, "$createdAt", createdAt],
          },
        },
      },
    ],
    { upsert: true, returnDocument: "after" },
  );

  return {
    count: result?.count ?? 1,
    resetAt:
      (result?.createdAt?.getTime() ?? createdAt.getTime()) + windowMs,
  };
}

export async function getOriginCache(
  origin: string,
): Promise<boolean | null> {
  await ensureTtlIndexes();

  const db = await getDb();
  const entry = await db
    .collection<OriginCacheDoc>("origin_cache")
    .findOne({ _id: `ORIGIN#${origin}` });

  if (!entry || entry.allowed === null || entry.allowed === undefined) {
    return null;
  }

  return entry.allowed;
}

export async function markSharedRedisOutage(db: any, isOutage: boolean): Promise<void> {
  if (!db) return;
  try {
    const collection = db.collection("origin_cache");
    await collection.updateOne(
      { _id: "ORIGIN#__SHARED_REDIS_OUTAGE__" },
      {
        $set: {
          outage: isOutage,
          updatedAt: new Date(),
        },
      },
      { upsert: true }
    );
  } catch {}
}

export async function getSharedRedisOutage(db: any): Promise<boolean> {
  if (!db) return false;
  try {
    const collection = db.collection("origin_cache");
    const doc = await collection.findOne({ _id: "ORIGIN#__SHARED_REDIS_OUTAGE__" });
    return Boolean(doc && doc.outage === true);
  } catch {
    return false;
  }
}

/**
 * SHARED MONOTONIC VERSION COUNTER (MongoDB fallback)
 *
 * Atomically increments a shared integer version stored in MongoDB and returns
 * the new value. Used when Redis is unavailable to assign a version to each
 * origin check without relying on process wall clocks. Monotonically increasing
 * across all processes that share this MongoDB instance.
 *
 * Uses findOneAndUpdate with $inc so that concurrent callers each receive a
 * unique, ordered version number even under high parallelism.
 */
export async function incrementCacheVersionMongo(): Promise<number> {
  const db = await getDb();
  const collection = db.collection("origin_cache");
  const result = await collection.findOneAndUpdate(
    { _id: "ORIGIN#__CACHE_VERSION__" },
    { $inc: { version: 1 } } as any,
    { upsert: true, returnDocument: "after" }
  );
  const version = (result as any)?.version ?? (result as any)?.value?.version ?? 1;
  return typeof version === "number" ? version : 1;
}

export async function putOriginCache(
  origin: string,
  allowed: boolean,
  startTime?: number,
): Promise<boolean> {
  await ensureTtlIndexes();

  const db = await getDb();
  const collection = db.collection<OriginCacheDoc>("origin_cache");
  const id = `ORIGIN#${origin}`;
  const now = new Date();

  // 1. Check global tombstone if startTime is provided
  if (typeof startTime === "number") {
    const globalTombstone = await collection.findOne({ _id: "ORIGIN#__GLOBAL_TOMBSTONE__" });
    if (globalTombstone) {
      if (
        typeof globalTombstone.invalidatedVersion === "number" &&
        globalTombstone.invalidatedVersion >= startTime
      ) {
        return false;
      }
      if (
        startTime > 1000000000000 &&
        globalTombstone.invalidatedAt &&
        globalTombstone.invalidatedAt.getTime() >= startTime
      ) {
        return false;
      }
    }
  }

  // 2. Atomic write with conditional filter:
  // If document does not exist, insert it.
  // If document exists, update ONLY IF it has NOT been invalidated since startTime.
  if (typeof startTime === "number") {
    const isTimestamp = startTime > 1000000000000;
    const filter: any = {
      _id: id,
      $and: [
        {
          $or: [
            { invalidatedVersion: { $exists: false } },
            { invalidatedVersion: { $lt: startTime } },
          ],
        },
      ],
    };
    if (isTimestamp) {
      filter.$and.push({
        $or: [
          { invalidatedAt: { $exists: false } },
          { invalidatedAt: { $lt: new Date(startTime) } },
        ],
      });
    }

    const update = {
      $set: {
        allowed,
        cachedAt: now,
      },
      $unset: { invalidatedAt: "", invalidatedVersion: "" },
    };

    // Try update first (when document already exists)
    const updateResult = await collection.updateOne(filter, update);
    if (updateResult.matchedCount > 0) {
      return true;
    }

    // Check if document exists with an invalidation newer than startTime
    const existing = await collection.findOne({ _id: id });
    if (existing) {
      if (
        typeof existing.invalidatedVersion === "number" &&
        existing.invalidatedVersion >= startTime
      ) {
        return false;
      }
      if (
        isTimestamp &&
        existing.invalidatedAt &&
        existing.invalidatedAt.getTime() >= startTime
      ) {
        return false;
      }
    }

    // Document didn't exist: attempt atomic insertOne
    try {
      await collection.insertOne({
        _id: id,
        allowed,
        cachedAt: now,
      });
      return true;
    } catch (insertErr: any) {
      if (insertErr?.code === 11000) {
        // Document was created concurrently (e.g. invalidation happened). Re-check conditionally.
        const retryResult = await collection.updateOne(filter, update);
        return retryResult.matchedCount > 0;
      }
      throw insertErr;
    }
  }

  await collection.updateOne(
    { _id: id },
    {
      $set: {
        allowed,
        cachedAt: now,
      },
      $unset: { invalidatedAt: "", invalidatedVersion: "" },
    },
    { upsert: true },
  );
  return true;
}

export async function invalidateOriginCache(
  origins?: string[],
  version?: number,
): Promise<void> {
  await ensureTtlIndexes();

  const db = await getDb();
  const collection = db.collection<OriginCacheDoc>("origin_cache");
  const now = new Date();

  if (origins && origins.length > 0) {
    const ids = origins.map((origin) => `ORIGIN#${origin}`);
    if (typeof collection.bulkWrite === "function") {
      const operations = ids.map((id) => ({
        updateOne: {
          filter: { _id: id },
          update: {
            $set: {
              allowed: null,
              invalidatedAt: now,
              ...(typeof version === "number" ? { invalidatedVersion: version } : {}),
              cachedAt: now,
            },
          },
          upsert: true,
        },
      }));
      await collection.bulkWrite(operations as any, { ordered: false });
    } else {
      for (const id of ids) {
        await collection.updateOne(
          { _id: id },
          {
            $set: {
              allowed: null,
              invalidatedAt: now,
              ...(typeof version === "number" ? { invalidatedVersion: version } : {}),
              cachedAt: now,
            },
          },
          { upsert: true },
        );
      }
    }
    return;
  }

  await collection.deleteMany({ _id: /^ORIGIN#/ });
  await collection.updateOne(
    { _id: "ORIGIN#__GLOBAL_TOMBSTONE__" },
    {
      $set: {
        allowed: null,
        invalidatedAt: now,
        ...(typeof version === "number" ? { invalidatedVersion: version } : {}),
        cachedAt: now,
      },
    },
    { upsert: true },
  );
}

// -------------------------------------------------------------
// B2 Token Family Tracking & Revocation (Fail-Secure / Authoritative Mongo)
// -------------------------------------------------------------

export async function registerTokenFamily(
  familyId: string,
  clientId: string,
  userId: string | undefined,
  initialTokenHash: string
): Promise<void> {
  const trimmedClientId = clientId?.trim();
  if (!trimmedClientId) {
    throw new Error("registerTokenFamily requires a non-empty clientId");
  }
  await ensureTtlIndexes();
  const db = await getDb();

  await db.collection<TokenFamilyDoc>("oauth_token_families").insertOne({
    familyId,
    clientId: trimmedClientId,
    userId,
    activeTokenHash: initialTokenHash,
    consumedTokenHashes: [],
    status: "active",
    createdAt: new Date(),
    updatedAt: new Date(),
  });
}

export async function verifyAndRotateTokenFamily(
  incomingTokenHash: string,
  newTokenHash: string,
  userId?: string,
  nowMs: number = Date.now(),
  expectedClientId?: string
): Promise<{
  valid: boolean;
  replayed: boolean;
  familyId?: string;
  clientId?: string;
  userId?: string;
  clientMismatch?: boolean;
}> {
  await ensureTtlIndexes();
  const db = await getDb();

  // 1. Authoritative lookup in MongoDB
  const doc = await db.collection<TokenFamilyDoc>("oauth_token_families").findOne({
    $or: [
      { activeTokenHash: incomingTokenHash },
      { consumedTokenHashes: incomingTokenHash },
    ],
  });

  if (!doc) {
    return { valid: false, replayed: false };
  }

  // 1b. Defense-in-depth: Cross-client isolation boundary
  // If an expectedClientId is specified, caller MUST own this token family.
  // Under NO circumstances may an unauthenticated or cross-client caller rotate,
  // lock, inspect, or cascade-revoke a family belonging to another client.
  // FAIL-CLOSED: doc.clientId must exist and match expectedClientId exactly.
  if (expectedClientId && (!doc.clientId || doc.clientId !== expectedClientId)) {
    return {
      valid: false,
      replayed: false,
      familyId: doc.familyId,
      clientId: doc.clientId,
      userId: doc.userId,
      clientMismatch: true,
    };
  }

  // 2. Check if family is already revoked
  if (doc.status === "revoked") {
    return { valid: false, replayed: true, familyId: doc.familyId, clientId: doc.clientId };
  }

  // 3. Replay Detection (Theft Detected!)
  if (doc.consumedTokenHashes.includes(incomingTokenHash)) {
    // Distinguish between an in-flight concurrent race (within 2000ms grace window of rotation)
    // and a subsequent replay theft attempt.
    const rotationTime = (doc as any).rotatedAt || doc.updatedAt;
    const timeSinceRotation = rotationTime ? Math.max(0, nowMs - new Date(rotationTime).getTime()) : 10000;
    const isWithinGraceWindow = timeSinceRotation < 2000;

    if (isWithinGraceWindow) {
      // In-flight collision: The token was legitimately rotated by the winning concurrent request.
      // Reject this loser request as consumed without revoking the winner's active family.
      return { valid: false, replayed: false, familyId: doc.familyId, clientId: doc.clientId, userId: doc.userId };
    }

    // FAIL-SECURE: Immediately cascade-revoke the entire family on true replay theft
    await db.collection<TokenFamilyDoc>("oauth_token_families").updateOne(
      { _id: doc._id, ...(doc.clientId ? { clientId: doc.clientId } : {}) },
      { $set: { status: "revoked", revokedAt: new Date() } }
    );

    // Revoke all active tokens for this client/user scope.
    // FAIL-CLOSED: If userId is missing, DO NOT fall back to client-wide deletion ({ clientId }).
    // A missing userId must NEVER cause revocation of unrelated users' credentials!
    if (doc.clientId && doc.userId) {
      const filter = { clientId: doc.clientId, userId: doc.userId };
      await Promise.all([
        db.collection("oauthAccessToken").deleteMany(filter),
        db.collection("oauthRefreshToken").deleteMany(filter),
        db.collection("oauthAuthorizationCode").deleteMany(filter),
      ]);
    } else {
      console.warn(`[TOKEN_FAMILY_REPLAY] Warning: Family ${doc.familyId} has missing userId/clientId; revoking family record only to prevent cross-user DoS`);
    }

    await recordAdminAudit({
      action: "token_family_revoked_on_replay",
      targetClientId: doc.clientId,
      targetUserId: doc.userId,
      details: { familyId: doc.familyId, replayedTokenHash: incomingTokenHash },
      timestamp: new Date(),
    });

    return { valid: false, replayed: true, familyId: doc.familyId, clientId: doc.clientId, userId: doc.userId };
  }

  // If caller only provided a dummy hash for replay-checking without rotating
  if (newTokenHash === "dummy" || !newTokenHash) {
    return {
      valid: doc.activeTokenHash === incomingTokenHash,
      replayed: false,
      familyId: doc.familyId,
      clientId: doc.clientId,
      userId: doc.userId,
    };
  }

  // 4. Legitimate Rotation with Atomic Compare-and-Swap (CAS)
  if (doc.activeTokenHash === incomingTokenHash) {
    const updateResult = await db.collection<TokenFamilyDoc>("oauth_token_families").updateOne(
      {
        _id: doc._id,
        activeTokenHash: incomingTokenHash,
        status: "active",
        ...(expectedClientId ? { clientId: expectedClientId } : (doc.clientId ? { clientId: doc.clientId } : {})),
      },
      {
        $push: { consumedTokenHashes: incomingTokenHash },
        $set: {
          activeTokenHash: newTokenHash,
          updatedAt: new Date(),
          rotating: false,
          ...(userId && !doc.userId ? { userId } : {}),
        },
      }
    );

    if (updateResult.modifiedCount === 0) {
      // In-flight race condition: Another concurrent request rotated the token first
      return {
        valid: false,
        replayed: false,
        familyId: doc.familyId,
        clientId: doc.clientId,
        userId: doc.userId || userId,
      };
    }

    return {
      valid: true,
      replayed: false,
      familyId: doc.familyId,
      clientId: doc.clientId,
      userId: doc.userId || userId,
    };
  }

  return { valid: false, replayed: false };
}

// -------------------------------------------------------------
// OAuth 2.1 Transaction State Management (Multi-Tab / Replay Isolation)
// -------------------------------------------------------------

export async function createOAuthTransaction(data: {
  transactionId: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  userId?: string;
  ttlSeconds?: number;
}): Promise<OAuthTransactionDoc> {
  await ensureTtlIndexes();
  const db = await getDb();
  const now = new Date();
  const ttl = data.ttlSeconds ?? 600; // 10 minutes default
  const expiresAt = new Date(now.getTime() + ttl * 1000);

  const doc: OAuthTransactionDoc = {
    transactionId: data.transactionId,
    clientId: data.clientId,
    redirectUri: data.redirectUri,
    state: data.state,
    codeChallenge: data.codeChallenge,
    codeChallengeMethod: data.codeChallengeMethod,
    userId: data.userId,
    status: "pending",
    createdAt: now,
    expiresAt,
  };

  await db.collection<OAuthTransactionDoc>("oauth_transactions").insertOne(doc);
  return doc;
}

export async function getOAuthTransaction(criteria: {
  transactionId?: string;
  state?: string;
}): Promise<OAuthTransactionDoc | null> {
  await ensureTtlIndexes();
  const db = await getDb();
  const query: any = { status: "pending", expiresAt: { $gt: new Date() } };

  if (criteria.state) {
    query.state = criteria.state;
  } else if (criteria.transactionId) {
    query.transactionId = criteria.transactionId;
  } else {
    return null;
  }

  return db.collection<OAuthTransactionDoc>("oauth_transactions").findOne(query);
}

export async function consumeOAuthTransaction(transactionId: string): Promise<boolean> {
  await ensureTtlIndexes();
  const db = await getDb();
  const res = await db.collection<OAuthTransactionDoc>("oauth_transactions").updateOne(
    { transactionId, status: "pending" },
    { $set: { status: "consumed", consumedAt: new Date() } as any }
  );
  return res.modifiedCount > 0;
}
