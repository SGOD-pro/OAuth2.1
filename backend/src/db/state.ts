import { getDb } from "./mongo";
import {
  getCachedTokenFamilyStatus,
  setCachedTokenFamilyStatus,
  invalidateCachedTokenFamily,
} from "../cache/redis";

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
  allowed: boolean;
  cachedAt: Date;
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
      safeIndex("oauthClient", { clientId: 1 }),
      safeIndex("oauthRefreshToken", { token: 1 }),
      safeIndex("oauthAccessToken", { token: 1 }),
      safeIndex("oauthAuthorizationCode", { code: 1 }),
      safeIndex("admin_audit", { timestamp: -1 }),
      safeIndex("app_admin_revoked_tokens", { expiresAt: 1 }, { expireAfterSeconds: 0 }),
      safeIndex("user_app_registrations", { clientId: 1, userId: 1 }, { unique: true }),
      safeIndex("oauth_transactions", { expiresAt: 1 }, { expireAfterSeconds: 0 }),
      safeIndex("oauth_transactions", { transactionId: 1 }, { unique: true }),
      safeIndex("oauth_transactions", { state: 1 }),
    ]);
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

export async function incrementRateLimit(
  ip: string,
  now: number,
  windowMs: number,
): Promise<RateLimitEntry> {
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

  return entry?.allowed ?? null;
}

export async function putOriginCache(
  origin: string,
  allowed: boolean,
): Promise<void> {
  await ensureTtlIndexes();

  const db = await getDb();
  await db.collection<OriginCacheDoc>("origin_cache").updateOne(
    { _id: `ORIGIN#${origin}` },
    {
      $set: {
        allowed,
        cachedAt: new Date(),
      },
    },
    { upsert: true },
  );
}

export async function invalidateOriginCache(
  origins?: string[],
): Promise<void> {
  await ensureTtlIndexes();

  const db = await getDb();
  const collection = db.collection<OriginCacheDoc>("origin_cache");

  if (origins && origins.length > 0) {
    await collection.deleteMany({
      _id: { $in: origins.map((origin) => `ORIGIN#${origin}`) },
    });
    return;
  }

  await collection.deleteMany({ _id: /^ORIGIN#/ });
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
  await ensureTtlIndexes();
  const db = await getDb();

  await db.collection<TokenFamilyDoc>("oauth_token_families").insertOne({
    familyId,
    clientId,
    userId,
    activeTokenHash: initialTokenHash,
    consumedTokenHashes: [],
    status: "active",
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  await setCachedTokenFamilyStatus(familyId, "active");
}

export async function verifyAndRotateTokenFamily(
  incomingTokenHash: string,
  newTokenHash: string,
  userId?: string,
  nowMs: number = Date.now()
): Promise<{
  valid: boolean;
  replayed: boolean;
  familyId?: string;
  clientId?: string;
  userId?: string;
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

  // 2. Check if family is already revoked
  if (doc.status === "revoked") {
    await invalidateCachedTokenFamily(doc.familyId);
    return { valid: false, replayed: true, familyId: doc.familyId, clientId: doc.clientId };
  }

  // 3. Replay Detection (Theft Detected!)
  if (doc.consumedTokenHashes.includes(incomingTokenHash)) {
    // When checking with a dummy hash, distinguish between an in-flight concurrent race
    // (within 2000ms grace window of rotation) and a subsequent replay theft attempt.
    const timeSinceRotation = doc.updatedAt ? nowMs - new Date(doc.updatedAt).getTime() : 10000;
    const isConcurrentCheck = newTokenHash === "dummy" && timeSinceRotation < 2000;

    if (isConcurrentCheck) {
      // In-flight collision: The token was legitimately rotated by the winning concurrent request.
      // Reject this loser request as consumed without revoking the winner's active family.
      return { valid: false, replayed: false, familyId: doc.familyId, clientId: doc.clientId, userId: doc.userId };
    }

    // FAIL-SECURE: Immediately cascade-revoke the entire family on true replay theft
    await db.collection<TokenFamilyDoc>("oauth_token_families").updateOne(
      { _id: doc._id },
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

    await invalidateCachedTokenFamily(doc.familyId);
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
      // Race condition detected! Another concurrent request rotated the token
      return {
        valid: false,
        replayed: true,
        familyId: doc.familyId,
        clientId: doc.clientId,
        userId: doc.userId || userId,
      };
    }

    await setCachedTokenFamilyStatus(doc.familyId, "active");
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

  if (criteria.transactionId && criteria.state) {
    query.$or = [{ transactionId: criteria.transactionId }, { state: criteria.state }];
  } else if (criteria.transactionId) {
    query.transactionId = criteria.transactionId;
  } else if (criteria.state) {
    query.state = criteria.state;
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
