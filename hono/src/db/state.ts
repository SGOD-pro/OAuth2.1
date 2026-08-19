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

let indexPromise: Promise<void> | null = null;

export async function ensureTtlIndexes(): Promise<void> {
  indexPromise ??= (async () => {
    const db = await getDb();

    await Promise.all([
      db
        .collection<RateLimitDoc>("rate_limits")
        .createIndex({ createdAt: 1 }, { expireAfterSeconds: 60 }),
      db
        .collection<OriginCacheDoc>("origin_cache")
        .createIndex({ cachedAt: 1 }, { expireAfterSeconds: 300 }),
      db
        .collection<TokenFamilyDoc>("oauth_token_families")
        .createIndex({ familyId: 1 }, { unique: true }),
      db
        .collection<TokenFamilyDoc>("oauth_token_families")
        .createIndex({ activeTokenHash: 1 }),
      db
        .collection<TokenFamilyDoc>("oauth_token_families")
        .createIndex({ consumedTokenHashes: 1 }),
      db
        .collection<AdminAuditEvent>("admin_audit")
        .createIndex({ timestamp: -1 }),
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
  newTokenHash: string
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
    // FAIL-SECURE: Immediately cascade-revoke the entire family
    await db.collection<TokenFamilyDoc>("oauth_token_families").updateOne(
      { _id: doc._id },
      { $set: { status: "revoked", revokedAt: new Date() } }
    );

    // Revoke all active tokens for this client/user
    if (doc.clientId) {
      await Promise.all([
        db.collection("oauthAccessToken").deleteMany({ clientId: doc.clientId }),
        db.collection("oauthRefreshToken").deleteMany({ clientId: doc.clientId }),
        db.collection("oauthAuthorizationCode").deleteMany({ clientId: doc.clientId }),
      ]);
    }

    await invalidateCachedTokenFamily(doc.familyId);
    await recordAdminAudit({
      action: "token_family_revoked_on_replay",
      targetClientId: doc.clientId,
      targetUserId: doc.userId,
      details: { familyId: doc.familyId, replayedTokenHash: incomingTokenHash },
      timestamp: new Date(),
    });

    return { valid: false, replayed: true, familyId: doc.familyId, clientId: doc.clientId };
  }

  // 4. Legitimate Rotation
  if (doc.activeTokenHash === incomingTokenHash) {
    await db.collection<TokenFamilyDoc>("oauth_token_families").updateOne(
      { _id: doc._id },
      {
        $push: { consumedTokenHashes: incomingTokenHash },
        $set: { activeTokenHash: newTokenHash, updatedAt: new Date() },
      }
    );

    await setCachedTokenFamilyStatus(doc.familyId, "active");
    return {
      valid: true,
      replayed: false,
      familyId: doc.familyId,
      clientId: doc.clientId,
      userId: doc.userId,
    };
  }

  return { valid: false, replayed: false };
}
