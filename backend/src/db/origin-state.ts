import { getDb } from "./mongo";
import { ensureTtlIndexes } from "./indexes";

export interface OriginCacheDoc {
  _id: string;
  allowed?: boolean | null;
  cachedAt?: Date;
  invalidatedAt?: Date;
  invalidatedVersion?: number;
  cachedVersion?: number;
  updatedAt?: Date;
}

export async function getOriginCache(
  origin: string,
): Promise<boolean | null> {
  await ensureTtlIndexes();

  const db = await getDb();
  const docs = await db
    .collection<OriginCacheDoc>("origin_cache")
    .find({
      _id: {
        $in: [
          `ORIGIN#${origin}`,
          `ORIGIN_INV#${origin}`,
          "ORIGIN#__GLOBAL_TOMBSTONE__",
        ],
      },
    })
    .toArray();

  const entry = docs.find((d) => d._id === `ORIGIN#${origin}`);
  const originTombstone = docs.find((d) => d._id === `ORIGIN_INV#${origin}`);
  const globalTombstone = docs.find((d) => d._id === "ORIGIN#__GLOBAL_TOMBSTONE__");

  if (!entry || entry.allowed === null || entry.allowed === undefined) {
    return null;
  }

  // Check 300s software TTL expiration on cachedAt
  if (entry.cachedAt && Date.now() - new Date(entry.cachedAt).getTime() > 300_000) {
    return null;
  }

  // If specific entry was invalidated at or after its cached version, entry is stale
  if (
    typeof entry.invalidatedVersion === "number" &&
    (typeof entry.cachedVersion !== "number" || entry.cachedVersion <= entry.invalidatedVersion)
  ) {
    return null;
  }

  // If durable origin tombstone has invalidatedVersion >= cachedVersion, entry is stale
  if (
    originTombstone &&
    typeof originTombstone.invalidatedVersion === "number" &&
    (typeof entry.cachedVersion !== "number" || entry.cachedVersion <= originTombstone.invalidatedVersion)
  ) {
    return null;
  }

  // If global invalidation occurred at or after this entry's cached version, entry is stale
  if (
    globalTombstone &&
    typeof globalTombstone.invalidatedVersion === "number" &&
    (typeof entry.cachedVersion !== "number" || entry.cachedVersion <= globalTombstone.invalidatedVersion)
  ) {
    return null;
  }

  return entry.allowed;
}

export async function markSharedRedisOutage(db: any, isOutage: boolean): Promise<void> {
  if (!db) return;
  try {
    const collection = db.collection("origin_cache");
    await collection.updateOne(
      { _id: "__SHARED_REDIS_OUTAGE__" },
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
    const doc = await collection.findOne({ _id: "__SHARED_REDIS_OUTAGE__" });
    return Boolean(doc && doc.outage === true);
  } catch {
    return false;
  }
}

export async function getNextAuthoritativeVersion(db?: any): Promise<number> {
  const database = db || await getDb();
  const collection = database.collection("origin_cache");
  const result = await collection.findOneAndUpdate(
    { _id: "__ORIGIN_AUTHORITATIVE_VERSION__" },
    { $inc: { version: 1 } },
    { upsert: true, returnDocument: "after" }
  );
  const version = (result as any)?.version ?? (result as any)?.value?.version ?? 1;
  return typeof version === "number" ? version : 1;
}

// Backwards-compatible alias for existing callers/tests
export const incrementCacheVersionMongo = getNextAuthoritativeVersion;

export async function putOriginCache(
  origin: string,
  allowed: boolean,
  version?: number,
): Promise<boolean> {
  await ensureTtlIndexes();

  const db = await getDb();
  const collection = db.collection<OriginCacheDoc>("origin_cache");
  const id = `ORIGIN#${origin}`;
  const invId = `ORIGIN_INV#${origin}`;
  const now = new Date();

  const effectiveVersion =
    typeof version === "number" && version > 0
      ? version
      : await getNextAuthoritativeVersion(db);

  // 1. Check durable tombstones (both global and origin-specific)
  const tombstones = await collection
    .find({ _id: { $in: ["ORIGIN#__GLOBAL_TOMBSTONE__", invId] } })
    .toArray();

  const globalTombstone = tombstones.find((d) => d._id === "ORIGIN#__GLOBAL_TOMBSTONE__");
  const originTombstone = tombstones.find((d) => d._id === invId);

  if (
    globalTombstone &&
    typeof globalTombstone.invalidatedVersion === "number" &&
    globalTombstone.invalidatedVersion >= effectiveVersion
  ) {
    // Global invalidation occurred at or after this check began. Refuse to write.
    return false;
  }

  if (
    originTombstone &&
    typeof originTombstone.invalidatedVersion === "number" &&
    originTombstone.invalidatedVersion >= effectiveVersion
  ) {
    // Origin-specific invalidation occurred at or after this check began. Refuse to write.
    return false;
  }

  // 2. Atomic write with conditional filter
  const filter = {
    _id: id,
    $and: [
      {
        $or: [
          { cachedVersion: { $exists: false } },
          { cachedVersion: { $lt: effectiveVersion } },
        ],
      },
      {
        $or: [
          { invalidatedVersion: { $exists: false } },
          { invalidatedVersion: { $lt: effectiveVersion } },
        ],
      },
    ],
  };

  const update = {
    $set: {
      allowed,
      cachedAt: now,
      cachedVersion: effectiveVersion,
      ...(originTombstone && typeof originTombstone.invalidatedVersion === "number"
        ? { invalidatedVersion: originTombstone.invalidatedVersion }
        : {}),
    },
  };

  const updateResult = await collection.updateOne(filter, update);
  if (updateResult.matchedCount > 0) {
    const postChecks = await collection
      .find({ _id: { $in: ["ORIGIN#__GLOBAL_TOMBSTONE__", invId] } })
      .toArray();
    const postGlobal = postChecks.find((d) => d._id === "ORIGIN#__GLOBAL_TOMBSTONE__");
    const postInv = postChecks.find((d) => d._id === invId);

    if (
      (postGlobal && typeof postGlobal.invalidatedVersion === "number" && postGlobal.invalidatedVersion >= effectiveVersion) ||
      (postInv && typeof postInv.invalidatedVersion === "number" && postInv.invalidatedVersion >= effectiveVersion)
    ) {
      await collection.updateOne(
        { _id: id, cachedVersion: effectiveVersion },
        { $set: { allowed: null }, $unset: { cachedAt: "" } },
      );
      return false;
    }
    return true;
  }

  const existing = await collection.findOne({ _id: id });
  if (existing) {
    if (
      (typeof existing.cachedVersion === "number" && existing.cachedVersion >= effectiveVersion) ||
      (typeof existing.invalidatedVersion === "number" && existing.invalidatedVersion >= effectiveVersion)
    ) {
      return false;
    }
  }

  try {
    await collection.insertOne({
      _id: id,
      allowed,
      cachedAt: now,
      cachedVersion: effectiveVersion,
      ...(originTombstone && typeof originTombstone.invalidatedVersion === "number"
        ? { invalidatedVersion: originTombstone.invalidatedVersion }
        : {}),
    });

    const finalChecks = await collection
      .find({ _id: { $in: ["ORIGIN#__GLOBAL_TOMBSTONE__", invId] } })
      .toArray();
    const finalGlobal = finalChecks.find((d) => d._id === "ORIGIN#__GLOBAL_TOMBSTONE__");
    const finalInv = finalChecks.find((d) => d._id === invId);

    if (
      (finalGlobal && typeof finalGlobal.invalidatedVersion === "number" && finalGlobal.invalidatedVersion >= effectiveVersion) ||
      (finalInv && typeof finalInv.invalidatedVersion === "number" && finalInv.invalidatedVersion >= effectiveVersion)
    ) {
      await collection.deleteOne({ _id: id, cachedVersion: effectiveVersion });
      return false;
    }

    return true;
  } catch (insertErr: any) {
    if (insertErr?.code === 11000) {
      const retryResult = await collection.updateOne(filter, update);
      return retryResult.matchedCount > 0;
    }
    throw insertErr;
  }
}

export { invalidateOriginCache } from "./origin-invalidation-db";
