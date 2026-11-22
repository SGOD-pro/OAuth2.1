import {
  getOriginCache,
  putOriginCache,
  invalidateOriginCache,
  markSharedRedisOutage,
  getSharedRedisOutage,
  getNextAuthoritativeVersion,
} from "../db/state";
import { getDb } from "../db/mongo";
import {
  getCachedOriginRedis,
  setCachedOriginRedis,
  setOriginLeaseRedis,
  invalidateCachedOriginRedis,
} from "./redis";
import {
  normalizeOrigin,
} from "../utils/security";
import { extractClientOrigins } from "./client-origin-extractor";
import {
  type OriginCheckContext,
  lastInvalidatedVersion,
  pruneInvalidatedVersion,
  getInvalidationMapSizeForTesting,
  clearInvalidationMapForTesting,
  globalLastInvalidatedVersion,
  setGlobalLastInvalidatedVersion,
  redisOutageDetected,
  setRedisOutageDetected,
  getRedisOutageDetected,
  setRedisOutageDetectedForTesting,
  getLastInvalidatedAt,
  preRedisWriteHook,
  postMongoCheckHook,
  setPreRedisWriteHookForTesting,
  setPostMongoCheckHookForTesting,
} from "./origin-cache-state";

export {
  extractClientOrigins,
  type OriginCheckContext,
  getInvalidationMapSizeForTesting,
  clearInvalidationMapForTesting,
  getRedisOutageDetected,
  setRedisOutageDetectedForTesting,
  getLastInvalidatedAt,
  setPreRedisWriteHookForTesting,
  setPostMongoCheckHookForTesting,
};

/**
 * Marks the start of an origin validation check.
 * The returned context token must be passed to setCachedOrigin to prevent
 * in-flight reads from repopulating the cache with stale data after a client mutation.
 *
 * Sourced strictly from MongoDB's single authoritative sequence counter.
 * If MongoDB is unreachable, this fails closed (throws).
 */
export async function startOriginCheck(origin: string): Promise<OriginCheckContext> {
  const normalized = normalizeOrigin(origin) || origin;
  const version = await getNextAuthoritativeVersion();

  try {
    await setOriginLeaseRedis(normalized, version);
  } catch {}

  return {
    origin: normalized,
    startVersion: version,
    startTime: version,
  };
}

export async function getCachedOrigin(
  origin: string,
): Promise<boolean | null> {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return false;

  let db: any = null;
  try {
    db = await getDb();
  } catch {}

  const sharedOutage = db ? await getSharedRedisOutage(db) : false;
  const isOutage = redisOutageDetected || sharedOutage;

  // If a previous Redis outage occurred, Redis may hold stale keys from missed invalidations.
  // Attempt recovery flush across instances before trusting any Redis cache hit.
  if (isOutage) {
    try {
      const recoveryVersion = await getNextAuthoritativeVersion(db);
      await invalidateCachedOriginRedis(undefined, recoveryVersion);
      setRedisOutageDetected(false);
      if (db) await markSharedRedisOutage(db, false);
    } catch {
      // Redis is still unavailable, skip Redis and fall back to Mongo
    }
  }

  // 1. Check Redis first (fast REST / memory)
  if (!redisOutageDetected && !(db && await getSharedRedisOutage(db))) {
    try {
      const redisVal = await getCachedOriginRedis(normalized);
      if (redisVal !== null) {
        return redisVal;
      }
    } catch (err) {
      console.error({ event: "redis_origin_cache_read_error", origin: normalized, error: String(err) });
    }
  }

  // 2. Fall back to MongoDB cache collection
  try {
    return await getOriginCache(normalized);
  } catch (err) {
    console.error({ event: "mongo_origin_cache_read_error", origin: normalized, error: String(err) });
    return null;
  }
}

export async function setCachedOrigin(
  origin: string,
  allowed: boolean,
  checkContext?: OriginCheckContext | number,
): Promise<void> {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return;

  let startVersion = typeof checkContext === "number"
    ? checkContext
    : checkContext?.startVersion ?? checkContext?.startTime;

  if (startVersion === undefined || startVersion <= 0) {
    try {
      startVersion = await getNextAuthoritativeVersion();
      await setOriginLeaseRedis(normalized, startVersion);
    } catch {}
  } else if (typeof checkContext === "number") {
    try {
      await setOriginLeaseRedis(normalized, startVersion);
    } catch {}
  }

  if (typeof startVersion === "number" && startVersion > 0) {
    const originInvVersion = lastInvalidatedVersion.get(normalized) || 0;
    const globalInvVersion = globalLastInvalidatedVersion;

    if (originInvVersion >= startVersion || globalInvVersion >= startVersion) {
      // An invalidation occurred at or after this check began.
      // Do NOT write to cache; this avoids repopulating stale data.
      return;
    }
  }

  // Authoritative Durable Verification:
  // Write to MongoDB FIRST. MongoDB is the authoritative, durable sequence coordinator.
  // putOriginCache performs an atomic conditional update/insert against durable
  // invalidation markers (ORIGIN#__GLOBAL_TOMBSTONE__ and origin-specific invalidatedVersion).
  // If an invalidation occurred at or after startVersion, putOriginCache returns false.
  let mongoAccepted = false;
  try {
    mongoAccepted = await putOriginCache(normalized, allowed, startVersion);
  } catch (err) {
    console.error({ event: "mongo_origin_cache_write_error", origin: normalized, error: String(err) });
    // MongoDB is unavailable. We cannot prove this write is not stale.
    // In accordance with fail-secure policy, do NOT write unverified data to Redis.
    return;
  }

  // If MongoDB rejected the write as stale or superseded, NEVER write to Redis.
  if (!mongoAccepted) {
    if (typeof startVersion === "number" && startVersion > 0) {
      const cur = lastInvalidatedVersion.get(normalized) || 0;
      if (startVersion > cur) {
        lastInvalidatedVersion.set(normalized, startVersion);
      }
    }
    return;
  }

  // Testing hook to simulate an interleaved pause right after MongoDB accepts
  // but before Redis receives the write
  if (preRedisWriteHook) {
    try {
      await preRedisWriteHook(normalized, allowed, startVersion);
    } catch (hookErr) {
      console.error({ event: "pre_redis_write_hook_error", origin: normalized, error: String(hookErr) });
    }
  }

  // Pre-Redis Write Guard:
  // Re-verify that MongoDB has NOT recorded an invalidation (global or origin-specific)
  // while this process was paused or waiting between MongoDB acceptance and Redis write.
  if (typeof startVersion === "number" && startVersion > 0) {
    try {
      const db = await getDb();
      const coll = db.collection("origin_cache");
      const tombstones = await coll
        .find({
          _id: { $in: ["ORIGIN#__GLOBAL_TOMBSTONE__", `ORIGIN_INV#${normalized}`, `ORIGIN#${normalized}`] as any },
        })
        .toArray();

      const globalTombstone = tombstones.find((d: any) => d._id === "ORIGIN#__GLOBAL_TOMBSTONE__");
      const originTombstone = tombstones.find((d: any) => d._id === `ORIGIN_INV#${normalized}`);
      const originDoc = tombstones.find((d: any) => d._id === `ORIGIN#${normalized}`);

      if (
        (globalTombstone && typeof globalTombstone.invalidatedVersion === "number" && globalTombstone.invalidatedVersion >= startVersion) ||
        (originTombstone && typeof originTombstone.invalidatedVersion === "number" && originTombstone.invalidatedVersion >= startVersion) ||
        (originDoc && (originDoc.allowed === null || (typeof originDoc.invalidatedVersion === "number" && originDoc.invalidatedVersion >= startVersion)))
      ) {
        // An invalidation occurred between MongoDB write and Redis write. Abort Redis write.
        return;
      }
    } catch {
      // Fail secure: if verification fails, do NOT write to Redis
      return;
    }
  }

  // Post-Mongo Check Hook:
  // Testing hook to simulate an interleaved pause right AFTER the final MongoDB
  // check passes, but BEFORE setCachedOriginRedis is invoked.
  if (postMongoCheckHook) {
    try {
      await postMongoCheckHook(normalized, allowed, startVersion);
    } catch (hookErr) {
      console.error({ event: "post_mongo_check_hook_error", origin: normalized, error: String(hookErr) });
    }
  }

  // MongoDB accepted the write and remains uninvalidated: populate Redis with the verified decision.
  try {
    await setCachedOriginRedis(normalized, allowed, startVersion);
  } catch (err) {
    console.error({ event: "redis_origin_cache_write_error", origin: normalized, error: String(err) });
  }
}

import {
  invalidateOrigins,
  invalidateClientOrigins,
  clearOriginCache,
  invalidateOrigin,
} from "./origin-invalidation";

export {
  invalidateOrigins,
  invalidateClientOrigins,
  clearOriginCache,
  invalidateOrigin,
};
