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
  invalidateCachedOriginRedis,
} from "./redis";
import {
  normalizeOrigin,
  deriveAllowedOriginsFromRedirectUris,
} from "../utils/security";

/**
 * Extracts all unique normalized web origins from an OAuth client document
 * or update payload, including explicit allowed origins and origins derived
 * from redirect URIs.
 */
export function extractClientOrigins(client: any): string[] {
  if (!client || typeof client !== "object") return [];
  const origins = new Set<string>();

  const rawAllowed = [
    ...(Array.isArray(client.allowedOrigins) ? client.allowedOrigins : []),
    ...(Array.isArray(client.allowed_origins) ? client.allowed_origins : []),
  ];
  for (const raw of rawAllowed) {
    if (typeof raw === "string") {
      let normalized = normalizeOrigin(raw);
      if (!normalized) {
        try {
          const parsed = new URL(raw);
          if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            normalized = normalizeOrigin(parsed.origin);
          }
        } catch {
          // ignore invalid URLs
        }
      }
      if (normalized) origins.add(normalized);
    }
  }

  const rawRedirects = [
    ...(Array.isArray(client.redirectUris) ? client.redirectUris : []),
    ...(Array.isArray(client.redirect_uris) ? client.redirect_uris : []),
  ];
  const derived = deriveAllowedOriginsFromRedirectUris(rawRedirects);
  for (const d of derived) {
    const normalized = normalizeOrigin(d);
    if (normalized) origins.add(normalized);
  }

  return Array.from(origins);
}

export interface OriginCheckContext {
  origin: string;
  /**
   * Shared monotonic sequence version at the start of this check, sourced
   * from MongoDB's single authoritative counter. Never from independent Redis
   * counters or process wall clocks.
   */
  startVersion: number;
  /** @deprecated use startVersion; kept for wire compatibility */
  startTime: number;
}

const lastInvalidatedVersion = new Map<string, number>();
const MAX_INVALIDATION_MAP_SIZE = 1000;

function pruneInvalidatedVersion(): void {
  if (lastInvalidatedVersion.size > MAX_INVALIDATION_MAP_SIZE) {
    const excess = lastInvalidatedVersion.size - MAX_INVALIDATION_MAP_SIZE;
    let count = 0;
    for (const key of lastInvalidatedVersion.keys()) {
      lastInvalidatedVersion.delete(key);
      count++;
      if (count >= excess) break;
    }
  }
}

export function getInvalidationMapSizeForTesting(): number {
  return lastInvalidatedVersion.size;
}

export function clearInvalidationMapForTesting(): void {
  lastInvalidatedVersion.clear();
  globalLastInvalidatedVersion = 0;
}

let globalLastInvalidatedVersion = 0;
let redisOutageDetected = false;

export function getRedisOutageDetected(): boolean {
  return redisOutageDetected;
}

export function setRedisOutageDetectedForTesting(val: boolean): void {
  redisOutageDetected = val;
}

export function getLastInvalidatedAt(origin: string): number {
  const norm = normalizeOrigin(origin) || origin;
  return Math.max(lastInvalidatedVersion.get(norm) || 0, globalLastInvalidatedVersion);
}

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
      redisOutageDetected = false;
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

  const startVersion = typeof checkContext === "number"
    ? checkContext
    : checkContext?.startVersion ?? checkContext?.startTime;

  if (typeof startVersion === "number" && startVersion > 0) {
    const originInvVersion = lastInvalidatedVersion.get(normalized) || 0;
    const globalInvVersion = globalLastInvalidatedVersion;

    if (originInvVersion >= startVersion || globalInvVersion >= startVersion) {
      // An invalidation occurred at or after this check began.
      // Do NOT write to cache; this avoids repopulating stale data.
      return;
    }
  }

  await Promise.allSettled([
    setCachedOriginRedis(normalized, allowed, startVersion).catch((err) => {
      console.error({ event: "redis_origin_cache_write_error", origin: normalized, error: String(err) });
    }),
    putOriginCache(normalized, allowed, startVersion).catch((err) => {
      console.error({ event: "mongo_origin_cache_write_error", origin: normalized, error: String(err) });
    }),
  ]);
}

/**
 * Invalidates CORS origin cache entries across Redis and MongoDB.
 * If origins is omitted or empty, clears all origin cache entries.
 * Safe against Redis unavailability; MongoDB invalidation always proceeds.
 */
export async function invalidateOrigins(
  origins?: string[],
): Promise<void> {
  let normalizedOrigins: string[] | undefined;

  // Obtain the single authoritative version sequence from MongoDB
  const invalidationVersion = await getNextAuthoritativeVersion();

  if (origins && Array.isArray(origins) && origins.length > 0) {
    const set = new Set<string>();
    for (const o of origins) {
      if (typeof o === "string") {
        let norm = normalizeOrigin(o);
        if (!norm) {
          try {
            const parsed = new URL(o);
            if (parsed.protocol === "http:" || parsed.protocol === "https:") {
              norm = normalizeOrigin(parsed.origin);
            }
          } catch {}
        }
        if (norm) set.add(norm);
      }
    }
    normalizedOrigins = Array.from(set);
    if (normalizedOrigins.length === 0) return;

    for (const norm of normalizedOrigins) {
      lastInvalidatedVersion.set(norm, invalidationVersion);
    }
    pruneInvalidatedVersion();
  } else {
    globalLastInvalidatedVersion = invalidationVersion;
    lastInvalidatedVersion.clear();
  }

  let redisFailed = false;

  await Promise.allSettled([
    invalidateCachedOriginRedis(normalizedOrigins, invalidationVersion).catch((err) => {
      redisFailed = true;
      redisOutageDetected = true;
      console.error({ event: "redis_origin_invalidation_error", error: String(err) });
    }),
    invalidateOriginCache(normalizedOrigins, invalidationVersion).catch((err) => {
      console.error({ event: "mongo_origin_invalidation_error", error: String(err) });
    }),
  ]);

  if (redisFailed) {
    redisOutageDetected = true;
    try {
      const db = await getDb();
      await markSharedRedisOutage(db, true);
    } catch {}
  }
}

/**
 * Invalidates CORS origin cache entries for both the old client state and
 * the updated client state, covering explicit allowed origins and redirect URIs.
 * Call this after database mutations to prevent invalidation races.
 */
export async function invalidateClientOrigins(
  oldClient: any,
  newClientOrUpdates?: any,
): Promise<void> {
  const oldOrigins = extractClientOrigins(oldClient);
  const newOrigins = extractClientOrigins(newClientOrUpdates);
  const combined = Array.from(new Set([...oldOrigins, ...newOrigins]));
  if (combined.length > 0) {
    await invalidateOrigins(combined);
  }
}

export async function clearOriginCache(): Promise<void> {
  await invalidateOrigins();
}

export async function invalidateOrigin(
  origin: string,
): Promise<void> {
  await invalidateOrigins([origin]);
}
