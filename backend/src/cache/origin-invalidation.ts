import {
  getNextAuthoritativeVersion,
  invalidateOriginCache,
  markSharedRedisOutage,
} from "../db/state";
import { getDb } from "../db/mongo";
import { invalidateCachedOriginRedis } from "./redis";
import { normalizeOrigin } from "../utils/security";
import { extractClientOrigins } from "./client-origin-extractor";
import {
  lastInvalidatedVersion,
  pruneInvalidatedVersion,
  globalLastInvalidatedVersion,
  setGlobalLastInvalidatedVersion,
  setRedisOutageDetected,
} from "./origin-cache-state";

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
      const prev = lastInvalidatedVersion.get(norm) || 0;
      if (invalidationVersion > prev) {
        lastInvalidatedVersion.set(norm, invalidationVersion);
      }
    }
    pruneInvalidatedVersion();
  } else {
    if (invalidationVersion > globalLastInvalidatedVersion) {
      setGlobalLastInvalidatedVersion(invalidationVersion);
    }
    for (const [norm, ver] of lastInvalidatedVersion.entries()) {
      if (ver <= invalidationVersion) {
        lastInvalidatedVersion.delete(norm);
      }
    }
  }

  let redisFailed = false;

  await Promise.allSettled([
    invalidateCachedOriginRedis(normalizedOrigins, invalidationVersion).catch((err) => {
      redisFailed = true;
      setRedisOutageDetected(true);
      console.error({ event: "redis_origin_invalidation_error", error: String(err) });
    }),
    invalidateOriginCache(normalizedOrigins, invalidationVersion).catch((err) => {
      console.error({ event: "mongo_origin_invalidation_error", error: String(err) });
    }),
  ]);

  if (redisFailed) {
    setRedisOutageDetected(true);
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
