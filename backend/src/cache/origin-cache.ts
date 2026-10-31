import {
  getOriginCache,
  putOriginCache,
  invalidateOriginCache,
} from "../db/state";
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

export async function getCachedOrigin(
  origin: string,
): Promise<boolean | null> {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return false;

  // 1. Check Redis first (fast REST / memory)
  try {
    const redisVal = await getCachedOriginRedis(normalized);
    if (redisVal !== null) {
      return redisVal;
    }
  } catch (err) {
    console.error({ event: "redis_origin_cache_read_error", origin: normalized, error: String(err) });
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
): Promise<void> {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return;

  await Promise.allSettled([
    setCachedOriginRedis(normalized, allowed).catch((err) => {
      console.error({ event: "redis_origin_cache_write_error", origin: normalized, error: String(err) });
    }),
    putOriginCache(normalized, allowed).catch((err) => {
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
  }

  await Promise.allSettled([
    invalidateCachedOriginRedis(normalizedOrigins).catch((err) => {
      console.error({ event: "redis_origin_invalidation_error", error: String(err) });
    }),
    invalidateOriginCache(normalizedOrigins).catch((err) => {
      console.error({ event: "mongo_origin_invalidation_error", error: String(err) });
    }),
  ]);
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
