import { redis } from "./redis";
import { config } from "../config";
import {
  GET_ORIGIN_CACHE_LUA,
  SET_ORIGIN_CACHE_LUA,
  INVALIDATE_ORIGIN_CACHE_LUA,
  INVALIDATE_GLOBAL_ORIGIN_CACHE_LUA,
  SET_ORIGIN_LEASE_LUA,
  CLEANUP_ABANDONED_LEASES_LUA,
} from "./origin-lua";

const ORIGIN_CACHE_TTL_SECONDS = 300;

let _globalInvalidationMidHook: (() => Promise<void>) | null = null;

export function setGlobalInvalidationMidHookForTesting(
  hook: (() => Promise<void>) | null,
): void {
  _globalInvalidationMidHook = hook;
}

/**
 * Origin allow-list cache. Failure behavior is "cache miss", never
 * "allowed" - a Redis error must fall through to the authoritative
 * MongoDB lookup in cors.ts's isOriginAllowed(), exactly like a genuine
 * cache miss. Never let a Redis error short-circuit into treating an
 * unverified origin as trusted.
 */
export async function getCachedOriginRedis(origin: string): Promise<boolean | null> {
  if (!redis) return null;
  try {
    const originKey = `swyra:origin:${origin}`;
    const verKey = `swyra:origin:ver:${origin}`;
    const invKey = `swyra:origin:inv:${origin}`;
    const globalInvKey = "swyra:inv:global";

    const res = await redis.eval(
      GET_ORIGIN_CACHE_LUA,
      [originKey, verKey, invKey, globalInvKey],
      [],
    );
    if (res === null || res === undefined) return null;

    if (res === true || res === "1" || res === 1 || res === "true") return true;
    if (res === false || res === "0" || res === 0 || res === "false") return false;
    return null;
  } catch (error) {
    console.error({ event: "redis_origin_cache_read_failed", origin, error: String(error) });
    return null;
  }
}

export async function setOriginLeaseRedis(
  origin: string,
  version: number,
  ttlSeconds: number = 60,
): Promise<boolean> {
  if (!redis || !version || version <= 0) return false;
  try {
    const leaseKey = `swyra:origin:lease:${origin}`;
    const leasesKey = "swyra:origin:leases";
    const res = await redis.eval(
      SET_ORIGIN_LEASE_LUA,
      [leaseKey, leasesKey],
      [origin, String(version), String(ttlSeconds), "3600"],
    );

    // Opportunistic bounded cleanup: 1 out of 20 lease sets triggers a bounded batch cleanup in production
    if (config.env === "production" && Math.random() < 0.05) {
      cleanupAbandonedOriginLeasesRedis("auto", 50, 50).catch(() => {});
    }

    return res === 1 || res === "1" || res === true;
  } catch (err) {
    console.error({ event: "redis_origin_lease_set_failed", origin, error: String(err) });
    return false;
  }
}

export async function cleanupAbandonedOriginLeasesRedis(
  cursor: string = "auto",
  batchSize: number = 50,
  maxEntries: number = batchSize,
): Promise<{ nextCursor: string; cleanedCount: number; processedCount: number }> {
  if (!redis) return { nextCursor: "0", cleanedCount: 0, processedCount: 0 };
  try {
    const leasesKey = "swyra:origin:leases";
    const cursorKey = "swyra:origin:leases:cursor";
    const leftoversKey = "swyra:origin:leases:leftovers";
    const res = await redis.eval(
      CLEANUP_ABANDONED_LEASES_LUA,
      [leasesKey, cursorKey, leftoversKey],
      [cursor, String(batchSize), String(maxEntries)],
    );
    if (!res || !Array.isArray(res)) return { nextCursor: "0", cleanedCount: 0, processedCount: 0 };
    return {
      nextCursor: String(res[0] ?? "0"),
      cleanedCount: Number(res[1] ?? 0),
      processedCount: Number(res[2] ?? 0),
    };
  } catch (err) {
    console.error({ event: "redis_cleanup_abandoned_leases_failed", error: String(err) });
    return { nextCursor: "0", cleanedCount: 0, processedCount: 0 };
  }
}

export async function setCachedOriginRedis(
  origin: string,
  allowed: boolean,
  startTime?: number,
): Promise<boolean> {
  if (!redis) return false;
  try {
    const originKey = `swyra:origin:${origin}`;
    const invKey = `swyra:origin:inv:${origin}`;
    const globalInvKey = "swyra:inv:global";
    const verKey = `swyra:origin:ver:${origin}`;
    const leaseKey = `swyra:origin:lease:${origin}`;
    const leasesKey = "swyra:origin:leases";

    const res = await redis.eval(
      SET_ORIGIN_CACHE_LUA,
      [originKey, invKey, globalInvKey, verKey, leaseKey, leasesKey],
      [
        allowed ? "1" : "0",
        typeof startTime === "number" ? startTime : 0,
        ORIGIN_CACHE_TTL_SECONDS,
        origin,
      ],
    );

    return res === 1 || res === "1" || res === true;
  } catch (error) {
    console.error({ event: "redis_origin_cache_write_failed", origin, error: String(error) });
    return false;
  }
}

export async function invalidateCachedOriginRedis(
  origins?: string[],
  version?: number,
): Promise<void> {
  if (!redis) return;
  const marker = typeof version === "number" && version > 0 ? version : 0;
  if (origins && origins.length > 0) {
    await redis.eval(
      INVALIDATE_ORIGIN_CACHE_LUA,
      origins,
      [String(marker), "0"],
    );
    return;
  }

  // Global invalidation: write global tombstone marker and atomically delete active leases container.
  // The marker key uses a DIFFERENT prefix (swyra:inv:global) so it cannot be
  // matched and deleted by the swyra:origin:* scan below.
  await redis.eval(
    INVALIDATE_GLOBAL_ORIGIN_CACHE_LUA,
    ["swyra:inv:global", "swyra:origin:leases"],
    [String(marker), "0"],
  );

  // Hook for testing race conditions between the atomic Lua step and the background scan loop
  if (_globalInvalidationMidHook) {
    await _globalInvalidationMidHook();
  }

  let cursor: string | number = 0;
  do {
    const result: [string, string[]] = await redis.scan(cursor, {
      match: "swyra:origin:*",
      count: 100,
    });
    const [nextCursor, keys] = result;
    // Delete only cached origin decisions, version keys, and individual lease keys.
    // Preserve swyra:origin:inv:* so per-origin invalidation markers remain intact!
    const originKeys = keys.filter(
      (k) =>
        (k.startsWith("swyra:origin:") ||
          k.startsWith("swyra:origin:ver:") ||
          k.startsWith("swyra:origin:lease:")) &&
        !k.startsWith("swyra:origin:inv:") &&
        k !== "swyra:origin:leases"
    );
    if (originKeys.length > 0) await redis.del(...originKeys);
    cursor = nextCursor;
  } while (String(cursor) !== "0");
}
