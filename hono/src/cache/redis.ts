import { Redis } from "@upstash/redis";
import { config } from "../config";

let redisClient: Redis | null = null;
let redisDisabled = false;

export function getRedisClient(): Redis | null {
  if (redisDisabled) return null;
  if (redisClient) return redisClient;

  const url = (config as any).redis?.url || process.env.UPSTASH_REDIS_REST_URL || process.env.REDIS_URL;
  const token = (config as any).redis?.token || process.env.UPSTASH_REDIS_REST_TOKEN || process.env.REDIS_TOKEN;

  if (url && token) {
    try {
      redisClient = new Redis({ url, token });
      return redisClient;
    } catch (err) {
      console.warn("[REDIS] Failed to initialize Redis client. Falling back to MongoDB/Memory:", err);
      return null;
    }
  }

  return null;
}

/**
 * Temporary kill switch for Redis to simulate outages during security tests
 */
export function setRedisDisabledForTesting(disabled: boolean) {
  redisDisabled = disabled;
}

/**
 * Rate limiting check with Redis.
 * FAIL-OPEN / DEGRADED MODE: If Redis is unavailable or fails, returns null so the caller
 * falls back to MongoDB TTL or in-memory tracking without blocking legitimate users.
 */
export async function checkRedisRateLimit(
  key: string,
  windowMs: number,
  limit: number
): Promise<{ allowed: boolean; count: number; resetAt: number } | null> {
  const client = getRedisClient();
  if (!client) return null;

  try {
    const now = Date.now();
    const windowSec = Math.ceil(windowMs / 1000);
    const redisKey = `rate_limit:${key}`;

    const count = await client.incr(redisKey);
    if (count === 1) {
      await client.expire(redisKey, windowSec);
    }

    return {
      allowed: count <= limit,
      count,
      resetAt: now + windowMs,
    };
  } catch (err) {
    // Fail-open: log warning and return null to trigger Mongo/memory fallback
    console.warn("[REDIS] Rate limit check failed. Degrading to Mongo/Memory fallback:", err);
    return null;
  }
}

/**
 * Token Family Cache Operations (FAIL-SECURE / AUTHORITATIVE MONGO)
 * Mongo is always the authoritative source of truth. Redis is used as a fast read-through cache.
 */
export async function getCachedTokenFamilyStatus(
  familyId: string
): Promise<"active" | "revoked" | null> {
  const client = getRedisClient();
  if (!client) return null;

  try {
    const status = await client.get<string>(`token_family:${familyId}`);
    if (status === "active" || status === "revoked") {
      return status;
    }
    return null;
  } catch (err) {
    console.warn("[REDIS] Token family cache read failed. Falling back to Authoritative Mongo:", err);
    return null;
  }
}

export async function setCachedTokenFamilyStatus(
  familyId: string,
  status: "active" | "revoked",
  ttlSeconds = 86400 * 30
): Promise<void> {
  const client = getRedisClient();
  if (!client) return;

  try {
    await client.set(`token_family:${familyId}`, status, { ex: ttlSeconds });
  } catch (err) {
    console.warn("[REDIS] Token family cache write failed:", err);
  }
}

export async function invalidateCachedTokenFamily(familyId: string): Promise<void> {
  const client = getRedisClient();
  if (!client) return;

  try {
    await client.set(`token_family:${familyId}`, "revoked", { ex: 86400 * 30 });
  } catch (err) {
    console.warn("[REDIS] Token family cache invalidation failed:", err);
  }
}