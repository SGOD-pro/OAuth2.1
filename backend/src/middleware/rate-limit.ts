import { createMiddleware } from "hono/factory";
import { getTrustedClientIp } from "../utils/security";
import { rateLimiters, checkRateLimit, RateLimiterName } from "../cache/redis";
import { incrementRateLimit } from "../db/state";

export type LimiterSensitivity = "admin" | "auth" | "public";

export interface EmergencyRateLimitEntry {
  count: number;
  resetAt: number;
}

/**
 * Bounded In-Process Emergency Rate Limiter.
 *
 * Activated when distributed backing stores (Redis, MongoDB) are unavailable.
 *
 * Invariants:
 * - Bounded memory: fixed max capacity (default 10,000 keys) prevents memory exhaustion.
 * - TTL Cleanup: automatically purges expired entries when at capacity.
 * - LRU/FIFO Eviction: if still at capacity after expired pruning, evicts oldest entry.
 * - Key Sanitization: keyed by trusted IP / target hash only, never logging or storing secrets.
 */
export class BoundedEmergencyLimiter {
  private store = new Map<string, EmergencyRateLimitEntry>();
  private readonly maxEntries: number;

  constructor(maxEntries = 10000) {
    this.maxEntries = maxEntries;
  }

  public increment(
    key: string,
    now: number,
    windowMs: number,
    limit: number
  ): { allowed: boolean; count: number; resetAt: number } {
    const existing = this.store.get(key);

    if (existing && now < existing.resetAt) {
      existing.count += 1;
      return {
        allowed: existing.count <= limit,
        count: existing.count,
        resetAt: existing.resetAt,
      };
    }

    // New or expired entry
    if (this.store.size >= this.maxEntries) {
      this.prune(now);
      if (this.store.size >= this.maxEntries) {
        // Evict oldest insertion (FIFO/LRU)
        const oldestKey = this.store.keys().next().value;
        if (oldestKey) this.store.delete(oldestKey);
      }
    }

    const resetAt = now + windowMs;
    const entry: EmergencyRateLimitEntry = { count: 1, resetAt };
    this.store.set(key, entry);

    return {
      allowed: 1 <= limit,
      count: 1,
      resetAt,
    };
  }

  public prune(now: number): void {
    for (const [k, v] of this.store.entries()) {
      if (now >= v.resetAt) {
        this.store.delete(k);
      }
    }
  }

  public clear(): void {
    this.store.clear();
  }

  public size(): number {
    return this.store.size;
  }
}

export const emergencyRateLimiter = new BoundedEmergencyLimiter(10000);

export function createRateLimiter(options: {
  windowMs: number;
  limit: number;
  prefix?: string;
  limiterName?: RateLimiterName;
  sensitivity?: LimiterSensitivity;
}) {
  const { windowMs, limit, prefix = "global", limiterName, sensitivity = "public" } = options;

  return createMiddleware(async (c, next) => {
    if (c.req.method === "OPTIONS") {
      return next();
    }

    const ip = getTrustedClientIp(c);
    const key = `${prefix}:${ip}`;
    const now = Date.now();

    // 1. Primary: Redis Upstash Ratelimit if available
    const limiter = limiterName && rateLimiters ? rateLimiters[limiterName] : null;

    if (limiter) {
      const redisResult = await checkRateLimit(limiter, ip);

      // remaining !== -1 indicates successful Redis execution
      if (redisResult.remaining !== -1) {
        c.header("X-RateLimit-Limit", String(limit));
        c.header("X-RateLimit-Remaining", String(Math.max(0, redisResult.remaining)));

        if (!redisResult.allowed) {
          c.header("Retry-After", String(Math.ceil(windowMs / 1000)));
          return c.json(
            {
              error: "too_many_requests",
              message: "Too many requests. Please try again later.",
            },
            429
          );
        }

        return next();
      }
    }

    // 2. Secondary: MongoDB Sliding-Window TTL Collection
    try {
      const entry = await incrementRateLimit(key, now, windowMs);
      c.header("X-RateLimit-Limit", String(limit));
      c.header("X-RateLimit-Remaining", String(Math.max(0, limit - entry.count)));
      c.header("X-RateLimit-Reset", String(Math.ceil(entry.resetAt / 1000)));

      if (entry.count > limit) {
        c.header("Retry-After", String(Math.ceil(windowMs / 1000)));
        return c.json(
          {
            error: "too_many_requests",
            message: "Rate limit exceeded (fallback mode). Please try again later.",
          },
          429
        );
      }

      return next();
    } catch (mongoErr) {
      console.warn(`[RATE_LIMIT] Mongo fallback store error for ${key} (${sensitivity}):`, mongoErr);
    }

    // 3. Tertiary: Classified Security Handling on Dual Store Failure
    // NEVER silently become unlimited!
    if (sensitivity === "admin") {
      // Administrative operations strictly fail closed when all rate limit stores fail
      console.error(`[RATE_LIMIT_CRITICAL] Administrative rate limiting store failed. Denying request on ${key}.`);
      c.header("Retry-After", String(Math.ceil(windowMs / 1000)));
      return c.json(
        {
          error: "too_many_requests",
          message: "Rate limiting unavailable for administrative operations. Request denied for security.",
        },
        429
      );
    }

    // Authentication and Public endpoints engage bounded in-process emergency limiter
    const emergResult = emergencyRateLimiter.increment(key, now, windowMs, limit);
    c.header("X-RateLimit-Limit", String(limit));
    c.header("X-RateLimit-Remaining", String(Math.max(0, limit - emergResult.count)));
    c.header("X-RateLimit-Reset", String(Math.ceil(emergResult.resetAt / 1000)));

    if (!emergResult.allowed) {
      c.header("Retry-After", String(Math.ceil(windowMs / 1000)));
      return c.json(
        {
          error: "too_many_requests",
          message: sensitivity === "auth"
            ? "Too many authentication requests (emergency rate limit exceeded). Please try again later."
            : "Too many requests. Please try again later.",
        },
        429
      );
    }

    return next();
  });
}

// Low-threshold rate limiter for admin user provisioning (5 req/min/IP)
// Strictly fails closed on backing store failure
export const adminProvisionRateLimit = createRateLimiter({
  windowMs: 60 * 1000,
  limit: 5,
  prefix: "admin_provision",
  limiterName: "adminProvision",
  sensitivity: "admin",
});

// Standard auth endpoint rate limiter (20 req/min/IP)
// Backed by emergency in-process limiter on dual store failure
export const authRateLimit = createRateLimiter({
  windowMs: 60 * 1000,
  limit: 20,
  prefix: "auth",
  limiterName: "signIn",
  sensitivity: "auth",
});
