import { createMiddleware } from "hono/factory";
import { getTrustedClientIp } from "../utils/security";
import { checkRedisRateLimit } from "../cache/redis";
import { incrementRateLimit } from "../db/state";

export function createRateLimiter(options: {
  windowMs: number;
  limit: number;
  prefix?: string;
}) {
  const { windowMs, limit, prefix = "global" } = options;

  return createMiddleware(async (c, next) => {
    const ip = getTrustedClientIp(c);
    const key = `${prefix}:${ip}`;
    const now = Date.now();

    // 1. Try Redis rate limiter (Fail-Open / Degraded Mode)
    const redisResult = await checkRedisRateLimit(key, windowMs, limit);

    if (redisResult) {
      c.header("X-RateLimit-Limit", String(limit));
      c.header("X-RateLimit-Remaining", String(Math.max(0, limit - redisResult.count)));
      c.header("X-RateLimit-Reset", String(Math.ceil(redisResult.resetAt / 1000)));

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

    // 2. Fallback to MongoDB TTL Collection / In-Memory (Degraded Mode)
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
    } catch (err) {
      // Degraded Fail-Open: log warning and continue so user is not blocked
      console.warn("[RATE_LIMIT] Fallback rate limit error (allowing request):", err);
    }

    return next();
  });
}

// Low-threshold rate limiter for admin user provisioning (B6: 5 req/min/IP)
export const adminProvisionRateLimit = createRateLimiter({
  windowMs: 60 * 1000,
  limit: 5,
  prefix: "admin_provision",
});

// Standard auth endpoint rate limiter (20 req/min/IP)
export const authRateLimit = createRateLimiter({
  windowMs: 60 * 1000,
  limit: 20,
  prefix: "auth",
});
