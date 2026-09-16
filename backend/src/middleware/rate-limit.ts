import { createMiddleware } from "hono/factory";
import { getTrustedClientIp } from "../utils/security";
import { rateLimiters, checkRateLimit, RateLimiterName } from "../cache/redis";
import { incrementRateLimit } from "../db/state";

export function createRateLimiter(options: {
  windowMs: number;
  limit: number;
  prefix?: string;
  limiterName?: RateLimiterName;
}) {
  const { windowMs, limit, prefix = "global", limiterName } = options;

  return createMiddleware(async (c, next) => {
    if (c.req.method === "OPTIONS") {
      return next();
    }

    const ip = getTrustedClientIp(c);
    const key = `${prefix}:${ip}`;
    const now = Date.now();

    // 1. Try Redis Upstash Ratelimit if available
    const limiter = limiterName && rateLimiters ? rateLimiters[limiterName] : null;

    if (limiter) {
      const redisResult = await checkRateLimit(limiter, ip);

      // remaining === -1 indicates Redis call failed (fail-open / degraded mode)
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
  limiterName: "adminProvision",
});

// Standard auth endpoint rate limiter (20 req/min/IP)
export const authRateLimit = createRateLimiter({
  windowMs: 60 * 1000,
  limit: 20,
  prefix: "auth",
  limiterName: "signIn",
});
