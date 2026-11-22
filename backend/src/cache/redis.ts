import { Redis } from "@upstash/redis";
import { Ratelimit } from "@upstash/ratelimit";
import { config } from "../config";

export const redisEnabled = config.redis.enabled;

const REDIS_CALL_TIMEOUT_MS = 2000;

export let redis = redisEnabled
  ? new Redis({
      url: config.redis.url!,
      token: config.redis.token!,
      retry: false,
      signal: () => AbortSignal.timeout(REDIS_CALL_TIMEOUT_MS),
    })
  : null;

export function setRedisClientForTesting(client: Redis | null): void {
  redis = client;
}

if (!redisEnabled && config.env === "production") {
  console.warn(
    "[WARN] UPSTASH_REDIS_REST_URL/TOKEN not set in production. " +
      "Rate limiting and CORS origin cache will fall back to MongoDB. " +
      "This is fully secure but slower under load — configure Upstash " +
      "when you outgrow single-instance MongoDB round-trip latency, or " +
      "leave it unset if you're self-hosting solo and don't need it yet.",
  );
}

export const rateLimiters = redis
  ? {
      signIn: new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(20, "60 s"),
        prefix: "swyra:rl:signin",
      }),
      twoFactor: new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(10, "60 s"),
        prefix: "swyra:rl:2fa",
      }),
      signUp: new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(5, "60 s"),
        prefix: "swyra:rl:signup",
      }),
      passwordReset: new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(5, "60 s"),
        prefix: "swyra:rl:pwreset",
      }),
      adminProvision: new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(5, "60 s"),
        prefix: "swyra:rl:adminprovision",
      }),
      corsLookup: new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(30, "60 s"),
        prefix: "swyra:rl:corslookup",
      }),
      credentialStuffingTarget: new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(15, "300 s"),
        prefix: "swyra:rl:target",
      }),
    }
  : undefined;

export type RateLimiterName = keyof NonNullable<typeof rateLimiters>;

export async function checkRateLimit(
  limiter: Ratelimit,
  key: string,
): Promise<{ allowed: boolean; remaining: number }> {
  try {
    const result = await limiter.limit(key);
    return { allowed: result.success, remaining: result.remaining };
  } catch (error) {
    console.error({ event: "redis_ratelimit_failed", key, error: String(error) });
    return { allowed: true, remaining: -1 };
  }
}

// Re-export Lua scripts and Redis origin cache methods for seamless compatibility
export {
  GET_ORIGIN_CACHE_LUA,
  SET_ORIGIN_CACHE_LUA,
  INVALIDATE_ORIGIN_CACHE_LUA,
  INVALIDATE_GLOBAL_ORIGIN_CACHE_LUA,
  SET_ORIGIN_LEASE_LUA,
  CLEANUP_ABANDONED_LEASES_LUA,
} from "./origin-lua";

export {
  getCachedOriginRedis,
  setOriginLeaseRedis,
  cleanupAbandonedOriginLeasesRedis,
  setCachedOriginRedis,
  invalidateCachedOriginRedis,
  setGlobalInvalidationMidHookForTesting,
} from "./redis-origin";
