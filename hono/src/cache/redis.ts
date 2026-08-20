import { Redis } from "@upstash/redis";
import { Ratelimit } from "@upstash/ratelimit";
import { config } from "../config";

/**
 * Upstash Redis — REST-based client, safe for Lambda's ephemeral execution
 * model (no persistent TCP connections to manage across cold starts).
 *
 * SCOPE OF THIS MODULE — read before adding a new use case:
 *   - Rate-limit counters and CORS origin-allow-list lookups ONLY.
 *   - Both are defense-in-depth, both tolerate staleness, both fail-open by
 *     design (see checkRateLimit / getCachedOriginRedis below).
 *
 * DO NOT put refresh-token family/revocation state behind this module's
 * fail-open pattern. That is security-critical correctness state, not a
 * performance cache — see db/token-families.ts, which is Mongo-authoritative
 * and only uses Redis as an optional accelerant that fails CLOSED (falls
 * through to a real Mongo check), never fails open to "not revoked".
 *
 * DEPLOYMENT NOTE: Redis is entirely optional. This project is designed to
 * be self-hosted by solo developers who may never configure Upstash. Every
 * consumer of this module MUST check `redisEnabled` and fall back to the
 * equivalent MongoDB-backed implementation in db/state.ts when false. The
 * system must be fully secure and fully functional with Redis absent —
 * Redis only removes load from Mongo and reduces latency, it is never a
 * hard dependency for anything security-relevant.
 */

export const redisEnabled = config.redis.enabled;

/**
 * @upstash/redis defaults to 5 retries with exponential backoff
 * (~50ms, 136ms, 369ms, 1s, 2.7s — over 4.3s worst case) before a call
 * throws. That default is built for durability-focused workloads, not for
 * a fail-open defense-in-depth cache sitting in the hot path of every
 * request. Retries are disabled here and a hard per-call timeout is set:
 * a slow/unreachable Redis must fail FAST so checkRateLimit()'s fail-open
 * path actually triggers quickly, not after several seconds of stalling —
 * a slow Redis instance would otherwise become a request-latency DoS vector
 * in its own right, independent of whether Redis is technically "up".
 */
const REDIS_CALL_TIMEOUT_MS = 400;

export const redis = redisEnabled
  ? new Redis({
      url: config.redis.url!,
      token: config.redis.token!,
      retry: false,
      signal: () => AbortSignal.timeout(REDIS_CALL_TIMEOUT_MS),
    })
  : null;

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
      /**
       * Keyed by TARGET (normalized email), not source IP. This is the
       * control that survives IP rotation / VPN / botnet distribution —
       * an attacker spreading a credential-stuffing run across thousands
       * of rotating IPs still hits this because every attempt targets the
       * same victim account. Apply alongside, not instead of, the
       * IP-keyed `signIn` limiter above; they catch different attack
       * shapes (one attacker/many targets vs many attackers/one target).
       */
      credentialStuffingTarget: new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(15, "300 s"),
        prefix: "swyra:rl:target",
      }),
    }
  : undefined;

export type RateLimiterName = keyof NonNullable<typeof rateLimiters>;

/**
 * Fail-open by design: rate limiting is defense-in-depth, not the sole
 * control. An Upstash outage must not become a self-inflicted denial of
 * service against your own login system. Every failure is logged loudly so
 * an outage is visible in monitoring, not silent. Callers should treat
 * `remaining: -1` as "Redis unavailable, request was allowed through" if
 * they want to distinguish this from a normal allow in logs/metrics.
 */
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

const ORIGIN_CACHE_TTL_SECONDS = 300;

/**
 * Origin allow-list cache. Failure behavior is "cache miss", never
 * "allowed" — a Redis error must fall through to the authoritative
 * MongoDB lookup in cors.ts's isOriginAllowed(), exactly like a genuine
 * cache miss. Never let a Redis error short-circuit into treating an
 * unverified origin as trusted.
 */
export async function getCachedOriginRedis(origin: string): Promise<boolean | null> {
  if (!redis) return null;
  try {
    const value = await redis.get<boolean>(`swyra:origin:${origin}`);
    return value ?? null;
  } catch (error) {
    console.error({ event: "redis_origin_cache_read_failed", origin, error: String(error) });
    return null;
  }
}

export async function setCachedOriginRedis(origin: string, allowed: boolean): Promise<void> {
  if (!redis) return;
  try {
    await redis.set(`swyra:origin:${origin}`, allowed, { ex: ORIGIN_CACHE_TTL_SECONDS });
  } catch (error) {
    console.error({ event: "redis_origin_cache_write_failed", origin, error: String(error) });
  }
}

export async function invalidateCachedOriginRedis(origins?: string[]): Promise<void> {
  if (!redis) return;
  try {
    if (origins && origins.length > 0) {
      await redis.del(...origins.map((o) => `swyra:origin:${o}`));
      return;
    }
    let cursor: string | number = 0;
    do {
      const result: [string, string[]] = await redis.scan(cursor, {
        match: "swyra:origin:*",
        count: 100,
      });
      const [nextCursor, keys] = result;
      if (keys.length > 0) await redis.del(...keys);
      cursor = nextCursor;
    } while (String(cursor) !== "0");
  } catch (error) {
    console.error({ event: "redis_origin_cache_invalidate_failed", error: String(error) });
  }
}

export async function getCachedTokenFamilyStatus(
  familyId: string
): Promise<"active" | "revoked" | null> {
  if (!redis) return null;
  try {
    const status = await redis.get<string>(`swyra:token_family:${familyId}`);
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
  if (!redis) return;
  try {
    await redis.set(`swyra:token_family:${familyId}`, status, { ex: ttlSeconds });
  } catch (err) {
    console.warn("[REDIS] Token family cache write failed:", err);
  }
}

export async function invalidateCachedTokenFamily(familyId: string): Promise<void> {
  if (!redis) return;
  try {
    await redis.set(`swyra:token_family:${familyId}`, "revoked", { ex: 86400 * 30 });
  } catch (err) {
    console.warn("[REDIS] Token family cache invalidation failed:", err);
  }
}