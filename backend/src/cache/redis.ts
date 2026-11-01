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

export const GET_ORIGIN_CACHE_LUA = `
-- LUA_GET_ORIGIN_CACHE
local originKey = KEYS[1]
local verKey = KEYS[2]
local invKey = KEYS[3]
local globalInvKey = KEYS[4]

local value = redis.call("get", originKey)
if not value then
    return nil
end

local ver = tonumber(redis.call("get", verKey)) or 0
local inv = tonumber(redis.call("get", invKey)) or 0
local globalInv = tonumber(redis.call("get", globalInvKey)) or 0

if globalInv > 0 and ver <= globalInv then
    return nil
end

if inv > 0 and ver <= inv then
    return nil
end

return value
`;

export const SET_ORIGIN_CACHE_LUA = `
-- LUA_SET_ORIGIN_CACHE
local originKey = KEYS[1]
local invKey = KEYS[2]
local globalInvKey = KEYS[3]
local verKey = KEYS[4]
local leaseKey = KEYS[5]
local leasesKey = KEYS[6]
local allowed = ARGV[1]
local checkVersion = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local origin = ARGV[4]

if checkVersion and checkVersion > 0 then
    if leaseKey then
        local activeLease = redis.call('get', leaseKey)
        if not activeLease or tonumber(activeLease) ~= checkVersion then
            return 0
        end
    end

    if leasesKey and origin then
        local activeGlobalLease = redis.call('hget', leasesKey, origin)
        if not activeGlobalLease or tonumber(activeGlobalLease) ~= checkVersion then
            return 0
        end
    end

    local currentVersion = redis.call('get', verKey)
    if currentVersion and tonumber(currentVersion) >= checkVersion then
        return 0
    end

    local invVersion = redis.call('get', invKey)
    if invVersion and tonumber(invVersion) >= checkVersion then
        return 0
    end

    local globalInvVersion = redis.call('get', globalInvKey)
    if globalInvVersion and tonumber(globalInvVersion) >= checkVersion then
        return 0
    end
end

redis.call('set', originKey, allowed, 'EX', ttl)
if checkVersion and checkVersion > 0 then
    redis.call('set', verKey, checkVersion, 'EX', ttl)
    if leaseKey then
        redis.call('del', leaseKey)
    end
    if leasesKey and origin then
        redis.call('hdel', leasesKey, origin)
    end
end
return 1
`;

export const INVALIDATE_ORIGIN_CACHE_LUA = `
-- LUA_INVALIDATE_ORIGIN_CACHE
local invalidationVersion = tonumber(ARGV[1]) or 0
local ttl = tonumber(ARGV[2]) or 0
for i = 1, #KEYS do
    local origin = KEYS[i]
    local invKey = "swyra:origin:inv:" .. origin
    local leaseKey = "swyra:origin:lease:" .. origin
    local currentInv = redis.call("get", invKey)
    local curNum = tonumber(currentInv)

    if not curNum or invalidationVersion > curNum then
        if ttl > 0 then
            redis.call("set", invKey, invalidationVersion, "EX", ttl)
        else
            redis.call("set", invKey, invalidationVersion)
        end
    elseif invalidationVersion == curNum and ttl > 0 then
        local currentTtl = redis.call("ttl", invKey)
        if currentTtl and currentTtl > 0 and currentTtl < ttl then
            redis.call("expire", invKey, ttl)
        end
    end
    redis.call("del", "swyra:origin:" .. origin)
    redis.call("del", "swyra:origin:ver:" .. origin)
    redis.call("del", leaseKey)
    redis.call("hdel", "swyra:origin:leases", origin)
end
return 1
`;

export const INVALIDATE_GLOBAL_ORIGIN_CACHE_LUA = `
-- LUA_INVALIDATE_GLOBAL_ORIGIN_CACHE
local globalInvKey = KEYS[1]
local leasesKey = KEYS[2]
local invalidationVersion = tonumber(ARGV[1]) or 0
local ttl = tonumber(ARGV[2]) or 0

local currentGlobal = redis.call("get", globalInvKey)
local curNum = tonumber(currentGlobal)
if not curNum or invalidationVersion > curNum then
    if ttl > 0 then
        redis.call("set", globalInvKey, invalidationVersion, "EX", ttl)
    else
        redis.call("set", globalInvKey, invalidationVersion)
    end
elseif invalidationVersion == curNum and ttl > 0 then
    local currentTtl = redis.call("ttl", globalInvKey)
    if currentTtl and currentTtl > 0 and currentTtl < ttl then
        redis.call("expire", globalInvKey, ttl)
    end
end

if leasesKey then
    redis.call("del", leasesKey)
end
return 1
`;

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
    await Promise.all([
      redis.set(leaseKey, version, { ex: ttlSeconds }),
      redis.hset(leasesKey, { [origin]: version }),
    ]);
    return true;
  } catch (err) {
    console.error({ event: "redis_origin_lease_set_failed", origin, error: String(err) });
    return false;
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