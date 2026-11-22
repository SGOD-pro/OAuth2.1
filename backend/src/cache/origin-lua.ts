/**
 * Lua scripts for Redis CORS origin allow-list caching and lease coordination.
 * Sourced atomically in Redis to prevent invalidation races and cache stampedes.
 */

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
    if not leaseKey or not leasesKey or not origin then
        return 0
    end

    local activeLease = redis.call('get', leaseKey)
    if not activeLease or tonumber(activeLease) ~= checkVersion then
        return 0
    end

    local activeGlobalLease = redis.call('hget', leasesKey, origin)
    if not activeGlobalLease or tonumber(activeGlobalLease) ~= checkVersion then
        return 0
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

export const SET_ORIGIN_LEASE_LUA = `
-- LUA_SET_ORIGIN_LEASE
local leaseKey = KEYS[1]
local leasesKey = KEYS[2]
local origin = ARGV[1]
local version = ARGV[2]
local ttlSeconds = tonumber(ARGV[3]) or 60
local containerTtl = tonumber(ARGV[4]) or 3600

redis.call('set', leaseKey, version, 'EX', ttlSeconds)
redis.call('hset', leasesKey, origin, version)
local curTtl = redis.call('ttl', leasesKey)
if not curTtl or curTtl < 0 or curTtl < ttlSeconds then
    redis.call('expire', leasesKey, containerTtl)
end
return 1
`;

export const CLEANUP_ABANDONED_LEASES_LUA = `
-- LUA_CLEANUP_ABANDONED_LEASES
local leasesKey = KEYS[1]
local cursorKey = KEYS[2]
local leftoversKey = KEYS[3]
local reqCursor = ARGV[1]
local countHint = tonumber(ARGV[2]) or 50
local maxEntries = tonumber(ARGV[3]) or countHint

-- If cursor is "auto" or empty/nil, retrieve the shared cursor from Redis
local cursor = "0"
local useSharedCursor = false
if not reqCursor or reqCursor == "" or reqCursor == "auto" then
    useSharedCursor = true
    if cursorKey then
        local storedCursor = redis.call('get', cursorKey)
        if storedCursor then
            cursor = storedCursor
        end
    end
else
    cursor = reqCursor
end

local cleaned = 0
local processed = 0

local function checkAndCleanEntry(origin, version)
    local leaseKey = "swyra:origin:lease:" .. origin
    local activeVal = redis.call('get', leaseKey)
    local activeVer = tonumber(activeVal)

    -- If individual lease is expired/missing or belongs to another version:
    if not activeVal or activeVer ~= version then
        -- Verify that the leases container still holds this exact version (prevent race with concurrent update)
        local curGlobalVer = tonumber(redis.call('hget', leasesKey, origin))
        if curGlobalVer == version then
            redis.call('hdel', leasesKey, origin)
            cleaned = cleaned + 1
        end
    end
end

-- 1. If leftovers exist from an oversized batch where HSCAN returned more entries than maxEntries, drain them first
if leftoversKey then
    local leftoversLen = redis.call('llen', leftoversKey)
    while leftoversLen > 0 and processed < maxEntries do
        local item = redis.call('lpop', leftoversKey)
        leftoversLen = leftoversLen - 1
        if item then
            local sep = string.find(item, "\\t")
            if sep then
                local origin = string.sub(item, 1, sep - 1)
                local version = tonumber(string.sub(item, sep + 1))
                processed = processed + 1
                checkAndCleanEntry(origin, version)
            end
        end
    end
end

-- If quota was fulfilled purely from leftovers, return without issuing a new HSCAN yet
if processed >= maxEntries then
    return { cursor, cleaned, processed }
end

-- 2. Leftovers drained; scan the next batch using HSCAN
local scanResult = redis.call('hscan', leasesKey, cursor, 'COUNT', countHint)
local nextCursor = scanResult[1]
local entries = scanResult[2]

for i = 1, #entries, 2 do
    local origin = entries[i]
    local version = tonumber(entries[i + 1])

    if processed < maxEntries then
        processed = processed + 1
        checkAndCleanEntry(origin, version)
    else
        -- Quota reached: buffer remaining entries from this HSCAN batch into leftoversKey so they are never lost
        if leftoversKey then
            redis.call('rpush', leftoversKey, origin .. "\\t" .. tostring(version))
        end
    end
end

if leftoversKey then
    redis.call('expire', leftoversKey, 86400)
end

-- Update the shared cursor key so next call continues progress across processes
if useSharedCursor and cursorKey then
    if nextCursor == "0" then
        -- Full cycle completed; wrap around to 0
        redis.call('set', cursorKey, "0", 'EX', 86400)
    else
        redis.call('set', cursorKey, nextCursor, 'EX', 86400)
    end
end

return { nextCursor, cleaned, processed }
`;
