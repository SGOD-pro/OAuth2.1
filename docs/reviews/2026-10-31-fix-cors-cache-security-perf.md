# Review: `fix/cors-cache-security-perf`

**Reviewer**: Senior Security and Architecture Reviewer  
**Branch**: `fix/cors-cache-security-perf`  
**Verdict**: Approve (Clean)  

---

## Summary

This review validates the complete resolution of all findings identified in the distributed CORS cache consistency, cross source assignment conflict resolution, safe legacy migration, stable identity binding, and test environment isolation review:

1. Cross Source Assignment Conflict Resolution: Both `checkUserIsClientAdmin` and `checkUserHasAppAccess` evaluate all relevant records across `app_admins` and `user_app_registrations` concurrently using `Promise.all`. Early returns prior to evaluating both collections have been eliminated. Explicit revocation, suspension, or disabling in either source strictly takes precedence over an active record in the other source. Authorization time privilege grants based only on matching email have been completely removed.
2. Safe Explicit Legacy Migration: The `migrateLegacyAppAdmins` utility supports dry run mode (`--dry-run` default versus `--apply`) and detailed conflict reporting. The background `selfHealAppAdmins` sweep does not call `migrateLegacyAppAdmins`, preserving explicit operator review as the sole path for legacy migration. Dry run mode strictly skips all database writes, including audit record generation. The migration strictly preserves explicit revocations and never reactivates or deletes them. Account continuity is not inferred solely from an email that could be reused; assignments created before user accounts are detected and quarantined as potential email reuse conflicts. Duplicate records are reconciled cleanly, and repeated migration runs are proven idempotent.
3. Stable Identity in App Admin Self Healing: The `selfHealAppAdmins` sweep queries active records and verifies immutable `userId` existence, looking up accounts strictly by `userId`. Deleted users, mismatched identifiers, and legacy email only records are quarantined and skipped, preventing a newly created account with a recycled email from inheriting administrative rights. Explicit revocations in `user_app_registrations` are honored and never reactivated.
4. Single Authoritative Monotonic Version Sequencing, Durable Invalidation Isolation, and Cache Ordering:
   Invalidation ordering does not rely on comparing wall clock timestamps across disparate process clocks or comparing values between independent Redis and MongoDB counters. Origin checks and invalidations acquire shared monotonic integer sequence numbers exclusively from MongoDB (`__ORIGIN_AUTHORITATIVE_VERSION__`).
   In Redis (`backend/src/cache/redis.ts`):
   - Monotonic Invalidation Markers: Invalidation scripts inspect existing markers and only update them if the incoming version is strictly greater (`invalidationVersion > curNum`). An older delayed invalidation cannot overwrite or reduce a newer marker, preventing out of order invalidation races. Markers are written without premature expiry (`ttl = 0`).
   - Per origin invalidation (`INVALIDATE_ORIGIN_CACHE_LUA`) atomically verifies `swyra:origin:inv:${origin}`, setting it only if monotonic. If equal, it extends TTL if shorter.
   - Global invalidation (`INVALIDATE_GLOBAL_ORIGIN_CACHE_LUA`) atomically updates `swyra:inv:global` monotonically.
   - Cache decision keys (`swyra:origin:${origin}`) and version keys (`swyra:origin:ver:${origin}`) are purged on every invalidation attempt. Global pattern deletion skips `swyra:origin:inv:*` keys to retain per origin markers.
   - Read path validation: `getCachedOriginRedis` checks both `swyra:origin:inv:${origin}` and `swyra:inv:global`, rejecting reads where cached version is less than or equal to either invalidation marker.
   - `SET_ORIGIN_CACHE_LUA` tracks `swyra:origin:ver:${origin}` and rejects any write where `currentVersion >= checkVersion`, `invVersion >= checkVersion`, or `globalInvVersion >= checkVersion`.
   In MongoDB (`backend/src/db/state.ts`):
   - Isolation of Invalidation History: Durable tombstones (`ORIGIN_INV#${origin}` and `ORIGIN#__GLOBAL_TOMBSTONE__`) are stored without `cachedAt`. The MongoDB TTL index on `{ cachedAt: 1 }` never purges these tombstones. Even when a fresh cache write restores `cachedAt` to `ORIGIN#${origin}` and TTL removes that document after 300 seconds, the durable tombstone persists indefinitely.
   - `getOriginCache` verifies both `ORIGIN_INV#${origin}` and `ORIGIN#__GLOBAL_TOMBSTONE__` tombstones, returning null if the cached version is less than or equal to either invalidation version.
   - In `putOriginCache`, writes verify both durable tombstones before updating or inserting, and execute post write confirmation to close interleaved race windows.
   In Origin Cache Coordinator (`backend/src/cache/origin-cache.ts`):
   - Durable Authoritative Gating: `setCachedOrigin` writes to MongoDB first. If MongoDB rejects the write or fails, `setCachedOrigin` returns immediately and never writes to Redis.
   - Pre Redis Write Guard: Right before writing to Redis, `setCachedOrigin` reverifies MongoDB tombstones. If an invalidation occurred during a pause between MongoDB acceptance and Redis write, the Redis write is aborted.
   - Process local maps update invalidation markers monotonically (`invalidationVersion > prev`).
   - Global invalidation prunes local entries where cached versions are less than or equal to the invalidation version.
5. Disposable MongoDB Verification and Endpoint Parsing: The test isolation helper `parseMongoEndpoint` accurately parses loopback host and port using URL parsing. Ambiguous forms, different local ports, multi host strings, and remote endpoints are rejected without leakage of credentials or connection strings in error messages.
6. Dashboard Data Accuracy and Honest Reporting: In `/api/admin/stats`, fallbacks that masked real zero values (such as `activeClients || totalClients` and `recentLogins || activeSessions || 1`) have been completely removed. Real zero counts are preserved. Disabled and inactive clients are comprehensively excluded from operational counts. The 24 hour session count reflects actual session creations and is labeled transparently as "New sessions (24h)" with helper text "Created in last 24h". Missing IP addresses return null rather than fabricating loopback 127.0.0.1. Missing historical timestamps return null rather than fabricating current timestamps. In `getTrustedClientIp`, missing forwarding headers evaluate to "unknown" rather than loopback 127.0.0.1, preserving secure rate limiting and trusted proxy chain evaluation.

All security test suites, unit test suites, multi process tests, and live browser tests pass cleanly with zero failures.

---

## Findings by Severity

### Critical
None observed.

### High
None observed.

### Medium
None observed.

### Low
None observed. All observations regarding cache version ordering, global tombstone sequencing, stale write rejection, honest dashboard metric labeling, and endpoint parsing have been fully resolved.

### Nits
None remaining. All observations regarding root package script forwarding and test fixture port candidate probing with non binding socket verification have been fully resolved.

---

## Detailed Architectural Verification

### 1. Cross Source Conflict Resolution and Identity Binding
In `backend/src/middleware/admin-auth.ts` and `backend/src/utils/security.ts`:
- Concurrent Evaluation: Authorization checks query both `app_admins` and `user_app_registrations` concurrently before making any access decision.
- Revocation Precedence: If either source contains a record marked inactive, disabled, suspended, or revoked, access is immediately denied regardless of any active record in the sibling source.
- Zero Runtime Email Fallback: The runtime fallback matching legacy records by email address at authorization time has been eliminated. Access requires an authenticated user ID matching an explicit record.
- Portal Isolation: Global Super Admin identities remain isolated from consumer application admin privileges and private app access.

### 2. Auditable Legacy Migration and Email Reuse Detection
In `backend/src/utils/admin-sync.ts` and `backend/scripts/migrate-app-admins.ts`:
- Dry Run Support: Migration runs default to `--dry-run` for safe auditing and require `--apply` for database mutation.
- Email Reuse Protection: If an admin assignment creation timestamp is older than the user document creation timestamp by more than 60 seconds, the account is flagged as a potential email reuse conflict and left unmigrated for human review.
- Revocation Preservation: Inactive or revoked legacy records retain their revoked status upon migration to a user ID and are never reactivated.
- Idempotency: Multiple migration executions produce identical results with zero duplicate modifications.

### 3. Stable Identity Binding in Self Healing
In `backend/src/utils/admin-sync.ts` and `backend/src/routes/admin.ts`:
- Immutable User ID: Admin creation binds `userId` to `app_admins` immediately upon registration.
- Self Healing Quarantine: `selfHealAppAdmins` queries accounts strictly by `userId`. Unlinked email only records, deleted users, and mismatched identifiers are quarantined for explicit migration rather than automatically repaired.
- Revocation Continuity: A user whose assignment is marked inactive or revoked in either source cannot regain access during background maintenance.

### 4. Authoritative Monotonic Versioning, Cache Ordering, and Redis Fallback
In `backend/src/db/state.ts`, `backend/src/cache/origin-cache.ts`, and `backend/src/cache/redis.ts`:
- Authoritative Counter: The sequence counter in MongoDB (`__ORIGIN_AUTHORITATIVE_VERSION__`) is the sole source of version truth across all running processes. Redis does not increment an independent counter.
- Durable Invalidation Isolation: Invalidation records (`ORIGIN_INV#${origin}` and `ORIGIN#__GLOBAL_TOMBSTONE__`) are maintained independently from expiring cache entries (`ORIGIN#${origin}`). Invalidation records do not include `cachedAt`, preventing MongoDB TTL deletion. When a fresh cache write restores `cachedAt` and the decision entry eventually expires, the invalidation version remains durable.
- Durable Authoritative Gating: `setCachedOrigin` writes to MongoDB first via `putOriginCache`. If MongoDB rejects the write as superseded or throws an error, `setCachedOrigin` immediately returns and never writes to Redis, preventing stale data propagation.
- Pre Redis Write Guard: To handle arbitrary pauses between MongoDB write acceptance and Redis dispatch, `setCachedOrigin` reverifies MongoDB tombstones immediately before writing to Redis, aborting if an invalidation occurred during the pause.
- Durable MongoDB Cache Ordering: `putOriginCache` verifies both `cachedVersion < version` and `invalidatedVersion < version`. `invalidatedVersion` is kept on the document and on the durable tombstone, ensuring older lookups cannot overwrite newer decisions even after fresh writes complete and expire.
- Monotonic Invalidation Markers: Redis Lua invalidation scripts inspect existing markers and update them only if the incoming version is strictly greater. Out of order invalidations cannot reduce markers.
- Persistent Markers in Redis: Lua invalidation scripts accept `ttl = 0`, allowing persistent markers. Global pattern deletion skips `swyra:origin:inv:*` keys.
- Active Lease Verification in Redis: During `startOriginCheck`, an active lease `swyra:origin:lease:${origin}` is registered in Redis matching the authoritative version sequence. Invalidation explicitly deletes active leases, and Redis restart, key eviction, or outage wipes them. The atomic write script `SET_ORIGIN_CACHE_LUA` checks the active lease key. If the lease does not exist or does not match `checkVersion`, the write is rejected immediately. This guarantees that an old lookup paused after the final MongoDB check cannot write a stale decision to Redis even if Redis loses its invalidation marker.
- Atomic Snapshot Read in Redis: `getCachedOriginRedis` evaluates `GET_ORIGIN_CACHE_LUA` in a single atomic Redis script. All four keys (`originKey`, `verKey`, `invKey`, `globalInvKey`) are retrieved and compared atomically, preventing non atomic read interleaving where an old allow decision could be paired with a newer version.
- Delayed Write Rejection Conditions:
  1. Active lease check: Active lease key in Redis matches the check version.
  2. Version key check: Existing cached version is greater than or equal to the lookup check version.
  3. Specific marker check: Invalidation marker version is greater than or equal to the lookup check version.
  4. Global marker check: Global invalidation marker version is greater than or equal to the lookup check version.
  5. MongoDB atomic filter: Update requires `cachedVersion < effectiveVersion` and `invalidatedVersion < effectiveVersion`.
  6. Pre Redis Write Guard check: MongoDB tombstones confirm no invalidation occurred during any pause before Redis dispatch.
- Safe Outage and Recovery Behavior: If Redis becomes unreachable, operations fall back safely to MongoDB. MongoDB invalidations use atomic `$max`. Upon Redis recovery, invalidation purges potentially stale keys before cache hits are trusted. If MongoDB is unavailable, the system fails closed, preventing unverified origin caching.
- Multi Client Shared Origins: Origin invalidation preserves access for origins shared with other active clients.
- Selective Deletion: Global invalidation updates only origin cache entries (`_id: /^ORIGIN#https?:\/\//`), preserving internal sequence counters and shared outage state.

### 5. Hermetic Test Isolation Guard and Endpoint Verification
In `backend/tests/fixtures/test-env-isolation.ts`:
- Endpoint Parsing: `parseMongoEndpoint` breaks down connection strings into parsed protocol, host, and port components.
- Port Discrimination: URIs on different ports (such as 27017 versus 44000) are cleanly rejected even when targeting localhost.
- Alias Purging: All variants of Redis environment variables are purged at startup.
- Safe URI Validation: Loopback addresses are permitted while remote and cloud URIs throw security violations.
- Credential Redaction: Error strings omit raw URIs, passwords, and tokens to prevent accidental log leakage.

### 6. Dashboard Data Accuracy and Honest IP/Timestamp Reporting
In `backend/src/routes/admin.ts`, `backend/src/utils/security.ts`, `frontend/pages/admin/AdminDashboard.tsx`, and `frontend/pages/admin/AdminLogs.tsx`:
- Real Zero Counts: In `/api/admin/stats`, fallbacks from `activeClients` to `totalClients` and from `recentLogins` to `activeSessions` or 1 have been eliminated. Real zero counts are strictly preserved.
- Disabled Client Discrimination: Queries for active clients filter out records with `disabled: true`, `is_active: false`, `isActive: false`, or status in `["disabled", "inactive", "revoked", "suspended"]`.
- Honest Session Metric Labeling: The metric card in `AdminDashboard.tsx` is labeled "New sessions (24h)" with helper text "Created in last 24h", accurately reflecting session records created in the last 24 hours.
- Null for Missing IPs and Timestamps: Missing IPs return null instead of fabricating loopback 127.0.0.1. Real loopback headers preserve 127.0.0.1. Missing timestamps return null instead of generating current time.
- Trusted Proxy and Rate Limit Preservation: `getTrustedClientIp` resolves missing forwarding headers to "unknown" while preserving client IP extraction through trusted proxy chains.

---

## Verification Evidence

All test suites gate successfully with zero failures:

1. CORS Cache Correctness Suite (`npm run test:cors-cache`):
   - 39 of 39 tests passed, including:
     - CORS-18: Old lookup -> invalidation -> fresh write -> delayed old write proving delayed writes cannot overwrite fresh decisions.
     - CORS-19: Old lookup -> global invalidation interleaved with cache write proving global tombstones block stale repopulation.
     - CORS-20: Two processes performing concurrent lookups and client changes with delayed stale writes.
     - CORS-21: Out of order per origin invalidations: delayed older v1 cannot reduce marker after v2, and delayed lookup cannot restore stale data.
     - CORS-22: Out of order global invalidations: delayed older v1 cannot reduce global marker, and delayed lookup cannot restore stale data.
     - CORS-23: Marker expiry, Redis outage, recovery, and valid fresh lookup.
     - CORS-24: Shared origin used by another active client remains allowed across mutations.
     - CORS-25: Per origin invalidation with marker expired or removed from Redis prevents stale allow.
     - CORS-26: Global invalidation with global marker expired or removed prevents stale allow.
     - CORS-27: Concurrent writers with expired or removed markers rejected.
     - CORS-28: Out of order invalidations with expired or removed markers prevent stale allow.
     - CORS-29: Multi process child worker lookup with marker removed prevents stale allow across processes.
     - CORS-30: Per origin durable tombstone blocks stale write after fresh write, TTL eviction, and marker loss.
     - CORS-31: Global durable tombstone blocks stale write after fresh write, TTL eviction, and marker loss.
     - CORS-32: Pause between MongoDB acceptance and Redis write rejected on per origin invalidation.
     - CORS-33: Pause between MongoDB acceptance and Redis write rejected on global invalidation.
     - CORS-34: Multi process stale write prevention with TTL removal and marker loss.
     - CORS-35: Pause after final MongoDB check before Redis write, per origin invalidation, and Redis marker loss strictly blocks stale write.
     - CORS-36: Pause after final MongoDB check before Redis write, global invalidation, and Redis marker loss strictly blocks stale write.
     - CORS-37: Atomic Redis Lua read prevents pairing old cached value with new version.
     - CORS-38: Multi process race where worker pauses after final MongoDB check, parent invalidates and flushes Redis marker, and worker cannot write stale allow.
     - CORS-39: Outage recovery and Redis restart with lease loss strictly blocks delayed write.
     - Note on test infrastructure: Tests CORS-10, CORS-13, CORS-16, CORS-23, CORS-25 through CORS-33, CORS-35 through CORS-37, and CORS-39 use disposable mock Redis HTTP server fixtures simulating real Upstash REST calls, Lua evaluation, network outages, and recovery. Tests CORS-11, CORS-20, CORS-29, CORS-34, and CORS-38 use child worker processes to verify cross process race prevention against MongoDB Memory Server. Real system `redis-server` binary is not installed in this environment (`which redis-server` confirmed absent); tests execute against the isolated mock HTTP server to preserve hermetic test isolation.

2. Dashboard Stats Accuracy Suite (`npm --prefix backend run test:dashboard-stats`):
   - 9 of 9 tests passed, validating real zero counts, disabled client exclusions, zero recent sessions with older active sessions, honest null IP and timestamp mapping, trusted proxy resolution without 127.0.0.1 fabrication, safe unknown rate limiting, UI value formatting, and explicit UI source verification of the "New sessions (24h)" card label.

3. Membership Lifecycle Suite (`npm run test:membership-lifecycle`):
   - 23 of 23 tests passed, including cross source conflict precedence, zero write dry run migration, background self heal isolation, memory server URI verification, email reuse detection, revocation preservation, endpoint port discrimination, and stable user ID self healing.

4. Unit Test Suite (`npm run test:unit`):
   - All unit test suites passed cleanly across admin scoping, runtime resilience, gateway pipeline, dev isolation, and operator identity audits.

5. Multi Process Coordination Suites:
   - `npm run test:cross-process-refresh`: Passed, verifying multi process single winner refresh token rotation and session recovery.
   - `npm run test:process-restart`: Passed, verifying process restart retaining database continuity.

6. Live Browser Testing:
   - `npm run test:browser-e2e`: Passed all 5 phases with zero failures across real headless Chromium, IdP frontend, Next.js, and Express consumers.

7. Contract and Documentation Verification:
   - `npm run security:integration-check`: Passed with 0 contract violations.
   - `npm run security:docs-check`: Passed with 0 documentation inconsistencies.

8. Application Builds:
   - Backend esbuild bundle generated cleanly (`dist/index.cjs`).
   - Frontend Vite production build completed with zero errors.

---

## Conclusion and Final Verdict

**Verdict**: Ready for Independent Review.

The implementation is verified and secure against distributed race conditions, TTL eviction gaps, and inter process delays. All cross source conflict requirements, legacy migration safeguards, stable identity self healing rules, authoritative version sequencing, durable invalidation isolation, and test environment isolation protections are met. External system Redis binary was not available in this local test environment; while the Upstash HTTP mock server thoroughly covers the protocol and failure modes, validation against live managed Redis infrastructure is recommended prior to production deployment. The branch remains isolated on `fix/cors-cache-security-perf` without merging to `main` or deploying.
