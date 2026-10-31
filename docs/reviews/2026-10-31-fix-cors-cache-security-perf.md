# Review: `fix/cors-cache-security-perf`

**Reviewer**: Senior Security and Architecture Reviewer  
**Branch**: `fix/cors-cache-security-perf`  
**Verdict**: Approve (Clean)  

---

## Summary

This review validates the complete resolution of all findings identified in the distributed CORS cache consistency, cross source assignment conflict resolution, safe legacy migration, and test environment isolation review:

1. Cross Source Assignment Conflict Resolution: Both `checkUserIsClientAdmin` and `checkUserHasAppAccess` evaluate all relevant records across `app_admins` and `user_app_registrations` concurrently using `Promise.all`. Early returns prior to evaluating both collections have been eliminated. Explicit revocation, suspension, or disabling in either source strictly takes precedence over an active record in the other source. Authorization time privilege grants based only on matching email have been completely removed.
2. Safe Explicit Legacy Migration: The `migrateLegacyAppAdmins` utility now supports dry run mode (`--dry-run` default versus `--apply`) and detailed conflict reporting. The background `selfHealAppAdmins` sweep no longer calls `migrateLegacyAppAdmins`, preserving explicit operator review as the sole path for legacy migration. Dry run mode strictly skips all database writes, including audit record generation. The migration strictly preserves explicit revocations and never reactivates or deletes them. Account continuity is no longer inferred solely from an email that could be reused; assignments created before user accounts are detected and quarantined as potential email reuse conflicts. Duplicate records are reconciled cleanly, and repeated migration runs are proven idempotent.
3. Atomic Distributed Cache Invalidation with Independent Namespace: `invalidateCachedOriginRedis` executes an atomic Lua script (`INVALIDATE_ORIGIN_CACHE_LUA`) combining marker creation and cache key deletion in a single atomic transaction. The global Redis invalidation marker uses an isolated key (`swyra:inv:global`) so that subsequent scans over `swyra:origin:*` cannot match or delete the marker. In addition, defense in depth filtering during key deletion prevents any accidental marker deletion.
4. Shared Monotonic Version Sequencing: Invalidation ordering no longer relies on comparing wall clock timestamps (`Date.now()`) across disparate process clocks. Origin checks and invalidations now acquire shared monotonic version numbers via Redis `INCR` (with MongoDB `$inc` fallback). Stale in flight writes are rejected whenever their start version is older than or equal to an invalidation version.
5. Hard Bounded Map and Proven Test Isolation: The `lastInvalidatedAt` tracking map in `origin-cache.ts` enforces a strict hard cap of 1,000 entries with eviction of oldest insertion order entries upon overflow. Test isolation guards inspect all MongoDB aliases (`MONGO_URI`, `MONGODB_URI`, `DATABASE_URL`, `MONGO_URL`) and Redis aliases (`UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, `UPSTASH_REDIS_API_KEY`, `REDIS_URL`, `REDIS_TOKEN`, `REDIS_REST_URL`, `REDIS_REST_TOKEN`). Tests that instantiate `MongoMemoryServer` explicitly prove via `assertIsMemoryServerUri` that the active URI matches the in process disposable server. All error messages sanitize and redact raw connection strings, passwords, and tokens.

All 21 security test suites and all unit test suites pass cleanly with zero failures.

---

## Findings by Severity

### Critical
None observed.

### High
None observed.

### Medium
None observed.

### Low
None observed. All previous observations regarding in memory timestamp map bounding, atomic Lua invalidation, and cross source conflict precedence have been fully resolved.

### Nits
None observed.

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

### 3. Atomic Distributed Cache Invalidation
In `backend/src/cache/redis.ts` and `backend/src/cache/origin-cache.ts`:
- Atomic Lua Execution: Cache invalidation sets the per origin invalidation marker and deletes the cached origin key in a single Lua transaction. This eliminates interleaving races between separate key deletion and marker creation steps.
- Global Invalidation Sequencing: Global tombstone markers are written prior to key deletion so concurrent in flight reads cannot commit stale entries into Redis.
- Bounded Memory Footprint: Map `lastInvalidatedAt` prunes entries older than 60 seconds and strictly caps capacity at 1,000 entries by evicting oldest insertion entries when capacity is exceeded.

### 4. Hermetic Test Isolation Guard
In `backend/tests/fixtures/test-env-isolation.ts`:
- Alias Purging: All variants of Redis environment variables are purged at startup.
- Safe URI Validation: Loopback addresses are permitted while remote and cloud URIs throw security violations.
- Credential Redaction: Error strings omit raw URIs, passwords, and tokens to prevent accidental log leakage.

---

## Verification Evidence

All test suites gate successfully with zero failures:

1. Security Suite Manifest (`npm run test:all-security`):
   - 21 of 21 test suites passed (0 failures).
   - `cors-cache-correctness.test.ts`: 15 of 15 tests passed, including atomic Lua invalidation, hard bounded map capacity, Redis outage recovery, cross process race rejection, scan marker preservation, and monotonic version sequencing.
   - `membership-lifecycle.test.ts`: 22 of 22 tests passed, including cross source conflict precedence, zero write dry run migration, background self heal isolation, memory server URI verification, email reuse detection, revocation preservation, and credential redaction.

2. Unit Test Suite (`npm run test:unit`):
   - All unit test suites passed cleanly across admin scoping, runtime resilience, gateway pipeline, dev isolation, and operator identity audits.

3. Contract and Documentation Verification:
   - `npm run security:integration-check`: Passed with 0 contract violations.
   - `npm run security:docs-check`: Passed with 0 documentation inconsistencies.

4. Application Builds:
   - Backend esbuild bundle generated cleanly (`dist/index.cjs`).
   - Frontend Vite production build completed with zero errors.

---

## Conclusion and Final Verdict

**Verdict**: Approve (Clean).

The implementation is verified, secure, and production ready. All cross source conflict requirements, legacy migration safeguards, atomic Redis Lua invalidation mechanisms, and test environment isolation protections are met. The branch remains isolated on `fix/cors-cache-security-perf` without merging to `main` or deploying.
