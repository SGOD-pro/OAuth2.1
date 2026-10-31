# Review: `fix/cors-cache-security-perf`

**Reviewer**: Senior Security and Architecture Reviewer  
**Branch**: `fix/cors-cache-security-perf`  
**Merge Base**: `d5e7663714ea45f279ddf4530af3fa71bf549a66`  
**HEAD**: `4c3046ed8a0b48a9b43234a12b08821f3a11a582` (`4c3046e`)  
**Verdict**: Approve (Clean)  

---

## Summary

This pull request delivers comprehensive hardening across three critical architectural domains:

1. Distributed CORS Cache Consistency: It replaces naive cache invalidation with atomic synchronization across Redis and MongoDB. A custom Redis Lua script validates in flight read timestamps against per origin and global tombstone markers. In MongoDB, atomic conditional updates with upsert retry guards prevent stale cache repopulation across concurrent worker processes. Commit `4c3046e` bounds the local in memory invalidation tracking map to 1000 entries with a 60 second rolling prune window, and optimizes origin invalidation using MongoDB `bulkWrite`.
2. Stable Identity Authorization: App admin privileges are now strictly bound to immutable user IDs. The unsafe legacy fallback granting admin rights based on user role and scoped client ID without an authoritative assignment record has been completely removed. Duplicate assignments now fail closed if any record is revoked or inactive. Ambiguous legacy email records are safely quarantined rather than blindly promoted.
3. Test Isolation and Performance Benchmarking: Strict environment guards purge inherited Redis environment variables and reject non disposable database URIs. Dedicated security suites prove cross process race resilience and complete membership lifecycle semantics. Standardized performance benchmarks confirm submillisecond CORS decisions and minimal overhead.

All 21 security test suites and all unit test suites pass cleanly. Contract linter and documentation consistency gates pass with zero violations.

---

## Findings by Severity

### Critical
None observed.

### High
None observed.

### Medium
None observed.

### Low
None observed.  
The previous finding regarding the unbounded in memory timestamp map has been resolved in commit `4c3046e`. Function `pruneInvalidatedAt` enforces a capacity limit of 1000 entries and purges entries older than 60 seconds (`60000` ms) whenever new origin invalidations arrive.

### Nits
None observed.  
Both previous suggestions have been addressed in commit `4c3046e`:
1. Sequential origin database updates: `invalidateOriginCache` in `backend/src/db/state.ts` now batches operations using `collection.bulkWrite` with unordered execution, reducing round trips while preserving fallback support for environments lacking `bulkWrite`.
2. Trailing slash path clarification: `backend/src/middleware/cors.ts` now documents that OAuth 2.1 redirect URIs standardly require absolute URIs with a path component (such as `/callback`) and details why prefix anchoring with a trailing slash prevents host confusion attacks.

---

## Architectural Strengths

### 1. Atomic Distributed CORS Cache Consistency
The distributed cache implementation addresses race conditions between concurrent readers and client mutations.
- Redis Lua Script Atomicity: `setCachedOriginRedis` executes a Lua script that inspects both the origin specific invalidation marker and the global invalidation marker. If either marker has a timestamp equal to or greater than the in flight read start time, the script aborts and returns zero without writing stale data.
- MongoDB Conditional Mutation: `putOriginCache` inspects the global tombstone and applies an atomic conditional update requiring `invalidatedAt` to be older than the read start time. If the entry does not exist, an insert is attempted with duplicate key collision handling to avoid races.
- Bounded Local Memory and Bulk Updates: Commit `4c3046e` adds `pruneInvalidatedAt` to prevent unbounded memory growth in long lived node processes, and executes explicit origin invalidations via unordered `bulkWrite` operations.
- Distributed Outage and Recovery Propagation: If Redis becomes unreachable during invalidation, the system marks a shared outage flag in MongoDB so sibling application instances immediately bypass potentially stale Redis entries and fall back safely to MongoDB. Upon Redis recovery, a global invalidation flush purges stale keys before Redis caching resumes.

### 2. Deterministic Cross Process Race Verification
In `backend/tests/security/cors-cache-correctness.test.ts` (test case 11), a child worker process is spawned using `node:child_process` fork. The child process initiates an origin check at time t1. The parent process mutates the OAuth client configuration at time t2. The child attempts to commit its stale read result at time t3. The test deterministically verifies that both parent and child observe cache rejection, and confirms that shared Redis outage flags propagate across separate processes through MongoDB state.

### 3. Strict Identity Binding and Removal of Unsafe Fallbacks
In `backend/src/middleware/admin-auth.ts` and `backend/src/utils/security.ts`:
- Removal of Unsafe Scoped Role Fallback: Previously, a user with `role: "admin"` and a matching `scopedClientId` in their user document could access app admin endpoints even if their assignment record in `app_admins` or `user_app_registrations` had been deleted. That bypass is now eliminated. Authorization requires an explicit, active assignment record.
- Immutable Identifier Validation: Authorization matches strictly on immutable `userId`. Matching on email alone is disallowed because email addresses can change or be recycled.
- Fail Closed Duplicate Resolution: When duplicate assignment records exist for a user and client, any inactive, revoked, suspended, or disabled record immediately revokes access.

### 4. Safe Legacy Migration
The `migrateLegacyAppAdmins` utility in `backend/src/utils/admin-sync.ts` securely reconciles preexisting records:
- Unambiguous Resolution Only: Legacy email records lacking a user ID are migrated only when exactly one user account matches that email address.
- Ambiguity Quarantine: If zero users or multiple users match an email, the record is flagged for operator inspection with full audit trail entries. No access is granted.
- Super Admin Isolation: Super admin accounts are prevented from being downgraded or assigned as consumer app admins.

### 5. Hermetic Test Environment Isolation
The isolation guard in `backend/tests/fixtures/test-env-isolation.ts`:
- Strips all Redis environment variable variants to prevent automated tests from contacting remote or production caches.
- Inspects `MONGO_URI` and throws a security violation error if a remote, cloud, or non loopback connection string is detected.
- Guarantees tests and benchmarks run strictly against disposable local instances.

---

## Test Coverage and Verification Evidence

All test suites gate successfully with zero failures:

1. Security Suite Manifest (`npm run test:all-security`):
   - 21 of 21 test suites passed (0 failures).
   - `cors-cache-correctness.test.ts`: 11 of 11 tests passed, including multi client origin overlap, derived redirect origins, Redis outage simulation, and cross process race rejection.
   - `membership-lifecycle.test.ts`: 16 of 16 tests passed, including inactive status rejection, boolean revocation flags, production loopback blocking, real route access control, duplicate record fail closed resolution, and removal of unsafe legacy fallbacks.

2. Unit Test Suite (`npm run test:unit`):
   - 12 of 12 tests passed in `admin-scoping.test.ts`.
   - Verified that unassigned users with `scopedClientId` fail closed.
   - All runtime resilience, gateway pipeline, dev isolation, and config simplification unit tests passed.

3. Contract and Documentation Verification:
   - `npm run security:integration-check`: Passed with 0 contract violations.
   - `npm run security:docs-check`: Passed with 0 documentation inconsistencies.

---

## Performance Baseline Summary

Measurements gathered via `backend/scripts/measure-performance-baseline.ts` running against a disposable MongoDB instance on Node v24:

| Operation | p50 (ms) | p95 (ms) | p99 (ms) | Average (ms) |
|---|---|---|---|---|
| User Login (`/api/auth/sign-in/email`) | 76.34 | 93.92 | 217.16 | 81.51 |
| Session Verification (`/api/auth/get-session`) | 6.51 | 10.33 | 117.95 | 8.05 |
| RS256 JWKS Token Verification | 0.09 | 0.36 | 1.07 | 0.14 |
| Novel CORS Origin Lookup (MongoDB seek) | 0.71 | 1.20 | 1.77 | 0.75 |
| Cached CORS Origin Lookup (Cache hit) | 0.66 | 1.28 | 1.82 | 0.75 |

Key Performance Observations:
- CORS queries take under 1 millisecond on average due to anchored prefix regexes seeking over compound B tree indexes (`allowedOrigins_1_disabled_1`, `redirectUris_1_disabled_1`).
- Token cryptographic validation against local JWKS averages 0.14 milliseconds.
- Session lookups execute in approximately 6 to 8 milliseconds.
- Origin cache bulk invalidations minimize database overhead to a single round trip.

---

## Conclusion and Final Verdict

**Verdict**: Approve (Clean).

The implementation is robust, complete, and fully verified. All previous low severity and nit observations have been resolved in commit `4c3046e`. The distributed cache consistency mechanisms, stable identity bindings, and comprehensive test coverage satisfy all architectural and security requirements. This branch is ready to merge.
