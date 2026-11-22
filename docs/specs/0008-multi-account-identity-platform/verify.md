# 0008 verification plan and evidence ledger

**Status:** P0 compatibility proof locally passed; production V2 scenarios remain pending. See [P0 evidence](file:///home/swyra/projects/OAuth2.1/docs/specs/0008-multi-account-identity-platform/p0-evidence.md) for source, commands, inventory and limitations.
Baseline security evidence is separate: [CI at 66738b0198b0fdb1342dec210394ac5e09041a77](https://github.com/SGOD-pro/OAuth2.1/actions/runs/44947156668). Later report wording correction does not add separate worker execution evidence.

## Docs only verification

Record actual commands/results in the documentation PR: relative links/anchors, required canonical contract checks, diagram syntax, requirement to slice mapping and docs only diff. A documentation check cannot mark the runtime matrix below complete.

## Runtime evidence

| Scenario | AC IDs | Required category | Status |
|---|---|---|---|
| Engine transaction rollback and writer inventory | 01-03,16 | Real engine + Mongo replica-set transaction | P0 isolated proof passed, 10 cases; production P2 pending |
| Request-local selected engine sessions | 07-09 | In-process engine HTTP + real Mongo replica set | P0 proof passed, 6 cases; browser/workers and P3 wiring pending |
| OTP start/verify/resend/finalize and wrong-code zero writes | 02-04,15 | Real API + disposable DB/mail sink; concurrency workers | Pending |
| New user/profile/key/session and lost response recovery | 03,16 | Real engine finalization + idempotency | Pending |
| Client-policy backfill and open/private matrix | 05-06,14 | Old/new schema and real consumer fixtures | P1a classification and zero write audit verified (32 unit/CLI cases passed); refresh lease fencing verified; P1b enforcement and P1c UI pending |
| Browser A/B login, tab interleave, expiry/logout, admin purpose | 07-09,21 | Real browser plus separate backend workers | Pending |
| Account-list CORS/CSRF/fixation/context misuse | 08 | Browser and direct HTTP negatives | Pending |
| Genuine user/admin MFA, recovery/promotion/step-up/plugin paths | 10-11 | Real password/TOTP/backup protocol | Pending |
| Dashboard A/B ownership, claims/privacy and admin serializers | 12-14 | Direct API + browser/cache/consumer tests | Pending |
| Mail signed callbacks, late jobs, crash/timeouts, bounce/suppression | 15,18 | Real sink/queue; controlled provider separately | Pending |
| Key backend/AAD/rotation/writers and old plaintext copies | 16 | Real key service and migration inventory | Pending |
| Delete/refresh race, lease recovery, receipts and snapshot restore | 17 | Separate workers + key service + pre-deletion restore | Pending |
| Fleet quotas, failover/outage, edge and cost saturation | 18 | Multi-process + staging load under explicit limits | Pending |
| Device spoof/missing/VPN/false-positive step-up | 19 | Controlled browser/risk fixtures | Pending |
| Cache invalidation and optional filter snapshots/fallback | 20 | Real cache/process tests; filter benchmark if selected | Pending |
| Page accessibility/expired/error/denied states | 21 | Browser keyboard/accessibility and backend outcomes | Pending |
| Fresh self-host install, upgrade, recovery/disclosure/provenance | 22 | Release drill and independent review | Pending |

## Required record format

For each implementing slice record commit SHA, source diff scope, worktree status, exact commands, dependency/service versions, case IDs, pass/fail/blocked/skipped counts, log references and limitations. Label mocks and two app instances in one process honestly. Real multi-worker claims require distinct processes/connections with deterministic barriers. Mail provider acceptance is not delivery; a scheduled key deletion is not destruction; notification is not consumer erasure.

## Gate behavior

A failed security invariant blocks affected rollout; do not skip/relax it for a green count. An unavailable dependency is blocked, not pass. Docs edits do not authorize deployment, destructive live tests or production data access. Proofs, keys, PII and tokens never appear in evidence artifacts.

## P1a client policy classification and read only audit evidence

**Date:** 2026-11-22. **Result:** P1a classification, authentication method resolution, streaming cursor audit, and ownership safe refresh lease fencing verified across 32 focused tests. Production token refresh grant handling ([auth-token-refresh.ts](file:///home/swyra/projects/OAuth2.1/backend/src/routes/auth-token-refresh.ts)) and rotation rights acquisition ([auth-token-claim.ts](file:///home/swyra/projects/OAuth2.1/backend/src/routes/auth-token-claim.ts)) have been hardened with ownership safe fencing tokens (`leaseOwner`) and deterministic barrier interception hooks (`after_lease_claim`). Administrative endpoints and authorization code issuance remain untouched. Slice P1b runtime enforcement and slice P1c frontend administrative controls remain pending.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `4d7b3340b93fe10695c818fc7583fc86fc1bac30`
* Worktree status: Clean at verification
* Source scope:
  * [client-policy-types.ts](file:///home/swyra/projects/OAuth2.1/backend/src/identity/client-policy-types.ts): Pure classification types, records, and URI validation
  * [client-policy.ts](file:///home/swyra/projects/OAuth2.1/backend/src/identity/client-policy.ts): Pure classification logic, safe reason codes, and streaming cursor audit
  * [auth-keys.ts](file:///home/swyra/projects/OAuth2.1/backend/src/routes/auth-keys.ts): Token barrier stage typing for lease claim synchronization
  * [auth-token-claim.ts](file:///home/swyra/projects/OAuth2.1/backend/src/routes/auth-token-claim.ts): Unique fencing token generation on rotation claim
  * [auth-token-refresh.ts](file:///home/swyra/projects/OAuth2.1/backend/src/routes/auth-token-refresh.ts): Production refresh grant handler with barrier hook and ownership fenced lock release
  * [token-families.ts](file:///home/swyra/projects/OAuth2.1/backend/src/db/token-families.ts): Atomic CAS rotation requiring matching lease owner
  * [audit-client-policies.ts](file:///home/swyra/projects/OAuth2.1/backend/scripts/audit-client-policies.ts): Read only CLI audit scanner
  * [client-policy-classification.test.ts](file:///home/swyra/projects/OAuth2.1/backend/tests/unit/client-policy-classification.test.ts): Pure classification helper unit test suite (16 tests)
  * [client-policy-auth-methods.test.ts](file:///home/swyra/projects/OAuth2.1/backend/tests/unit/client-policy-auth-methods.test.ts): Authentication method regression suite (8 tests)
  * [client-policy-audit-cli.test.ts](file:///home/swyra/projects/OAuth2.1/backend/tests/unit/client-policy-audit-cli.test.ts): Process level read only database and CLI execution test suite (6 tests)
  * [refresh-lease-fencing.test.ts](file:///home/swyra/projects/OAuth2.1/backend/tests/unit/refresh-lease-fencing.test.ts): Thread level separate worker lease fencing and route execution suite (2 tests)
  * [0008-p1-client-policy-migration.md](file:///home/swyra/projects/OAuth2.1/docs/specs/0008-multi-account-identity-platform/0008-p1-client-policy-migration.md): P1c administrative UI specification, production native loopback alignment, and Migrated validation invariant
  * [USER_EXPERIENCE.md](file:///home/swyra/projects/OAuth2.1/docs/USER_EXPERIENCE.md): Section 6 link to P1c administrative UI specification
* File length: All modified and new production and test source files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: Focused P1a and refresh concurrency suites
   * Helper execution in [client-policy-classification.test.ts](file:///home/swyra/projects/OAuth2.1/backend/tests/unit/client-policy-classification.test.ts): 16 passed, 0 failed
     * Four clean classes: Open Public, Private Confidential, Open Confidential, Private Public
     * Migrated class with explicit fields
     * Strict boolean development mode parsing where truthy strings are classified as ambiguous
     * Ephemeral port variation on native loopback interfaces per RFC 8252
     * Ambiguity reason codes: PARTIAL_EXPLICIT_POLICY, MISSING_ACCESS_METADATA, MALFORMED_ACCESS_METADATA, MALFORMED_DEV_FLAGS, CONFLICTING_AUTH_METHOD, ID conflicts
     * Complete URI redaction: Safe constant error messages without raw URIs, queries, fragments, or userinfo credentials
     * Pure isolation: Zero mutations to input records; no runtime imports into authorize or token routes
   * Helper execution in [client-policy-auth-methods.test.ts](file:///home/swyra/projects/OAuth2.1/backend/tests/unit/client-policy-auth-methods.test.ts): 8 passed, 0 failed
     * `private_key_jwt` missing `jwks` or `jwks_uri` classified as ambiguous, never clean public
     * `private_key_jwt` with valid `jwks_uri` and no secret classified as confidential
     * `private_key_jwt` with registered client secret flagged as conflicting
     * Unsupported `client_secret_jwt` flagged as ambiguous
     * Explicit public client with `private_key_jwt` flagged as conflicting metadata
     * Explicit confidential client with `private_key_jwt` and `jwks_uri` resolves as Migrated
     * Four legitimate legacy combinations preserved
   * Process execution in [client-policy-audit-cli.test.ts](file:///home/swyra/projects/OAuth2.1/backend/tests/unit/client-policy-audit-cli.test.ts): 6 passed, 0 failed
     * Engine enforced zero writes against real MongoDB instance using read only database user role (`roles: [{ role: "read", db: dbName }]`), verifying that direct insert attempts throw `MongoServerError: not authorized`
     * Output redaction in CLI JSON and human readable output
     * Process exit codes: 0 for clean inventory, 1 for ambiguous inventory, 1 for missing configuration
   * Thread and route execution in [refresh-lease-fencing.test.ts](file:///home/swyra/projects/OAuth2.1/backend/tests/unit/refresh-lease-fencing.test.ts): 2 passed, 0 failed
     * Worker A executes `handleRefreshTokenGrant`, claims rotation lease with unique `leaseOwnerA`, and pauses at `after_lease_claim` deterministic barrier hook
     * Lease expires in MongoDB by backdating `rotatingAt` past 15 seconds
     * Worker B executes `handleRefreshTokenGrant`, claims replacement lease with distinct `leaseOwnerB`, and pauses at `after_lease_claim` hook
     * Worker A resumes with controlled failure, entering `catch` block in `handleRefreshTokenGrant` which calls `releaseRotationLock(database, incomingHash, canonicalClientId, leaseOwnerA)`. Because the document in MongoDB contains `rotationOwner: leaseOwnerB`, Worker A cleanup modifies 0 documents
     * MongoDB inspection proves Worker B owner and lock (`rotating: true`, `rotationOwner: leaseOwnerB`) are strictly preserved
     * Stale Worker A attempts rotation CAS with `leaseOwnerA`; CAS matches 0 documents and fails with `valid: false`
     * Active Worker B resumes and completes production `handleRefreshTokenGrant` successfully, returning HTTP 200 with minted RS256 access token and rotated refresh token
     * MongoDB token family active token hash is updated, previous token hash is moved to `consumedTokenHashes`, `rotating` is false, and `rotationOwner` is cleared
     * Replay of initial token after grace window triggers immediate replay detection, cascade revoking the token family
     * Direct unit test confirms `handleRefreshTokenGrant` releases rotation lock with `leaseOwner` on thrown handler error
2. Command: `npm run security:docs-check`
   * Result: Passed without errors
3. Command: `git diff --check`
   * Result: Passed without whitespace or formatting errors

### Limitations and pending scope

* Classification and audit tests executed against disposable in memory MongoDB (v7.0.24). Production and staging database inventory runs require platform super admin execution.
* Slice P1b (runtime enforcement of `clientType`, `accessPolicy`, PKCE on public code exchange, verifier free public refresh rotation, and bypass of ambient membership writes) is not yet active.
* Slice P1c (frontend admin interface updates in `RegisterAppModal.tsx`, `EditAppModal.tsx`, `AdminClients.tsx`) is documented but unimplemented.
