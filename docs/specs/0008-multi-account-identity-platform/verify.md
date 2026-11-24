# 0008 verification plan and evidence ledger

**Status:** P0 compatibility proof locally passed; production V2 scenarios remain pending. See [P0 evidence](p0-evidence.md) for source, commands, inventory and limitations.
Baseline security evidence is separate: [CI at 66738b0198b0fdb1342dec210394ac5e09041a77](https://github.com/SGOD-pro/OAuth2.1/actions/runs/44947156668). Later report wording correction does not add separate worker execution evidence.

## Docs only verification

Record actual commands and results in the documentation PR: relative links, anchors, required canonical contract checks, diagram syntax, requirement to slice mapping and docs only diff. A documentation check cannot mark the runtime matrix below complete.

## Runtime evidence

| Scenario | AC IDs | Required category | Status |
|---|---|---|---|
| Engine transaction rollback and writer inventory | 01-03,16 | Real engine + Mongo replica set transaction | P0 isolated proof passed, 10 cases; production P2 pending |
| Request local selected engine sessions | 07-09 | In process engine HTTP + real Mongo replica set | P0 proof passed, 6 cases; browser and workers and P3 wiring pending |
| OTP start, verify, resend, finalize and wrong code zero writes | 02-04,15 | Real API + disposable DB and mail sink; concurrency workers | Pending |
| New user, profile, key, session and lost response recovery | 03,16 | Real engine finalization + idempotency | Pending |
| Client policy backfill and open, private matrix | 05-06,14 | Old and new schema and real consumer fixtures | P1a classification and audit (32 cases), refresh lease fencing (2 cases), P1b canonical resolution and ambiguous denial (10 cases), and four class HTTP compatibility (4 cases) verified; later P1b enforcement and P1c UI pending |
| Browser A and B login, tab interleave, expiry, logout, admin purpose | 07-09,21 | Real browser plus separate backend workers | Pending |
| Account list CORS, CSRF, fixation, context misuse | 08 | Browser and direct HTTP negatives | Pending |
| Genuine user, admin MFA, recovery, promotion, step up, plugin paths | 10-11 | Real password, TOTP, backup protocol | Pending |
| Dashboard A and B ownership, claims, privacy and admin serializers | 12-14 | Direct API + browser, cache, consumer tests | Pending |
| Mail signed callbacks, late jobs, crash, timeouts, bounce, suppression | 15,18 | Real sink and queue; controlled provider separately | Pending |
| Key backend, AAD, rotation, writers and old plaintext copies | 16 | Real key service and migration inventory | Pending |
| Delete, refresh race, lease recovery, receipts and snapshot restore | 17 | Separate workers + key service + pre deletion restore | Pending |
| Fleet quotas, failover, outage, edge and cost saturation | 18 | Multi process + staging load under explicit limits | Pending |
| Device spoof, missing, VPN, false positive step up | 19 | Controlled browser and risk fixtures | Pending |
| Cache invalidation and optional filter snapshots, fallback | 20 | Real cache and process tests; filter benchmark if selected | Pending |
| Page accessibility, expired, error, denied states | 21 | Browser keyboard, accessibility and backend outcomes | Pending |
| Fresh self host install, upgrade, recovery, disclosure, provenance | 22 | Release drill and independent review | Pending |

## Required record format

For each implementing slice record commit SHA, source diff scope, worktree status, exact commands, dependency and service versions, case IDs, pass, fail, blocked, skipped counts, log references and limitations. Label mocks and two app instances in one process honestly. Real multi worker claims require distinct processes or connections with deterministic barriers. Mail provider acceptance is not delivery; a scheduled key deletion is not destruction; notification is not consumer erasure.

## Gate behavior

A failed security invariant blocks affected rollout; do not skip or relax it for a green count. An unavailable dependency is blocked, not pass. Docs edits do not authorize deployment, destructive live tests or production data access. Proofs, keys, PII and tokens never appear in evidence artifacts.

## P1a client policy classification and read only audit evidence

**Date:** 2026-11-22. **Result:** P1a classification, authentication method resolution, streaming cursor audit, and ownership safe refresh lease fencing verified across 32 focused tests. Production token refresh grant handling ([auth-token-refresh.ts](../../../backend/src/routes/auth-token-refresh.ts)) and rotation rights acquisition ([auth-token-claim.ts](../../../backend/src/routes/auth-token-claim.ts)) have been hardened with ownership safe fencing tokens (`leaseOwner`) and deterministic barrier interception hooks (`after_lease_claim`). Administrative endpoints and authorization code issuance remain untouched. Slice P1b runtime enforcement and slice P1c frontend administrative controls remain pending.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `4d7b3340b93fe10695c818fc7583fc86fc1bac30`
* Worktree status: Clean at verification
* Source scope:
  * [client-policy-types.ts](../../../backend/src/identity/client-policy-types.ts): Pure classification types, records, and URI validation
  * [client-policy.ts](../../../backend/src/identity/client-policy.ts): Pure classification logic, safe reason codes, and streaming cursor audit
  * [auth-keys.ts](../../../backend/src/routes/auth-keys.ts): Token barrier stage typing for lease claim synchronization
  * [auth-token-claim.ts](../../../backend/src/routes/auth-token-claim.ts): Unique fencing token generation on rotation claim
  * [auth-token-refresh.ts](../../../backend/src/routes/auth-token-refresh.ts): Production refresh grant handler with barrier hook and ownership fenced lock release
  * [token-families.ts](../../../backend/src/db/token-families.ts): Atomic CAS rotation requiring matching lease owner
  * [audit-client-policies.ts](../../../backend/scripts/audit-client-policies.ts): Read only CLI audit scanner
  * [client-policy-classification.test.ts](../../../backend/tests/unit/client-policy-classification.test.ts): Pure classification helper unit test suite (16 tests)
  * [client-policy-auth-methods.test.ts](../../../backend/tests/unit/client-policy-auth-methods.test.ts): Authentication method regression suite (8 tests)
  * [client-policy-audit-cli.test.ts](../../../backend/tests/unit/client-policy-audit-cli.test.ts): Direct CLI function and read only database execution test suite (6 tests)
  * [refresh-lease-fencing.test.ts](../../../backend/tests/unit/refresh-lease-fencing.test.ts): Worker thread lease fencing and route execution suite (2 tests)
  * [0008-p1-client-policy-migration.md](0008-p1-client-policy-migration.md): P1c administrative UI specification, production native loopback alignment, and Migrated validation invariant
  * [USER_EXPERIENCE.md](../../USER_EXPERIENCE.md): Section 6 link to P1c administrative UI specification
* File length: All modified and new production and test source files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: Focused P1a and refresh concurrency suites
   * Helper execution in [client-policy-classification.test.ts](../../../backend/tests/unit/client-policy-classification.test.ts): 16 passed, 0 failed
     * Four clean classes: Open Public, Private Confidential, Open Confidential, Private Public
     * Migrated class with explicit fields
     * Strict boolean development mode parsing where truthy strings are classified as ambiguous
     * Ephemeral port variation on native loopback interfaces per RFC 8252
     * Ambiguity reason codes: PARTIAL_EXPLICIT_POLICY, MISSING_ACCESS_METADATA, MALFORMED_ACCESS_METADATA, MALFORMED_DEV_FLAGS, CONFLICTING_AUTH_METHOD, ID conflicts
     * Complete URI redaction: Safe constant error messages without raw URIs, queries, fragments, or userinfo credentials
     * Pure isolation: Zero mutations to input records; no runtime imports into authorize or token routes
   * Helper execution in [client-policy-auth-methods.test.ts](../../../backend/tests/unit/client-policy-auth-methods.test.ts): 8 passed, 0 failed
     * `private_key_jwt` missing `jwks` or `jwks_uri` classified as ambiguous, never clean public
     * `private_key_jwt` with valid `jwks_uri` and no secret classified as confidential
     * `private_key_jwt` with registered client secret flagged as conflicting
     * Unsupported `client_secret_jwt` flagged as ambiguous
     * Explicit public client with `private_key_jwt` flagged as conflicting metadata
     * Explicit confidential client with `private_key_jwt` and `jwks_uri` resolves as Migrated
     * Four legitimate legacy combinations preserved
   * Direct CLI function execution in [client-policy-audit-cli.test.ts](../../../backend/tests/unit/client-policy-audit-cli.test.ts): 6 passed, 0 failed
     * Engine enforced zero writes against real MongoDB instance using read only database user role (`roles: [{ role: "read", db: dbName }]`), verifying that direct insert attempts throw `MongoServerError: not authorized`
     * Direct invocation of `runClientPolicyAudit` function with in memory stream captures and redacts secrets and URIs
     * Output redaction in CLI JSON and human readable output
     * Process exit code simulation: 0 for clean inventory, 1 for ambiguous inventory, 1 for missing configuration
   * Worker thread and route execution in [refresh-lease-fencing.test.ts](../../../backend/tests/unit/refresh-lease-fencing.test.ts): 2 passed, 0 failed
     * Separate `worker_threads.Worker` instances run independent backend execution contexts with distinct MongoClient connections and deterministic barrier interception hooks (`after_lease_claim`)
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
   * Mocked engine execution vs live MongoDB distinction:
     * Classification and auth method tests execute pure in memory helpers with zero network or database dependencies
     * Audit CLI tests execute direct CLI functions against disposable authenticated MongoDB instances with genuine read only role enforcement
     * Refresh lease fencing tests execute production `handleRefreshTokenGrant` route handlers across genuine worker threads and distinct MongoDB connections
     * In `refresh-lease-fencing.test.ts`, Worker B configures an `authProvider.handler` mock for token minting while executing live MongoDB CAS lease acquisition, lease fencing, and rotation commit against disposable MongoDB
2. Command: `npm run security:docs-check`
   * Result: Passed without errors
3. Command: `git diff --check`
   * Result: Passed without whitespace or formatting errors

### Limitations and pending scope

* Classification and audit tests executed against disposable in memory MongoDB (v7.0.24). Production and staging database inventory runs require platform super admin execution.
* Slice P1b canonical client policy resolution and ambiguous client denial are verified. Later P1b enforcement (PKCE for confidential authorization code clients, membership bypass write removal) remains pending.
* Slice P1c (frontend admin interface updates in `RegisterAppModal.tsx`, `EditAppModal.tsx`, `AdminClients.tsx`) is documented but unimplemented.

## P1b canonical client policy resolution and ambiguous denial evidence

**Date:** 2026-11-23. **Result:** P1b canonical client policy resolution, ambiguous client denial, and four class HTTP compatibility verified across 14 focused integration cases (10 in [client-policy-enforcement.test.ts](../../../backend/tests/security/client-policy-enforcement.test.ts) and 4 in [client-policy-compatibility.test.ts](../../../backend/tests/security/client-policy-compatibility.test.ts)). Canonical client representation exposes validated policy dimensions (`clientType`, `accessPolicy`, `classification`, `isAmbiguous`, `ambiguityReasonCodes`, `ambiguityReasons`) through [client-resolver.ts](../../../backend/src/utils/client-resolver.ts). All four clean combinations (Class A open public, Class B private confidential, Class C open confidential, Class E private public) and explicitly migrated records resolve cleanly and complete authorization code flow and token exchange. Ambiguous clients fail closed at protocol boundaries with endpoint specific responses, and client revocation enforces authentication before mutation with zero mutations.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `0d96d37dbd2c1e656ea7435ffcceeb4610c96e21`
* CI run reference: `45088868911` (diagnosed and resolved loopback development classification in restart fixture)
* Worktree status: Clean at verification
* Source scope:
  * [client-resolver.ts](../../../backend/src/utils/client-resolver.ts): Extended `CanonicalOAuthClient` with validated policy dimensions and reason codes, resolving via `resolveClientPolicy`
  * [auth-authorize.ts](../../../backend/src/routes/auth-authorize.ts): Direct HTTP 400 rejection for ambiguous clients without redirecting per RFC 6749 Section 3.1.2.4
  * [auth-consent.ts](../../../backend/src/routes/auth-consent.ts): Direct HTTP 400 rejection on ambiguous clients across consent and continuation endpoints
  * [auth-token-auth.ts](../../../backend/src/routes/auth-token-auth.ts): HTTP 401 rejection on ambiguous clients across authorization code and refresh grants, returning Basic challenge header when caller presents Basic credentials
  * [auth-introspect.ts](../../../backend/src/routes/auth-introspect.ts): HTTP 401 on ambiguous calling client; returns active false on ambiguous token target client
  * [auth-revoke.ts](../../../backend/src/routes/auth-revoke.ts): HTTP 401 on ambiguous calling client with authentication before mutation guaranteeing zero database mutations
  * [auth-initiate.ts](../../../backend/src/routes/auth-initiate.ts): Direct HTTP 400 rejection on ambiguous client
  * [auth-sign-in.ts](../../../backend/src/routes/auth-sign-in.ts): Direct HTTP 400 rejection on ambiguous client
  * [auth-sign-up.ts](../../../backend/src/routes/auth-sign-up.ts): Direct HTTP 400 rejection on ambiguous client
  * [idp-process-restart.test.ts](../../../backend/tests/e2e/idp-process-restart.test.ts): Marked local server confidential fixture explicitly as development mode to resolve loopback redirect URI classification under V2 policy resolution while preserving private access policy and secret authentication
  * [runtime-resilience.test.ts](../../../backend/tests/unit/runtime-resilience.test.ts): Marked local server confidential fixture explicitly as development mode
  * [config-simplification.test.ts](../../../backend/tests/unit/config-simplification.test.ts): Asserted ambiguous classification and fail closed private access policy for incomplete client documents without access metadata
  * [client-policy-enforcement.test.ts](../../../backend/tests/security/client-policy-enforcement.test.ts): 10 focused HTTP entry point tests against disposable MongoDB covering ambiguous denial, Basic challenge headers on 401, and authenticated introspection of tokens targeting ambiguous clients
  * [client-policy-compatibility.test.ts](../../../backend/tests/security/client-policy-compatibility.test.ts): 4 HTTP compatibility integration tests against disposable MongoDB covering Class A (Open Public), Class B (Private Confidential), Class C (Open Confidential), and Class E (Private Public) with authorization code flow, explicit private membership gates, Basic or PKCE credentials, and RS256 token verification
* File length: All modified and new production and test source files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `npm --prefix backend run test:process-restart`
   * Result: Passed without errors, verifying pre restart tokens, retained signing keys across process termination, post restart refresh token rotation, and UserInfo profile retrieval
2. Command: `npm --prefix backend run test:client-policy-enforcement`
   * Result: 10 passed, 0 failed
   * Validated canonical policy resolution across Class A (open public), Class B (private confidential), Class C (open confidential), Class E (private public), and Migrated Class
   * Direct HTTP 400 rejection at `GET /api/auth/oauth2/authorize` for ambiguous client with zero redirect
   * Direct HTTP 400 rejection at `POST /api/auth/oauth2/consent` and `POST /api/auth/oauth2/continue` for ambiguous client
   * HTTP 401 rejection at `POST /api/auth/oauth2/token` for code exchange and refresh grants
   * HTTP 401 rejection at `POST /api/auth/oauth2/introspect` for ambiguous caller client
   * HTTP 401 rejection with `WWW-Authenticate: Basic realm="OAuth"` challenge header when caller presents Basic credentials
   * HTTP 401 rejection at `POST /api/auth/oauth2/revoke` for ambiguous caller client, with database verification proving zero mutations on token family and access token documents
   * Authenticated introspection returns HTTP 200 `{ active: false }` for token targeting ambiguous client
   * HTTP 400 rejection at initiate, sign in, and sign up endpoints
   * Progression verification: clean legacy client proceeds through authorize endpoint with 302 redirect and transaction cookie set
3. Command: `npm --prefix backend run test:client-policy-compatibility`
   * Result: 4 passed, 0 failed
   * Class A (Open Public): authenticated authorization, code issuance, public token exchange with PKCE and no client secret, and RS256 token signature and subject verification
   * Class B (Private Confidential): unassigned user denied with HTTP 302 access denied, assigned user authorized, code issuance, Basic auth token exchange, and RS256 token signature and subject verification
   * Class C (Open Confidential): authenticated authorization, code issuance, Basic auth token exchange, and RS256 token signature and subject verification
   * Class E (Private Public): unassigned user denied with HTTP 302 access denied, assigned user authorized, code issuance, public token exchange with PKCE and no client secret, and RS256 token signature and subject verification
4. Command: `npm --prefix backend run test:config-simplification`
   * Result: 10 passed, 0 failed
   * Incomplete client documents without access metadata fail closed to private access policy with ambiguous classification
5. Command: Unit test suite `NODE_OPTIONS="--jitless" npm --prefix backend run test:unit`
   * Result: All 16 unit and security suites passed with 0 failures
6. Command: `npm --prefix backend run security:docs-check`
   * Result: Passed without errors
7. Command: `git diff --check`
   * Result: Passed without whitespace or formatting errors


## Security test runner hang repair and local recovery verification

**Date:** 2026-11-23. **Result:** Verified resolution of the test runner stall and confirmed full local recovery across all 32 automated security test suites, 16 unit test suites, and 11 local consumer end to end flows using the shared Docker MongoDB harness.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `5b3463208c6b166b689d61b71c4a2fc7efca4470`
* Worktree status: Working tree with hang repair and runtime reconciliation
* Source scope:
  * [cors-worker-client.ts](../../../backend/tests/fixtures/cors-worker-client.ts): Reusable worker IPC client with pre registered listeners, bounded deadlines, child error, exit, disconnect, and send callback handling, and graceful worker shutdown
  * [cors-multi-process-worker.ts](../../../backend/tests/fixtures/cors-multi-process-worker.ts): Handlers for crash, disconnect, and silent worker simulation
  * [cors-worker-ipc-resilience.test.ts](../../../backend/tests/security/cors-worker-ipc-resilience.test.ts): 5 dedicated test cases exercising worker crash, disconnect, missing reply timeout, sending to terminated child, and process cleanup
  * [cors-cache-correctness.test.ts](../../../backend/tests/security/cors-cache-correctness.test.ts): Refactored all 7 worker test cases (CORS 11, CORS 20, CORS 29, CORS 34, CORS 38, CORS 47, CORS 49) to use bounded IPC helper and graceful worker termination
  * [run-all-security.ts](../../../backend/scripts/run-all-security.ts): Configurable suite deadlines (default 60s, heavy suites 120s), process group termination with SIGTERM and fallback SIGKILL, exit confirmation prior to database cleanup, bounded database cleanup with timeouts and finally blocks, interruption signal handling for SIGINT and SIGTERM, and preservation of externally owned Docker MongoDB
  * [admin-mfa-fixture.ts](../../../backend/tests/fixtures/admin-mfa-fixture.ts): Stable simulated IP allocation per fixture session, explicit caller header preservation for trusted proxy and rate limit assertions, HTTP status validation before parsing totpURI, and descriptive HTTP 429 error reporting
* File length: All modified and new production and test source files are strictly under 300 lines

### Distinguishing reproduced causes from hypotheses

1. Reproduced cause: Unhandled worker IPC in `cors-cache-correctness.test.ts` where parent promises lacked deadlines, error listeners, and disconnect handling caused worker stalls, blocking the runner indefinitely because `run-all-security.ts` lacked execution timeouts. This was reproduced, localized, and resolved.
2. Unconfirmed hypothesis: The hypothesis that Node v26 JIT or WASM compilation bugs caused the runner freeze is unconfirmed by evidence. Both Node 24 (matching CI) and Node 26 execute all 32 security test suites cleanly without segmentation faults once worker IPC and timeouts are bounded. The `--jitless` flag is treated as an optional documented workaround via `NODE_TEST_FLAGS` rather than an active requirement.
3. Fixture rate limiting: Consecutive test logins sharing the default IP `127.0.0.1` intermittently triggered Better Auth rate limiting (HTTP 429) during TOTP enrollment. Allocating a stable simulated IP (`198.51.100.X`) per fixture session resolves rate limit collisions while preserving explicit caller headers for dedicated rate limit and proxy tests.

### Verification commands and execution evidence

1. Command: `cd backend && node --import tsx tests/security/cors-worker-ipc-resilience.test.ts`
   * Result: 5 passed, 0 failed (2730ms)
   * Worker crash during IPC: bounded error rejection with exit code details (< 300ms)
   * Worker disconnect during IPC: bounded error rejection with disconnect info (< 300ms)
   * Missing worker reply: bounded timeout with stage attribution (~1465ms)
   * Send on dead child: immediate error rejection without hang (< 300ms)
   * Graceful termination: verified zero surviving child processes
2. Command: `cd backend && node --import tsx tests/security/cors-cache-correctness.test.ts`
   * Result: 49 passed, 0 failed (12971ms)
   * All 49 test cases passed cleanly, including multi process race and cache invalidation scenarios
3. Command: `cd backend && npm run test:all-security`
   * Result: 32 passed, 0 failed (100 percent pass rate across all security test files)
4. Command: `npm run test:unit`
   * Result: All 16 unit test suites passed with 0 failures
5. Command: `npm run test:local-consumer-e2e`
   * Result: All 11 local consumer flows passed with 0 failures
6. Command: `npm run security:integration-check`
   * Result: 0 violations
7. Command: `npm run security:docs-check`
   * Result: 0 errors
8. Command: `ps aux | grep -E "cors|worker" | grep -v grep`
   * Result: Zero orphaned node test worker processes surviving


## Authenticate before mutation and runner lifecycle cleanup verification

**Date:** 2026-11-24. **Result:** Verified that confidential client credentials are fully authenticated through the installed engine before authorization code consumption, burning, or token family replay revocation. Verified robust process group cleanup covering suite leader exit with stubborn descendants ignoring SIGTERM, coordinated cleanup across timeout, interruption, and natural exit paths, signal code exit detection, and bounded database deletion with operation deadlines. Open app membership bypass and slice P1c administrative controls remain pending.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `4de35b1aabcd7bc4d8f53c59eb911464e9409e21`
* Worktree status: Working tree with authentication ordering and runner lifecycle cleanup
* Source scope:
  * [auth-token-auth.ts](../../../backend/src/routes/auth-token-auth.ts): Authenticates confidential clients through the installed engine's probe endpoint before granting execution
  * [security-runner-lifecycle.ts](../../../backend/scripts/security-runner-lifecycle.ts): Module managing process group termination with SIGKILL escalation, signalCode exit detection, bounded database drop operations, and coordinated suite cleanup
  * [run-all-security.ts](../../../backend/scripts/run-all-security.ts): Updated aggregate runner consuming coordinated lifecycle cleanup across timeout, interruption, and child exit paths
  * [auth-before-mutation-repro.test.ts](../../../backend/tests/security/auth-before-mutation-repro.test.ts): Regression suite proving wrong credentials cause zero code mutations or family revocations, and legitimate exchanges succeed
  * [runner-lifecycle-cleanup.test.ts](../../../backend/tests/security/runner-lifecycle-cleanup.test.ts): Lifecycle suite proving stubborn descendant termination, signalCode detection, and bounded database cleanup deadlines
* File length: All modified and new production and test source files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `cd backend && node --import tsx tests/security/auth-before-mutation-repro.test.ts`
   * Result: 3 passed, 0 failed (1156ms)
   * REPRO 1: Wrong Basic secret returns HTTP 401 invalid_client; authorization code remains pending in database with consumedAt unset; legitimate confidential client subsequently exchanges the same code with HTTP 200
   * REPRO 2: Wrong body client_secret returns HTTP 401 invalid_client; authorization code remains pending in database; legitimate client subsequently exchanges with HTTP 200
   * REPRO 3: Replay of consumed code with wrong secret returns HTTP 401 invalid_client; existing token family remains active; subsequent replay by legitimate client with correct secret returns HTTP 400 invalid_grant and revokes the token family with reason code_replayed
2. Command: `cd backend && node --import tsx tests/security/runner-lifecycle-cleanup.test.ts`
   * Result: 4 passed, 0 failed (470ms)
   * Process group cleanup: Leader process exits first while descendant ignores SIGTERM; runner targets negative process group ID and terminates stubborn descendant via SIGKILL escalation within bounded time
   * Signal detection: Child terminated by SIGKILL with null exitCode is recognized immediately via signalCode
   * Bounded drop: Unreachable connection and stalled drop fail fast within configured deadline (~327ms for 300ms deadline) and close MongoDB client in finally block
   * Coordinated cleanup: Process termination completes strictly before database removal begins
3. Command: `npm run test:pkce-enforcement`
   * Result: 19 passed, 0 failed
4. Command: `npm run test:unit`
   * Result: All 16 unit test suites passed with 0 failures
5. Command: `npm run test:local-consumer-e2e`
   * Result: All 11 local consumer flows passed with 0 failures
6. Command: `npm run security:integration-check`
   * Result: 0 violations
7. Command: `npm run security:docs-check`
   * Result: 0 errors
8. Command: `npm run test:all-security`
   * Result: All 34 security test files passed (100 percent)
9. Prose check: Verified zero punctuation hyphens or dashes in added documentation prose


## Open app membership bypass and client secret post engine authentication verification

**Date:** 2026-11-24. **Result:** Verified open application authorization with zero ambient user_app_registrations writes across login, signup, social callbacks, MFA continuation, authorize, and consent when OPEN_APP_MEMBERSHIP_BYPASS_ENABLED is set to true. Verified that private applications always require active assignment, denying unassigned users and immediately revoking access across authorize, code exchange, refresh, UserInfo, and introspection upon revocation. Verified client_secret_post client authentication through the installed engine probe with full credential preservation and zero code or family mutations on invalid secrets. Verified runner lifecycle cleanup with explicit failed outcome reporting on database drop failures and reliable deadline timer clearing. Slice P1c administrative controls and UI remain pending.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `8431e7f26f31904a26eb7c6658981aec8acab42e`
* Worktree status: Working tree with open app membership bypass and client secret post verification
* Source scope:
  * [config/schema.ts](../../../backend/src/config/schema.ts): Typed OPEN_APP_MEMBERSHIP_BYPASS_ENABLED configuration with strict boolean parsing
  * [config/index.ts](../../../backend/src/config/index.ts): Strict boolean accessor defaulting to false in production
  * [routes/auth-token-auth.ts](../../../backend/src/routes/auth-token-auth.ts): Preserves client_secret_post body credentials for genuine engine verification
  * [routes/auth-authorize.ts](../../../backend/src/routes/auth-authorize.ts): Skips ambient registration writes for open apps when bypass is enabled
  * [routes/auth-consent.ts](../../../backend/src/routes/auth-consent.ts): Skips ambient registration writes on consent completion when bypass is enabled
  * [routes/auth-sign-in.ts](../../../backend/src/routes/auth-sign-in.ts): Skips ambient registration writes on password login when bypass is enabled
  * [routes/auth-sign-up.ts](../../../backend/src/routes/auth-sign-up.ts): Skips ambient registration writes on signup when bypass is enabled
  * [routes/auth-interceptors.ts](../../../backend/src/routes/auth-interceptors.ts): Skips ambient registration writes on social callbacks when bypass is enabled
  * [routes/auth-two-factor-context.ts](../../../backend/src/routes/auth-two-factor-context.ts): Skips ambient registration writes on MFA continuation when bypass is enabled
  * [routes/auth-token-code.ts](../../../backend/src/routes/auth-token-code.ts): Enforces private application active assignment at code exchange
  * [routes/auth-token-refresh-validate.ts](../../../backend/src/routes/auth-token-refresh-validate.ts): Enforces private application active assignment during refresh validation
  * [routes/auth-userinfo.ts](../../../backend/src/routes/auth-userinfo.ts): Enforces private application policy and denies revoked members at UserInfo
  * [routes/auth-introspect.ts](../../../backend/src/routes/auth-introspect.ts): Enforces private application policy and returns active false for revoked members
  * [utils/app-access.ts](../../../backend/src/utils/app-access.ts): Implements checkPrivateAppTokenAccess for post issuance token validation
  * [scripts/security-runner-lifecycle.ts](../../../backend/scripts/security-runner-lifecycle.ts): Clears database drop timer when settled and propagates cleanup errors
  * [scripts/run-all-security.ts](../../../backend/scripts/run-all-security.ts): Flags failed test suite outcome when cleanup fails
  * [tests/security/open-app-membership-bypass.test.ts](../../../backend/tests/security/open-app-membership-bypass.test.ts): Regression suite for open app membership bypass behavior
  * [tests/security/private-app-policy-enforcement.test.ts](../../../backend/tests/security/private-app-policy-enforcement.test.ts): Regression suite for private app active assignment and revocation
  * [tests/security/client-secret-post-auth.test.ts](../../../backend/tests/security/client-secret-post-auth.test.ts): Regression suite for client_secret_post credential preservation and verification
  * [tests/security/runner-lifecycle-cleanup.test.ts](../../../backend/tests/security/runner-lifecycle-cleanup.test.ts): Tests for cleanup failure propagation and timeout clearing
* File length: All modified and new production and test source files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `cd backend && node --import tsx tests/security/open-app-membership-bypass.test.ts`
   * Result: 4 passed, 0 failed (2542ms)
   * Open public client: Authorizes user with zero rows in user_app_registrations when bypass is enabled
   * Open confidential client: Authorizes user with zero rows in user_app_registrations when bypass is enabled
   * Backward compatibility: Writes legacy compatibility row to user_app_registrations when bypass is disabled
   * Ambient skips: Skips ambient registration writes during email signup and signin when bypass is enabled
2. Command: `cd backend && node --import tsx tests/security/private-app-policy-enforcement.test.ts`
   * Result: 3 passed, 0 failed (2381ms)
   * Private client access denied: Unassigned user is rejected with 302 access_denied redirect
   * Super admin exclusion: Super admin without explicit assignment is rejected with 302 access_denied
   * Immediate revocation propagation: Active member authorizes cleanly, then revoking registration immediately invalidates refresh exchange with HTTP 401, UserInfo with HTTP 403, and token introspection with active false
3. Command: `cd backend && node --import tsx tests/security/client-secret-post-auth.test.ts`
   * Result: 2 passed, 0 failed (1925ms)
   * Invalid secret rejection: Requests supplying invalid client_secret in POST body fail with HTTP 400 invalid_client; authorization code remains pending; legitimate exchange succeeds with HTTP 200
   * Replay protection: Replay of consumed code with wrong secret returns HTTP 400 invalid_client; existing token family remains active
4. Command: `cd backend && node --import tsx tests/security/runner-lifecycle-cleanup.test.ts`
   * Result: 5 passed, 0 failed (801ms)
   * Failure propagation: Database drop failure in coordinateSuiteCleanup is thrown and causes an explicit failed suite outcome
   * Timeout clearing: Timeout timers are cleared when database drop operations settle
5. Command: `npm run test:unit`
   * Result: All 16 unit test suites passed with 0 failures
6. Command: `npm run test:local-consumer-e2e`
   * Result: All 11 local consumer flows passed with 0 failures
7. Command: `npm run security:integration-check`
   * Result: 0 violations
8. Command: `npm run security:docs-check`
   * Result: 0 errors
9. Command: `npm run test:all-security`
   * Result: All 37 security test files passed (100 percent)
10. Prose check: Verified zero punctuation hyphens or dashes in added documentation prose


## Private token access closure and open app bypass flows verification

**Date:** 2026-11-24. **Result:** Verified authoritative active assignment requirements across all private clients, removing the isExplicit loophole and ensuring empty assignment collections deny access. Verified token derived client binding in UserInfo and rejection of query client_id substitution. Verified independent membership removal before refresh, followed by refresh denial with HTTP 401 and token family revocation. Completed open app bypass evidence for consent required authorization, MFA continuation, and social callback flows with zero ambient writes when enabled and reliable compatibility writes when disabled. Slice P1c administrative controls and UI remain pending.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `c00aa8d600b2fc101711afe841c76a685fe7410a`
* Worktree status: Working tree with private token access and bypass flows verification
* Source scope:
  * [utils/app-access.ts](../../../backend/src/utils/app-access.ts): Removes isExplicit loophole and enforces checkUserHasAppAccess for all private clients
  * [routes/auth-userinfo.ts](../../../backend/src/routes/auth-userinfo.ts): Derives target client from token claims or authoritative engine record, rejects query substitution, fails closed on missing, disabled, or ambiguous clients
  * [routes/auth-introspect.ts](../../../backend/src/routes/auth-introspect.ts): Preserves client credential error handling and validates client validity
  * [routes/auth-consent.ts](../../../backend/src/routes/auth-consent.ts): Records compatibility registration for open apps when bypass is disabled and skips writes when enabled
  * [scripts/run-all-security.ts](../../../backend/scripts/run-all-security.ts): Registers new test suites and adjusts suite timeout
  * [tests/fixtures/test-docker-mongo.ts](../../../backend/tests/fixtures/test-docker-mongo.ts): Allocates 1536m memory limit for test MongoDB container
  * [tests/security/private-token-access.test.ts](../../../backend/tests/security/private-token-access.test.ts): Regression suite for authoritative assignment, client binding, and independent membership removal
  * [tests/security/open-app-bypass-flows.test.ts](../../../backend/tests/security/open-app-bypass-flows.test.ts): Regression suite for consent, MFA continuation, and social callback bypass flows
* File length: All modified and new production and test source files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `cd backend && node --import tsx --test tests/security/private-token-access.test.ts`
   * Result: 6 passed, 0 failed (1810ms)
   * Legacy private client assignment deletion: UserInfo returns 403, introspection returns active false before refresh; refresh is denied 401 and family is revoked
   * Explicit private client assignment revocation: UserInfo returns 403, introspection returns active false before refresh; refresh is denied 401 and family is revoked
   * Client substitution rejection: Query client_id cannot override token client context
   * Target client validation: Missing, disabled, or ambiguous target clients fail closed
   * App admin assignment: Admin role granted; access denied immediately when assignment is deleted
   * Super admin exclusion: Super admin strictly excluded from private app token access
2. Command: `cd backend && node --import tsx --test tests/security/open-app-bypass-flows.test.ts`
   * Result: 3 passed, 0 failed (2421ms)
   * Consent flow: Zero ambient writes when bypass enabled; compatibility row written when disabled
   * MFA continuation: Zero ambient writes when bypass enabled; compatibility row written when disabled
   * Social callback: Zero ambient writes when bypass enabled; compatibility row written when disabled
3. Command: `npm run test:unit`
   * Result: All 16 unit test suites passed with 0 failures
4. Command: `npm run test:local-consumer-e2e`
   * Result: All 11 local consumer flows passed with 0 failures
5. Command: `npm run security:integration-check`
   * Result: 0 violations
6. Command: `npm run security:docs-check`
   * Result: 0 errors
7. Command: `npm run test:all-security`
   * Result: All 39 security test files passed (100 percent)
8. Prose check: Verified zero punctuation hyphens or dashes in added documentation prose


## UserInfo engine success handling and introspection caller authentication repair

**Date:** 2026-11-24. **Result:** Verified UserInfo engine success handling repair, clean accDoc scoping, client context audience requirement, and safe error response returns without stream reuse. Verified introspection proven caller authentication gating via installed engine probe, preserving engine rejections for wrong Basic credentials (HTTP 401) and wrong body secrets (HTTP 400 invalid_client). Verified that engine errors and outages never return active true, and verified RFC 7662 cross client isolation. Resolved backend TypeScript diagnostics across admin.ts, auth-consent.ts, and auth-userinfo.ts. Slice P1c administrative controls and UI remain pending.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `2339779de44ce1168d5b4b12ed2cfc8c079d0814`
* Worktree status: Working tree with UserInfo engine success and introspection auth repair
* Source scope:
  * [routes/auth-userinfo.ts](../../../backend/src/routes/auth-userinfo.ts): Scopes accDoc correctly in outer scope, requires validated target client audience before returning claims, returns fresh error responses preventing consumed stream errors
  * [routes/auth-introspect.ts](../../../backend/src/routes/auth-introspect.ts): Preserves engine authentication failures (Basic 401, body secret 400), fails closed on engine errors without active true responses, establishes caller authentication via engine probe before inspecting RS256 token claims
  * [routes/auth-consent.ts](../../../backend/src/routes/auth-consent.ts): Scopes tx and clientId in outer function scope of handleOAuthContinue
  * [routes/admin.ts](../../../backend/src/routes/admin.ts): Fixes Context get requestId type overload
  * [scripts/run-all-security.ts](../../../backend/scripts/run-all-security.ts): Registers userinfo-introspect-auth regression suite in security test runner
  * [tests/security/userinfo-introspect-auth.test.ts](../../../backend/tests/security/userinfo-introspect-auth.test.ts): Regression suite for UserInfo engine success and introspection caller authentication gating (11 tests)
* File length: All modified and new production and test source files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `cd backend && node --import tsx --test tests/security/userinfo-introspect-auth.test.ts`
   * Result: 11 passed, 0 failed (1025ms)
   * UserInfo engine success allows valid access for authorized member on private client (passed)
   * UserInfo engine success denies access with HTTP 403 when private client assignment is deleted (passed)
   * UserInfo engine success rejects query client substitution with HTTP 400 (passed)
   * UserInfo engine success fails closed with HTTP 401 when client context is missing (passed)
   * Introspection rejects unauthenticated caller with missing credentials with HTTP 401 (passed)
   * Introspection rejects confidential caller supplying client_id without client_secret with HTTP 401 (passed)
   * Introspection preserves engine rejection for wrong Basic credentials with HTTP 401 (passed)
   * Introspection preserves engine rejection for wrong body credentials with HTTP 400 (passed)
   * Introspection denies cross client token introspection with HTTP 200 active false (passed)
   * Introspection allows valid authenticated caller to introspect their own RS256 token with HTTP 200 active true (passed)
   * Introspection fails closed and never returns active true on engine error (passed)
2. Command: `./frontend/node_modules/.bin/tsc --project backend/tsconfig.json --noEmit`
   * Result: 0 diagnostics across entire backend source tree
3. Command: `npm run test:unit`
   * Result: All 16 unit test suites passed with 0 failures
4. Command: `npm run test:local-consumer-e2e`
   * Result: All 11 local consumer flows passed with 0 failures
5. Command: `npm run security:integration-check`
   * Result: 0 violations
6. Command: `npm run security:docs-check`
   * Result: 0 errors
7. Command: `npm run test:all-security`
   * Result: All 40 security test files passed (100 percent)
8. Prose check: Verified zero punctuation hyphens or dashes in added documentation prose
