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
| OTP start, verify, resend, finalize and wrong code zero writes | 02-04,15 | Real API + disposable DB and mail sink; concurrency workers | P2a intents, OTP limits, atomic budgets, encrypted outbox, leased worker with local test sink, authenticated callbacks, and browser UI verified locally (zero accounts or sessions created); real cloud mail provider delivery and P2b finalization remain pending |
| New user, profile, key, session and lost response recovery | 03,16 | Real engine finalization + idempotency | P2b verified email account creation, normalized unique username transaction, idempotent retry, post commit session fallback, `/register/profile`, and provisioning bypass closure verified locally (account `keyRef` remains `null` until P6 and live cloud mail provider delivery remains pending) |
| Client policy backfill and open, private matrix | 05-06,14 | Old and new schema and real consumer fixtures | P1a classification and audit (32 cases), refresh lease fencing (2 cases), P1b canonical resolution, open app bypass, token enforcement, introspection gating, and P1c admin registration, editing, and BAC P1C 01 through 06 browser acceptance checks locally verified; P2 through P9 remain pending |
| Browser A and B login, tab interleave, expiry, logout, admin purpose | 07-09,21 | Real browser plus separate backend workers | First two P3 slices (`browser_session_sets` registry, atomic sign out, request local session adapter, chooser UI, per tab OAuth selection with CAS revision, `prompt`/`max_age`/`nonce`/private issuance fences, and real two tab Playwright E2E) locally verified; dashboard contexts (`POST /api/identity/contexts`) and separate worker multi process P3 tests remain pending |
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


## Introspection authentication gating, controlled failures, and CI typecheck

**Date:** 2026-11-24. **Result:** Verified introspection caller authentication gating and response shape validation. Preserves engine rejections (HTTP 401, HTTP 400, HTTP 403) and rate limits (HTTP 429 with Retry-After header) directly. Fails closed with HTTP 502 on malformed responses or unexpected active probe outcomes. Fails closed with HTTP 503 on engine errors and thrown exceptions. Never returns active true for an otherwise valid stored JWT during engine outages or non-200 responses. Replaced misleading nonexistent client test with authentic engine outage fixture. Added declared typescript compiler dependency and separate CI typecheck command. Slice P1c administrative controls and UI remain pending.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `73ad4c26d358307f6c5ccd624bb202f8b4635b5c`
* Worktree status: Working tree with introspection authentication gating, controlled failure suite, and CI typecheck
* Source scope:
  * [routes/auth-introspect.ts](../../../backend/src/routes/auth-introspect.ts): Preserves engine non-200 responses including 403 and 429 with Retry-After, enforces object shape with boolean active, fails closed with 502 on malformed or unexpected active probe responses, fails closed with 503 on exceptions
  * [tests/security/introspect-controlled-failures.test.ts](../../../backend/tests/security/introspect-controlled-failures.test.ts): Controlled engine response regression suite exercising 403, 429 with Retry-After, 500, malformed 200, unexpected probe active true, and thrown exceptions alongside genuine engine executions (9 tests)
  * [tests/security/userinfo-introspect-auth.test.ts](../../../backend/tests/security/userinfo-introspect-auth.test.ts): Replaced misleading nonexistent client credential rejection test with authentic engine outage fixture
  * [scripts/run-all-security.ts](../../../backend/scripts/run-all-security.ts): Registers introspect-controlled-failures regression suite in runner (41 total suites)
  * [package.json](../../../backend/package.json): Added declared typescript compiler dependency and typecheck script
  * [.github/workflows/ci.yml](../../../.github/workflows/ci.yml): Added dedicated backend typecheck step before build
* File length: All modified and new production and test source files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `cd backend && node --import tsx --test tests/security/introspect-controlled-failures.test.ts`
   * Result: 9 passed, 0 failed
   * Controlled engine failures:
     * Introspection preserves engine HTTP 403 response and headers, never active true (passed)
     * Introspection preserves engine HTTP 429 rate limit response and Retry-After header, never active true (passed)
     * Introspection fails closed on engine HTTP 500 error, never active true (passed)
     * Introspection fails closed (502) on malformed engine HTTP 200 payload lacking active boolean (passed)
     * Introspection fails closed (502) when sentinel probe unexpectedly returns active true (passed)
     * Introspection fails closed (503) when engine handler throws unexpected exception (passed)
   * Genuine engine executions:
     * Introspection succeeds with genuine engine probe for valid Basic credentials (200 active true) (passed)
     * Introspection rejects with genuine engine for invalid Basic credentials (401) (passed)
     * Introspection rejects with genuine engine for invalid body credentials (400) (passed)
2. Command: `cd backend && node --import tsx --test tests/security/userinfo-introspect-auth.test.ts`
   * Result: 11 passed, 0 failed (including replaced genuine engine outage fixture)
3. Command: `npm run typecheck` (`tsc --project tsconfig.json --noEmit`)
   * Result: 0 diagnostics across entire backend source tree using declared compiler dependency
4. Command: `npm run test:unit`
   * Result: All 16 unit test suites passed with 0 failures
5. Command: `npm run test:local-consumer-e2e`
   * Result: All 11 local consumer flows passed with 0 failures
6. Command: `npm run security:integration-check`
   * Result: 0 violations
7. Command: `npm run security:docs-check`
   * Result: 0 errors
8. Command: `npm run test:all-security`
   * Result: All 41 security test files passed (100 percent)
9. Prose check: Verified zero punctuation hyphens or dashes in added documentation prose


## Slice P1c administrative client policy registration, editing, and browser acceptance

**Date:** 2026-11-25. **Result:** Verified Slice P1c server policy enforcement and administrative React UI. Default registration sets Confidential, Private, and Production while supporting all four client type and access policy combinations cleanly, including Confidential Development clients without false ambiguity. Plaintext client secrets appear once only on Confidential creation or Public to Confidential transitions and are never shown or stored for Public clients. Confidential to Public transitions require confirmation, delete stored secrets, set auth method `none`, and revoke active tokens and families. Scoped app admins attempting V2 policy field mutations receive HTTP 403 Forbidden with unchanged stored policy. Server validation blocks Migrated promotion on ambiguous records until configuration validation passes. All six browser acceptance cases (`BAC-P1C-01` through `BAC-P1C-06`) pass against a real IdP backend, MongoDB replica set container, and Vite production frontend bundle. Production P2 through P9 flows remain pending.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `4b2f0f87e3b39077544a004b2d8cb89385e13a00`
* Worktree status: Working tree with Slice P1c backend API policy enforcement, admin React UI updates, API regression suite, Playwright browser suite, and CI wiring
* Source scope:
  * [identity/client-policy.ts](../../../backend/src/identity/client-policy.ts): Exempts valid `isDev` native mapped Confidential clients from false ambiguity classification
  * [utils/client-resolver.ts](../../../backend/src/utils/client-resolver.ts): Exposes `isExplicit` and `hasClientSecret` on canonical client normalization
  * [routes/admin-client-policy-helper.ts](../../../backend/src/routes/admin-client-policy-helper.ts): Validates client policy combinations, credential transitions, secret hashing, and sensitive field stripping
  * [routes/admin-clients.ts](../../../backend/src/routes/admin-clients.ts): Enforces V2 policy defaults, Public secret exclusion, and sanitized list projections
  * [routes/admin-client-detail.ts](../../../backend/src/routes/admin-client-detail.ts): Enforces HTTP 403 scoped admin policy block, candidate `MIGRATED` gate, secret rotation, and revocation on Public downgrade
  * [routes/admin-app-config.ts](../../../backend/src/routes/admin-app-config.ts): Blocks scoped admin V2 policy field updates with HTTP 403
  * [frontend/pages/admin/AdminClients.tsx](../../../frontend/pages/admin/AdminClients.tsx): Splits applications registry with search and policy filter toolbar and table
  * [frontend/pages/admin/RegisterAppModal.tsx](../../../frontend/pages/admin/RegisterAppModal.tsx): Defaults Confidential, Private, Production controls and one time secret view
  * [frontend/pages/admin/EditAppModal.tsx](../../../frontend/pages/admin/EditAppModal.tsx): Ambiguity remediation banner, confirmation prompts, and server validated Migrated status
  * [tests/security/p1c-admin-policy-api.test.ts](../../../backend/tests/security/p1c-admin-policy-api.test.ts): HTTP API tests for policy defaults, four combinations, credential transitions, ambiguity block, and scoped admin 403 denial (5 tests)
  * [tests/e2e/p1c-admin-browser.test.ts](../../../backend/tests/e2e/p1c-admin-browser.test.ts): Real Playwright browser suite covering `BAC-P1C-01` through `BAC-P1C-06`, redirect URI blur validation, and credential transitions
* File length: All modified and new backend, frontend, and test source files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `npm run typecheck` (`tsc --project tsconfig.json --noEmit`)
   * Result: 0 diagnostics across backend source tree
2. Command: `npm --prefix frontend run lint && npm --prefix frontend run build:ui`
   * Result: 0 ESLint errors and clean Vite TypeScript build
3. Command: `npm run test:unit`
   * Result: All 16 unit test suites passed with 0 failures
4. Command: `npm run test:p1c-admin-api`
   * Result: 5 passed, 0 failed
   * Registration defaults to Confidential, Private, Production and omits secret hashes in list responses (passed)
   * Creates all four client policy combinations including Confidential Development cleanly (passed)
   * Handles Confidential to Public revocation and Public to Confidential secret generation cleanly (passed)
   * Blocks ambiguous client migration until redirect configuration passes validation (passed)
   * Rejects scoped App Admin V2 policy mutations on both admin PATCH endpoints with HTTP 403 and unchanged DB policy (passed)
5. Command: `npm run test:p1c-admin-browser`
   * Result: Exited 0; all six browser acceptance cases (`BAC-P1C-01` through `BAC-P1C-06`) plus credential transition and inline redirect blur validation checks passed against live IdP and built UI
6. Command: `npm run test:local-consumer-e2e`
   * Result: All 11 local consumer flows passed with 0 failures
7. Command: `npm run test:browser-e2e`
   * Result: All 5 Playwright browser E2E phases passed with 0 failures
8. Command: `npm run test:all-security`
   * Result: All 42 security test files passed (0 failures)
9. Command: `npm run security:integration-check && npm run security:docs-check`
   * Result: 0 violations and 0 errors
10. Prose check: Verified zero punctuation hyphens or dashes in added documentation and review prose


## Slice P1c credential transition atomicity, commit guards, and P2a slice plan

**Date:** 2026-11-25. **Result:** Verified transactional Confidential to Public credential cleanup rollback on failure, safe retry behavior, and in flight commit linearization guards across `/oauth2/authorize`, `/oauth2/consent`, `/oauth2/continue`, authorization code exchange, and refresh token rotation. Drafted the P2a pre account email verification and durable mail outbox implementation slice ([0008-p2a-mail-and-intents.md](0008-p2a-mail-and-intents.md)); P2a implementation and runtime verification remain pending with account creation deferred to P2b.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `a60afa06267bbb936a9e0224ba2a10cbc64abb72`
* Worktree status: Working tree with transactional client transition cleanup, Better Auth `verification` code revocation, monotonic client `credentialVersion` issuance fences, regression tests, P2a planning slice spec, review record, and synced ledger docs
* Source scope:
  * [routes/admin-client-transition.ts](../../../backend/src/routes/admin-client-transition.ts): Wraps `oauthClient` updates and credential/token/code/family/`verification` cleanup inside MongoDB `session.withTransaction` with fallback snapshot restore and shared response serialization
  * [routes/admin-client-detail.ts](../../../backend/src/routes/admin-client-detail.ts): Increments `credentialVersion`, records `clientSecretRevokedAt`, executes atomic transition cleanup before post commit Better Auth sync, and returns HTTP 500 cleanly if cleanup fails
  * [routes/auth-client-fence.ts](../../../backend/src/routes/auth-client-fence.ts): Enforces monotonic `credentialVersion` and client type checks on in flight authorize, code, and refresh commits across both V2 explicit and legacy client records, plus code purge on abort
  * [routes/auth-token-linearize.ts](../../../backend/src/routes/auth-token-linearize.ts): Integrates optional client issuance fence into `commitTokenIssuanceLinearization` and extends token commit failure purging to hashed token variants
  * [routes/auth-authorize.ts](../../../backend/src/routes/auth-authorize.ts), [routes/auth-consent.ts](../../../backend/src/routes/auth-consent.ts), [routes/auth-token-code.ts](../../../backend/src/routes/auth-token-code.ts), [routes/auth-token-refresh.ts](../../../backend/src/routes/auth-token-refresh.ts), [routes/auth-token-refresh-validate.ts](../../../backend/src/routes/auth-token-refresh-validate.ts), [utils/pkce.ts](../../../backend/src/utils/pkce.ts), [routes/auth-keys.ts](../../../backend/src/routes/auth-keys.ts): Propagates `clientType`, `credentialVersion`, and `clientSecretRevokedAt` transition guards and `before_authorize_commit` test barrier
  * [tests/security/p1c-credential-transition.test.ts](../../../backend/tests/security/p1c-credential-transition.test.ts): Regression suite verifying cleanup failure rollback + safe retry + idempotent retry, plus concurrent Confidential to Public abort on code exchange, refresh rotation, and authorize issuance (4 tests)
  * [scripts/run-all-security.ts](../../../backend/scripts/run-all-security.ts): Registers transition regression suite (43 total suites)
  * [0008-p2a-mail-and-intents.md](0008-p2a-mail-and-intents.md): Drafted P2a implementation slice specification (Planned; implementation remains pending)
* File length: All modified and new production and test source files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `npm run typecheck` (`tsc --project tsconfig.json --noEmit`)
   * Result: 0 diagnostics across backend source tree
2. Command: `npm run test:p1c-credential-transition`
   * Result: 4 passed, 0 failed
   * Cleanup failure rolls back Confidential to Public preserving policy/credentials and completes safely on retry plus idempotent repeat (passed)
   * In flight authorization code exchange fails closed cleanly when Confidential to Public commits before issuance fence (passed)
   * In flight refresh token rotation fails closed cleanly when Confidential to Public commits before issuance fence (passed)
   * In flight authorize request fails closed without returning authorization code when Confidential to Public commits mid flow (passed)
3. Command: `npm run test:p1c-admin-api`
   * Result: 5 passed, 0 failed
4. Command: `npm run test:p1c-admin-browser`
   * Result: Passed all six Playwright browser acceptance checks (`BAC-P1C-01` through `BAC-P1C-06`)
5. Command: `npm run test:unit`
   * Result: All 16 unit test suites passed, 0 failed (including `runtime-resilience` and `refresh-lease-fencing`)
6. Command: `npm run test:all-security`
   * Result: All 43 security test files passed, 0 failed
7. Command: `npm run security:integration-check && npm run security:docs-check`
   * Result: 0 violations and 0 errors


## Slice P2a email verification intents, atomic budgets, encrypted outbox, worker, and UI

**Date:** 2026-11-25. **Result:** Verified Slice P2a pre account email verification backend and React UI against shared Docker MongoDB (`rs0`), Hono APIs, Playwright Chromium, and the loopback `test_sink` mail transport. Both failed and successful OTP verifications create zero `user`, `account`, `session`, `oauthConsent`, `user_app_registrations`, `oauthAccessToken`, or `oauthRefreshToken` documents. Live cloud mail provider execution (SES/SMTP) and P2b account/session finalization remain pending.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `238d125f4e7414a4f8e2302b32362292268e8ee2`
* Worktree status: Working tree with typed P2a configuration, MongoDB collection indexes, HMAC/AEAD cryptography, transactional budget reservation, encrypted outbox and leased fenced worker, authenticated bounce/complaint callback route, `/api/identity/*` registration endpoints, `/register` and `/register/verify` UI routes, P2a API/worker/browser tests, and review record
* Evidence distinction:
  * Local sink & loopback transport (`IDENTITY_MAIL_TRANSPORT=test_sink`, in process sink and local HTTP sink server): Exercised and verified in API, worker, and Playwright browser runs
  * Production cloud provider (`ses`, `approved_smtp`, external DNS DKIM/SPF/DMARC): Config and authenticated client scaffolding implemented only; live provider sending remains pending
* Source scope:
  * [config/schema.ts](../../../backend/src/config/schema.ts) & [config/index.ts](../../../backend/src/config/index.ts): Typed `IDENTITY_*` config defaulting `IDENTITY_REGISTRATION_MODE` to `disabled` and validating production key/transport bounds
  * [db/indexes.ts](../../../backend/src/db/indexes.ts): Indexes for `registration_intents`, `mail_outbox`, `mail_budgets`, `mail_suppressions`, and `mail_callback_events`
  * [identity/registration-crypto.ts](../../../backend/src/identity/registration-crypto.ts) & [identity/registration-budgets.ts](../../../backend/src/identity/registration-budgets.ts): HMAC lookup/OTP/proof digests, AES256GCM mail payload and contact encryption, and transactional send/verify budget enforcement
  * [identity/mail-service.ts](../../../backend/src/identity/mail-service.ts) & [identity/mail-webhooks.ts](../../../backend/src/identity/mail-webhooks.ts): `EmailSender` with `test_sink`, leased worker with monotonic fencing, deadline/generation/suppression checks, 3 attempt bounded retries including `TimeoutError` handling, payload scrubbing, and signed callback replay/suppression handler
  * [routes/identity.ts](../../../backend/src/routes/identity.ts), [routes/identity-registration-shared.ts](../../../backend/src/routes/identity-registration-shared.ts), [routes/identity-registration.ts](../../../backend/src/routes/identity-registration.ts), [routes/identity-registration-verify.ts](../../../backend/src/routes/identity-registration-verify.ts), [middleware/cors.ts](../../../backend/src/middleware/cors.ts), [app.ts](../../../backend/src/app.ts): Same origin CSRF/no store `/api/identity/*` endpoints and conditional `HttpOnly` proof issuance
  * [frontend/pages/Register.tsx](../../../frontend/pages/Register.tsx), [frontend/pages/VerifyEmail.tsx](../../../frontend/pages/VerifyEmail.tsx), [frontend/src/App.tsx](../../../frontend/src/App.tsx): Default off gated `/register` and `/register/verify` screens stopping cleanly at verified proof state
  * [tests/security/p2a-intents-and-otp.test.ts](../../../backend/tests/security/p2a-intents-and-otp.test.ts), [tests/security/p2a-outbox-worker-and-callbacks.test.ts](../../../backend/tests/security/p2a-outbox-worker-and-callbacks.test.ts), [tests/e2e/p2a-registration-browser.test.ts](../../../backend/tests/e2e/p2a-registration-browser.test.ts), [tests/fixtures/browser-harness.ts](../../../backend/tests/fixtures/browser-harness.ts), [scripts/run-all-security.ts](../../../backend/scripts/run-all-security.ts), [.github/workflows/ci.yml](../../../.github/workflows/ci.yml)
* File length: All new and modified source and test files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `npm run typecheck` (`tsc --project tsconfig.json --noEmit`)
   * Result: 0 diagnostics across backend source tree
2. Command: `npm --prefix frontend run lint && npm --prefix frontend run build:ui`
   * Result: 0 ESLint errors and clean Vite TypeScript build
3. Command: `npm run test:p2a-intents`
   * Result: 3 passed, 0 failed (default off gate, same origin CORS rejection, missing browser cookie rejection, store failure 503 with 0 intents/outbox/sends, malformed OTP attempt consumption, 5 attempt exhaustion, inline expiry, resend invalidating gen 1 code and prior proof without extending intent expiry, concurrent verify minting 1 proof in `HttpOnly` cookie, 0 identities/sessions across failed and successful cases)
4. Command: `npm run test:p2a-outbox`
   * Result: 3 passed, 0 failed (outbox tx failure rolling back budget and intent, `Idempotency-Key` dedup, lost lease recovery with fence bump, 3 retry bound reusing single key + dead letter payload scrub, inline deadline drop, signed bounce callback replay/forged check and silent suppression)
5. Command: `npm run test:p2a-browser`
   * Result: Passed against built UI, live backend, shared Docker MongoDB, and loopback HTTP mail sink (default off `/register` block + `/register` -> `/register/verify` with wrong and valid OTP assertions leaving 0 user/account/session/token/membership documents)
6. Command: `npm run test:unit && npm run test:local-consumer-e2e && npm run test:all-security`
   * Result: All 16 unit suites passed, all 11 local consumer E2E flows passed, and all 45 security suites passed with 0 failures
7. Command: `npm run security:integration-check && npm run security:docs-check`
   * Result: 0 violations and 0 errors


## Slice P2b verified account completion, profile UI, and bypass closure

**Date:** 2026-11-25. **Result:** Verified Slice P2b transactional verified account creation, `/register/profile` completion screen, `/register/verify` continuation link, idempotent recovery, post commit ordinary session establishment/fallback, and unverified provisioning bypass closure in `verified` mode against shared Docker MongoDB (`rs0`), Redis, Hono APIs, Playwright Chromium, and the loopback `test_sink` transport. `IDENTITY_REGISTRATION_MODE` defaults to `disabled`; per account encryption (`keyRef`), live cloud mail delivery (SES/SMTP), and P3 multi account sessions remain pending.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `71802ebc7bcb1c7fdd1ad2bcfb5a56dc05508046`
* Worktree status: Working tree with transactional account completion service and Better Auth transaction engine, `POST /api/identity/registration/complete`, proof bound `POST /api/identity/username/check`, MongoDB collection/unique indexes, verified creation hook guard and legacy signup/admin bypass closures, `/register/profile` and `/register/verify` UI updates, P2b security/bypass/browser suites, review record, and synced ledger docs
* Source scope:
  * [identity/registration-context.ts](../../../backend/src/identity/registration-context.ts): `AsyncLocalStorage` verified creation boundary context
  * [identity/registration-crypto.ts](../../../backend/src/identity/registration-crypto.ts): Username syntax normalization and keyed `username-lookup-v1` HMAC computation
  * [identity/registration-tx-engine.ts](../../../backend/src/identity/registration-tx-engine.ts): Transaction enabled Better Auth engine with pre created schema indexes and atomic replica set transaction execution
  * [identity/registration-complete.ts](../../../backend/src/identity/registration-complete.ts): Pre hash proof/syntax validation, idempotency replay handling, concurrent write conflict recovery, and post commit `signInEmail` ordinary session establishment with sign in fallback
  * [routes/identity-registration-complete.ts](../../../backend/src/routes/identity-registration-complete.ts) & [routes/identity.ts](../../../backend/src/routes/identity.ts): Same origin CSRF protected `POST /api/identity/registration/complete` and `POST /api/identity/username/check` handlers
  * [db/indexes.ts](../../../backend/src/db/indexes.ts), [routes/auth-sign-up.ts](../../../backend/src/routes/auth-sign-up.ts), [routes/auth.ts](../../../backend/src/routes/auth.ts), [utils/auth.ts](../../../backend/src/utils/auth.ts): Unique partial lookup indexes, `/api/auth/sign-up/email` and `/api/auth/admin/create-user` gates, and `databaseHooks.user.create.before` verified guard
  * [frontend/pages/CompleteRegistration.tsx](../../../frontend/pages/CompleteRegistration.tsx), [frontend/pages/VerifyEmail.tsx](../../../frontend/pages/VerifyEmail.tsx), [frontend/src/App.tsx](../../../frontend/src/App.tsx): Default off gated `/register/profile` UI and `/register/verify` continuation link
  * [tests/security/p2b-account-completion.test.ts](../../../backend/tests/security/p2b-account-completion.test.ts), [tests/security/p2b-provisioning-bypasses.test.ts](../../../backend/tests/security/p2b-provisioning-bypasses.test.ts), [tests/e2e/p2b-complete-browser.test.ts](../../../backend/tests/e2e/p2b-complete-browser.test.ts), [scripts/run-all-security.ts](../../../backend/scripts/run-all-security.ts), [.github/workflows/ci.yml](../../../.github/workflows/ci.yml)
* File length: All new and modified source and test files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend` (`tsc --project tsconfig.json --noEmit`)
   * Result: 0 diagnostics across backend source tree
2. Command: `npm --prefix frontend run lint && npm --prefix frontend run build:ui`
   * Result: 0 ESLint errors and clean Vite TypeScript build
3. Command: `npm run test:p2b-complete`
   * Result: 4 test groups passed, 0 failed (atomic commit of derived intent email user, credential, profile, lookups, non PII audit, and outbox event with ordinary session; zero password hashing before valid browser/proof/syntax checks and commit time proof expiry recheck; normalized username collision preserving proof plus two intent concurrent username race returning `ERR_USERNAME_TAKEN` and duplicate email rejection; mid transaction rollback leaving zero partial state, idempotent `Idempotency-Key` replay without duplicate accounts or sessions, and post commit session failure survival)
4. Command: `npm run test:p2b-bypasses`
   * Result: 2 test groups passed, 0 failed (default `disabled` backward compatibility + `/complete` 403 gate; `verified` mode blocks `/api/auth/sign-up/email`, direct `authProvider.api.signUpEmail`, `/api/auth/admin/create-user`, simulated social auto provisioning, and forged `invitationHandle` escalation while preserving existing user sign in)
5. Command: `npm run test:p2b-browser && npm run test:p2a-browser`
   * Result: Passed against built UI, live backend, shared Docker MongoDB, and loopback HTTP mail sink (default off `/register/profile` block plus `/register` to `/register/verify` to `/register/profile` with username collision retry and ordinary user verification leaving 0 memberships)
6. Command: `npm run test:unit && npm run test:local-consumer-e2e && npm run test:all-security && npm run build && npm run build:node`
   * Result: All 16 unit suites passed, all 11 local consumer E2E flows passed, all 47 security suites passed with 0 failures, and Lambda/Node production bundles built cleanly
7. Command: `npm run security:integration-check && npm run security:docs-check`
   * Result: 0 violations and 0 errors


## Slice P3 browser session registry and request local session adapter

**Date:** 2026-11-25. **Result:** Verified the first P3 slice (`browser_session_sets` server registry, opaque entry handles, request local session adapter, single account browser sign out/removal, 10 account non evicting capacity cap, and ordinary sign in / verified registration session wiring) against shared Docker MongoDB (`rs0`), real Better Auth engine sessions, Playwright browser E2E, local consumer OAuth E2E, and security/documentation contract checks. Chooser UI, OAuth transaction account selection, dashboard contexts, and multi tab browser interleaving remain pending for the next P3 slice.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `5947aad15922e1c291976d3ca425cac5ba6c5a90`
* Worktree status: Working tree with `browser_session_sets` registry and indexes, request local [session-adapter.ts](../../../backend/src/identity/session-adapter.ts), `/api/identity/accounts*` endpoints, ordinary login / verified registration browser session enrollment, review record, and updated ledger docs
* Source scope:
  * [identity/browser-session-registry.ts](../../../backend/src/identity/browser-session-registry.ts): `browser_session_sets` storage (digested proof handles, monotonic CAS version rotation, 10 account capacity enforcement without silent eviction, live status projection, single entry sign out and signed out removal) and `__Host-swyra-browser` / `swyra-browser` cookie attributes
  * [identity/session-adapter.ts](../../../backend/src/identity/session-adapter.ts): Multi layer revalidation (browser proof, active entry status, `tokenVersion`, engine `session` expiry/revocation, real `engine.api.getSession` with cache disabled), request local authorize/consent dispatch via `selected-engine-session.ts`, and `attachOrdinaryBrowserSessionToResponse`
  * [routes/identity-accounts.ts](../../../backend/src/routes/identity-accounts.ts) & [routes/identity.ts](../../../backend/src/routes/identity.ts): `GET /api/identity/accounts`, `POST /api/identity/accounts/sign-out`, `POST /api/identity/accounts/remove` under CSRF and `no-store` headers
  * [routes/auth-sign-in.ts](../../../backend/src/routes/auth-sign-in.ts), [identity/registration-complete.ts](../../../backend/src/identity/registration-complete.ts), [routes/identity-registration-complete.ts](../../../backend/src/routes/identity-registration-complete.ts), [db/indexes.ts](../../../backend/src/db/indexes.ts)
  * [tests/security/p3-browser-session-registry.test.ts](../../../backend/tests/security/p3-browser-session-registry.test.ts), [tests/security/p3-session-adapter-isolation.test.ts](../../../backend/tests/security/p3-session-adapter-isolation.test.ts), [scripts/run-all-security.ts](../../../backend/scripts/run-all-security.ts), [package.json](../../../package.json), [backend/package.json](../../../backend/package.json)
* File length: All modified and added source and test files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm --prefix frontend run lint && npm --prefix frontend run build:ui`
   * Result: 0 TypeScript diagnostics, 0 ESLint errors, clean Vite build
2. Command: `npm run test:p3-registry`
   * Result: 3 test groups passed, 0 failed (account A verified registration + account B login coexistence, proof rotation, digest only storage, zero leaked session tokens or emails, signing out or expiring A preserves B, invalid proofs fail closed, 10 account capacity blocks 11th without silent eviction until remove)
3. Command: `npm run test:p3-adapter`
   * Result: 2 test groups passed, 0 failed (request local OAuth authorize/consent dispatch ignores conflicting ambient cookies, revalidates `tokenVersion` and engine session while preserving B, enforces `__Host-swyra-browser` production cookie attributes and preserves admin/MFA gates)
4. Command: `npm --prefix backend run test:p0-sessions && npm --prefix backend run test:p0-transactions && npm run test:p2b-complete && npm run test:p2b-bypasses && npm run test:p2b-browser && npm run test:browser-e2e && npm run test:local-consumer-e2e && npm run test:unit`
   * Result: All P0, P2b (completion, bypasses, and Playwright browser), general Playwright OAuth E2E, local consumer OAuth E2E, and 16 unit suites passed with 0 failures
5. Command: `npm run test:all-security && npm run security:integration-check && npm run security:docs-check`
   * Result: All 49 security suites passed (49 passed, 0 failed), 0 integration lint violations, and 0 documentation consistency errors


## Slice P3 account chooser UI and per tab OAuth selection

**Date:** 2026-11-25. **Result:** Verified Slice P3 account chooser UI, atomic single account browser sign out, per tab `oauth_transactions` selection binding (`POST /api/identity/accounts/select`) with CAS revisions, request local authorize/consent dispatch, issuance commit session revalidation, and real two tab Playwright browser interleaving against shared Docker MongoDB (`rs0`), real Better Auth engine sessions, local consumer OAuth E2E, and security/documentation checks. P3 remains open for dashboard contexts (`POST /api/identity/contexts`) and separate worker P3 coverage.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `3211afa20129ac66a8c527fa94cc30d017abbe6d`
* Worktree status: Working tree with transactional `signOutBrowserEntry`, extended `oauth_transactions` selection binding, `POST /api/identity/accounts/select`, OIDC `prompt`/`max_age`/`nonce` chooser/consent enforcement, `AccountChooser.tsx`, updated `SignIn.tsx` and `Consent.tsx`, P3 selection and two tab browser suites, CI trigger, review record, and ledger updates
* File length: All modified and new backend source and test files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm --prefix frontend run lint && npm --prefix frontend run build:ui`
   * Result: 0 TypeScript diagnostics, 0 ESLint errors, clean Vite TypeScript build
2. Command: `npm run test:p3-selection`
   * Result: 2 test groups passed, 0 failed (atomic transaction consistency on concurrent sign out + idempotent retry, CAS revision conflicts, interleaved two tab authorize/consent/token exchange, `prompt=none` / `select_account` / `private` access checks, revoked selection blocked at consent)
3. Command: `npm run test:p3-two-tab`
   * Result: Real Playwright two tab browser E2E passed (sign in A, add B via chooser preserving A, interleaved two tab chooser -> consent -> PKCE code exchange yielding exact `sub` and `nonce`, sign out A from chooser preserving B)
4. Command: `npm run test:p3-registry && npm run test:p3-adapter && npm run test:browser-e2e && npm run test:local-consumer-e2e`
   * Result: All P3 registry/adapter suites, general Playwright browser OAuth E2E, and 11 local consumer OAuth E2E flows passed with 0 failures
5. Command: `npm run test:all-security && npm run security:integration-check && npm run security:docs-check`
   * Result: All 50 security suites passed (50 passed, 0 failed), 0 integration contract violations, and 0 documentation consistency errors


## Slice P3 chooser session binding and issuance commit guard

**Date:** 2026-11-25. **Result:** Verified that OAuth authorization and consent flows resolve authTime and MFA metadata directly from the exact engine session validated by the session adapter without fallback to user level session scans or current time. Denied stale and unproven freshness requests for both max_age and prompt=login. Implemented durable shared commit guards serializing code issuance with selected session revocation and transaction reselection across all code issuing paths. Verified against separate backend worker processes on shared Docker MongoDB (`rs0`), real two tab Playwright browser coverage, local consumer OAuth E2E, and repository security and documentation checks. Dashboard contexts remain pending for the next slice to complete P3.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `23ca91c4dfa7792237f5f80594cce91e37a112f7`
* Worktree status: Working tree with exact engine session metadata extraction in `session-adapter.ts`, freshness enforcement in `oauth-selection.ts`, durable commit guard `session-issuance-fence.ts`, issuance integration in `auth-client-fence.ts` and `auth-consent.ts`, separate process concurrency test harness `p3-external-worker.ts`, security test suite `p3-chooser-session-binding.test.ts`, review record, and updated ledger documentation
* File length: All modified and new backend source and test files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm --prefix frontend run lint && npm --prefix frontend run build:ui`
   * Result: 0 TypeScript diagnostics, 0 ESLint errors, clean Vite production build
2. Command: `npm run test:p3-binding`
   * Result: 3 test groups passed, 0 failed (enforces freshness against two sessions of the same user and rejects unproven freshness without fallback, invalidates pending issuance when separate process commits sign out on shared MongoDB, invalidates pending issuance when separate process commits transaction reselection with code purge)
3. Command: `npm run test:p3-two-tab`
   * Result: Real Playwright two tab browser E2E passed (interleaved chooser selection, consent, PKCE code exchange verifying bound subject and nonce, sign out A preserving B)
4. Command: `npm run test:p3-selection && npm run test:p3-registry && npm run test:p3-adapter && npm run test:browser-e2e && npm run test:local-consumer-e2e`
   * Result: All P3 selection/registry/adapter suites, general Playwright browser OAuth E2E, and 11 local consumer OAuth E2E flows passed with 0 failures
5. Command: `npm run test:all-security && npm run security:integration-check && npm run security:docs-check`
   * Result: All 51 security suites passed (51 passed, 0 failed), 0 integration contract violations, and 0 documentation consistency errors


## Slice P3 OAuth continuation session binding

**Date:** 2026-11-25. **Result:** Verified that `/api/auth/oauth2/continue` reuses the request local session adapter whenever the OAuth transaction has a selected account, using the same validated subject and session for policy checks, engine dispatch, and code finalization with the original selection revision, while failing closed on stale or revoked selections and preserving legacy continuation for transactions without a selection. Dashboard contexts remain pending for the next slice to complete P3.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `a7d3830a1d83a0c63e89e6d141a3562bc0040a12`
* Worktree status: Working tree with shared `resolveConsentOrContinueSession` in `auth-consent.ts`, `/api/auth/oauth2/continue` allowlist in `selected-engine-session.ts`, route level suite `p3-continuation-session-binding.test.ts`, review record, and updated ledger documentation
* File length: All modified and new backend source and test files are strictly under 300 lines

### Verification commands and execution evidence

1. Command: `npm run test:p3-continuation`
   * Result: 3 test groups passed, 0 failed (selected subject used for private app policy check despite conflicting ambient cookie, stale/revoked selection fails closed with 401 `ERR_SESSION_REVOKED`, legacy continuation without selection preserved)
2. Command: `npm run typecheck:backend && npm run test:p3-binding && npm run test:p3-two-tab && npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 0 TypeScript diagnostics, 3/3 P3 binding tests passed, Playwright two tab browser E2E passed, 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P3 owner dashboard contexts

**Date:** 2026-11-25. **Result:** Verified `POST /api/identity/contexts`, `GET /api/identity/contexts/me`, and `POST /api/identity/contexts/renew` for ordinary owner dashboards, plus tab memory frontend wiring (`/account`) and tightened continuation assertions. Two dashboard tabs stay pinned to their respective accounts, signing out A invalidates A's context while B remains usable, expiry and parent session bounded renewal are enforced, wrong purpose and conflicting browser proofs are rejected, and admin routes reject owner contexts. P3 acceptance criteria are met; P4 MFA work and P5 full dashboard features remain separate.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `646189e00249df4ddf958e29f6c5f92ff055a066`
* Worktree status: Working tree with `owner-contexts.ts`, `identity-contexts.ts`, `identity_contexts` TTL/unique indexes, `identityContext.ts`, `AccountDashboard.tsx`, `p3-owner-dashboard-contexts.test.ts`, tightened `p3-continuation-session-binding.test.ts`, review record, and updated ledger documentation

### Verification commands and execution evidence

1. Command: `npm --prefix frontend run lint && npm --prefix frontend run build:ui && npm run typecheck:backend`
   * Result: 0 ESLint errors, clean Vite build, 0 TypeScript diagnostics
2. Command: `npm run test:p3-contexts`
   * Result: 2 test groups passed, 0 failed (two tabs pinned to A and B, admin route rejection, sign out A invalidates A while B stays usable, expiry, parent session bounded renewal, wrong purpose, and browser mismatch)
3. Command: `npm run test:p3-continuation && npm run test:p3-two-tab && npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 3/3 continuation tests passed, Playwright two tab browser E2E passed, 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P3 dashboard browser evidence and Slice P4 admin MFA start

**Date:** 2026-11-25. **Result:** Verified `/account` in a real two tab Playwright browser test (tabs pinned to A and B, zero persistent storage, reload clears in memory handle, sign out A leaves B usable) and verified P4 admin TOTP enrollment, setup only authority, app admin assignment boundaries, and 15 minute step up freshness for both platform and app admins. P3 is complete; P4 remains open for invitation lifecycle, recovery changes, and optional user TOTP.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `45d693ac793c00bd4393988161e6e7b3a7191597`
* Worktree status: Working tree with `p3-account-dashboard-browser.test.ts`, `p4-admin-mfa-enrollment.test.ts`, package scripts, review record, and updated ledger documentation

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p3-dashboard-browser`
   * Result: 0 TypeScript diagnostics; Playwright `/account` two tab E2E passed
2. Command: `npm run test:p4-admin-mfa`
   * Result: 2 test groups passed, 0 failed (platform admin setup only authority, TOTP enrollment, and step up freshness; app admin setup only authority, TOTP enrollment, and assignment isolation)
3. Command: `npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P4 admin MFA five minute freshness alignment and CI coverage

**Date:** 2026-11-25. **Result:** Aligned `requireRecentMfa` in `admin-mfa.ts` to 5 minutes (`5 * 60 * 1000` ms) with updated error copy, verified deterministic inside (`4m30s`) and outside (`5m10s`) 5 minute checks for both platform and app admins, and added `test:p3-dashboard-browser` to `.github/workflows/ci.yml`. P3 is complete; P4 remains open for invitations, recovery, and optional user TOTP.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `aa4315615cd46577fd4ee7a4c1efc442f567c9ef`
* Worktree status: Working tree with 5 minute `requireRecentMfa` in `admin-mfa.ts`, deterministic 5 minute boundary tests in `p4-admin-mfa-enrollment.test.ts`, `test:p3-dashboard-browser` in `.github/workflows/ci.yml`, review record, and updated ledger/roadmap

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 2 test groups passed, 0 failed (inside/outside 5 minute boundary for both platform and app admins)
2. Command: `npm run test:p3-dashboard-browser && npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: Playwright `/account` two tab E2E passed, 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P4 invitation claim consistency and local system walkthrough

**Date:** 2026-11-25. **Result:** Wrapped `claimPrivateAppInvitation` in a MongoDB replica set transaction so invitation consumption and membership or `app-admin` assignment commit together, verified failed grant rollback and retryability, verified existing `admin` role preservation and TOTP enforcement for `app-admin` access, and ran the full local system walkthrough. All flows (OTP signup, two account selection, `/account` dashboard, open/private app login, and invite claim) passed in automated Playwright and protocol suites against shared Docker MongoDB (`rs0`); no separate manual browser click through was performed, and invitation delivery used `localInviteMailSink` rather than live SMTP. P3 is complete; P4 remains open for recovery and optional user TOTP.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `0d0078e3a08acc0f932e06882ae3a7b012a576ae`
* Worktree status: Working tree with transactional `claimPrivateAppInvitation` in `app-invitations.ts`, rollback and role preservation tests in `p4-private-app-invitations.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-invitations && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 3/3 invitation tests passed (including failed grant rollback, retryability, privileged role preservation, and TOTP gating); 2/2 admin MFA tests passed
2. Command: `npm run test:p2b-browser && npm run test:p3-two-tab && npm run test:p3-dashboard-browser && npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: P2b registration browser E2E, P3 two tab chooser E2E, P3 `/account` dashboard E2E, 11/11 local consumer E2E flows, integration contract check, and docs consistency check all passed


## Slice P4 backup code recovery and mandatory invite claim transaction

**Date:** 2026-11-25. **Result:** Enforced mandatory MongoDB transactions in `claimPrivateAppInvitation` (`503 ERR_TRANSACTION_REQUIRED` if unavailable) and implemented `POST /api/identity/recovery/backup-code` reusing Better Auth's TOTP engine with rate limiting, single use backup code consumption, atomic invalidation of old elevated sessions and `tokenVersion` bump, setup only recovery authority, and fresh TOTP restoration preserving exact role and `scopedClientId`. P3 is complete (with CI evidence); P4 remains open for operator lost factor recovery custody and optional user TOTP.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `d46ffe3ef48feedf17eadd3425540003b7908b30`
* Worktree status: Working tree with mandatory transaction guard in `app-invitations.ts`, `identity-recovery.ts`, `p4-backup-code-recovery.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-recovery && npm run test:p4-invitations && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 2/2 recovery tests passed (concurrent single use backup code consumption, old session invalidation, setup only authority, fresh TOTP restoration preserving `app-admin` scope, and rate limiting); 3/3 invitation tests passed; 2/2 admin MFA tests passed
2. Command: `npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P4 independent account and IP recovery rate limits

**Date:** 2026-11-25. **Result:** Enforced independent trusted IP (`limit: 10`) and normalized email digest (`limit: 5`) rate limits before password verification on `POST /api/identity/recovery/backup-code` via `createRateLimiter` (`sensitivity: "auth"`), verified shared `rate_limits` counters across accounts and IPs including unknown accounts, and verified fail closed (`429`) behavior under simulated store outage. Optional user TOTP and operator lost factor recovery custody remain open in P4.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `926b5c547e08121acfda5f245f11e55e8741cfe7` (CI run: `https://github.com/SGOD-pro/OAuth2.1/actions/runs/45625840490`)
* Worktree status: Working tree with `keyFn` in `rate-limit.ts`, `digestToken` account key in `identity-recovery.ts`, cross IP unknown account, cross account IP, and store outage tests in `p4-backup-code-recovery.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-recovery && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 4/4 recovery tests passed; 2/2 admin MFA tests passed
2. Command: `npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P4 backup code recovery atomicity and shared rate limiting

**Date:** 2026-11-25. **Result:** Closed P4 backup code recovery failure and rate limit gaps by moving backup code consumption, old session invalidation, `tokenVersion` bump, `twoFactorEnabled: false` reset, and restricted recovery session issuance into a single MongoDB replica set transaction, replacing the local counter with shared `createRateLimiter` IP and account limits (`sensitivity: "auth"`), and using configured session cookie attributes (`Secure` in production). Optional user TOTP and operator lost factor recovery custody remain open.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `4f5cc32b33219c4518efd0b3ce194d0ad0f84fa0`
* Worktree status: Working tree with transactional `identity-recovery.ts`, shared `recoveryIpRateLimit` and `recoveryAccountRateLimit`, failed commit and platform admin recovery tests in `p4-backup-code-recovery.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-recovery && npm run test:p4-invitations && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 3/3 recovery tests passed (concurrent single use, rate limiting, failed commit preservation and platform admin restoration); 3/3 invitation tests passed; 2/2 admin MFA tests passed
2. Command: `npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P4 independent account and IP recovery rate limits

**Date:** 2026-11-25. **Result:** Enforced independent trusted IP (`limit: 10`) and normalized email digest (`limit: 5`) rate limits before password verification on `POST /api/identity/recovery/backup-code` via `createRateLimiter` (`sensitivity: "auth"`), verified shared `rate_limits` counters across accounts and IPs including unknown accounts, and verified fail closed (`429`) behavior under simulated store outage. Optional user TOTP and operator lost factor recovery custody remain open in P4.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `926b5c547e08121acfda5f245f11e55e8741cfe7` (CI run: `https://github.com/SGOD-pro/OAuth2.1/actions/runs/45625840490`)
* Worktree status: Working tree with `keyFn` in `rate-limit.ts`, `digestToken` account key in `identity-recovery.ts`, cross IP unknown account, cross account IP, and store outage tests in `p4-backup-code-recovery.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-recovery && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 4/4 recovery tests passed; 2/2 admin MFA tests passed
2. Command: `npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P4 verified private app invitations

**Date:** 2026-11-25. **Result:** Implemented and verified private app invitation issuance (`POST /api/admin/clients/:clientId/invitations`), revocation (`DELETE /api/admin/clients/:clientId/invitations/:inviteId`), and atomic single use claim (`POST /api/identity/invitations/claim`) with local mail sink delivery, mailbox proof and authenticated account checks, inviter role ceilings, 5 minute MFA gating, and tightened fresh MFA assertions (`404` exact status). P3 is complete; P4 remains open for recovery and optional user TOTP.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `d45d5d0167b3fa46800863661ac3a74de23814e1`
* Worktree status: Working tree with `app-invitations.ts`, `admin-invitations.ts`, `identity-invitations.ts`, `app_invitations` indexes, `p4-private-app-invitations.test.ts`, tightened `p4-admin-mfa-enrollment.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-invitations && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 2/2 invitation tests passed (role ceilings, mailbox proof, concurrent single use claim, revocation, expiry, role separation); 2/2 admin MFA tests passed
2. Command: `npm run test:p3-dashboard-browser && npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: Playwright `/account` two tab E2E passed, 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P4 invitation claim consistency and local system walkthrough

**Date:** 2026-11-25. **Result:** Wrapped `claimPrivateAppInvitation` in a MongoDB replica set transaction so invitation consumption and membership or `app-admin` assignment commit together, verified failed grant rollback and retryability, verified existing `admin` role preservation and TOTP enforcement for `app-admin` access, and ran the full local system walkthrough. All flows (OTP signup, two account selection, `/account` dashboard, open/private app login, and invite claim) passed in automated Playwright and protocol suites against shared Docker MongoDB (`rs0`); no separate manual browser click through was performed, and invitation delivery used `localInviteMailSink` rather than live SMTP. P3 is complete; P4 remains open for recovery and optional user TOTP.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `0d0078e3a08acc0f932e06882ae3a7b012a576ae`
* Worktree status: Working tree with transactional `claimPrivateAppInvitation` in `app-invitations.ts`, rollback and role preservation tests in `p4-private-app-invitations.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-invitations && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 3/3 invitation tests passed (including failed grant rollback, retryability, privileged role preservation, and TOTP gating); 2/2 admin MFA tests passed
2. Command: `npm run test:p2b-browser && npm run test:p3-two-tab && npm run test:p3-dashboard-browser && npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: P2b registration browser E2E, P3 two tab chooser E2E, P3 `/account` dashboard E2E, 11/11 local consumer E2E flows, integration contract check, and docs consistency check all passed


## Slice P4 backup code recovery and mandatory invite claim transaction

**Date:** 2026-11-25. **Result:** Enforced mandatory MongoDB transactions in `claimPrivateAppInvitation` (`503 ERR_TRANSACTION_REQUIRED` if unavailable) and implemented `POST /api/identity/recovery/backup-code` reusing Better Auth's TOTP engine with rate limiting, single use backup code consumption, atomic invalidation of old elevated sessions and `tokenVersion` bump, setup only recovery authority, and fresh TOTP restoration preserving exact role and `scopedClientId`. P3 is complete (with CI evidence); P4 remains open for operator lost factor recovery custody and optional user TOTP.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `d46ffe3ef48feedf17eadd3425540003b7908b30`
* Worktree status: Working tree with mandatory transaction guard in `app-invitations.ts`, `identity-recovery.ts`, `p4-backup-code-recovery.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-recovery && npm run test:p4-invitations && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 2/2 recovery tests passed (concurrent single use backup code consumption, old session invalidation, setup only authority, fresh TOTP restoration preserving `app-admin` scope, and rate limiting); 3/3 invitation tests passed; 2/2 admin MFA tests passed
2. Command: `npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P4 independent account and IP recovery rate limits

**Date:** 2026-11-25. **Result:** Enforced independent trusted IP (`limit: 10`) and normalized email digest (`limit: 5`) rate limits before password verification on `POST /api/identity/recovery/backup-code` via `createRateLimiter` (`sensitivity: "auth"`), verified shared `rate_limits` counters across accounts and IPs including unknown accounts, and verified fail closed (`429`) behavior under simulated store outage. Optional user TOTP and operator lost factor recovery custody remain open in P4.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `926b5c547e08121acfda5f245f11e55e8741cfe7` (CI run: `https://github.com/SGOD-pro/OAuth2.1/actions/runs/45625840490`)
* Worktree status: Working tree with `keyFn` in `rate-limit.ts`, `digestToken` account key in `identity-recovery.ts`, cross IP unknown account, cross account IP, and store outage tests in `p4-backup-code-recovery.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-recovery && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 4/4 recovery tests passed; 2/2 admin MFA tests passed
2. Command: `npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P4 backup code recovery atomicity and shared rate limiting

**Date:** 2026-11-25. **Result:** Closed P4 backup code recovery failure and rate limit gaps by moving backup code consumption, old session invalidation, `tokenVersion` bump, `twoFactorEnabled: false` reset, and restricted recovery session issuance into a single MongoDB replica set transaction, replacing the local counter with shared `createRateLimiter` IP and account limits (`sensitivity: "auth"`), and using configured session cookie attributes (`Secure` in production). Optional user TOTP and operator lost factor recovery custody remain open.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `4f5cc32b33219c4518efd0b3ce194d0ad0f84fa0`
* Worktree status: Working tree with transactional `identity-recovery.ts`, shared `recoveryIpRateLimit` and `recoveryAccountRateLimit`, failed commit and platform admin recovery tests in `p4-backup-code-recovery.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-recovery && npm run test:p4-invitations && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 3/3 recovery tests passed (concurrent single use, rate limiting, failed commit preservation and platform admin restoration); 3/3 invitation tests passed; 2/2 admin MFA tests passed
2. Command: `npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors


## Slice P4 independent account and IP recovery rate limits

**Date:** 2026-11-25. **Result:** Enforced independent trusted IP (`limit: 10`) and normalized email digest (`limit: 5`) rate limits before password verification on `POST /api/identity/recovery/backup-code` via `createRateLimiter` (`sensitivity: "auth"`), verified shared `rate_limits` counters across accounts and IPs including unknown accounts, and verified fail closed (`429`) behavior under simulated store outage. Optional user TOTP and operator lost factor recovery custody remain open in P4.

### Tested commit and boundary

* Branch: `v2`
* Base inspection commit SHA: `926b5c547e08121acfda5f245f11e55e8741cfe7` (CI run: `https://github.com/SGOD-pro/OAuth2.1/actions/runs/45625840490`)
* Worktree status: Working tree with `keyFn` in `rate-limit.ts`, `digestToken` account key in `identity-recovery.ts`, cross IP unknown account, cross account IP, and store outage tests in `p4-backup-code-recovery.test.ts`, review record, and updated ledger

### Verification commands and execution evidence

1. Command: `npm run typecheck:backend && npm run test:p4-recovery && npm run test:p4-admin-mfa`
   * Result: 0 TypeScript diagnostics; 4/4 recovery tests passed; 2/2 admin MFA tests passed
2. Command: `npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 11/11 local consumer E2E flows passed, 0 integration violations, and 0 documentation consistency errors








## Slice P4 optional user TOTP (AC-11, partial) and review remediation

**Date:** 2026-11-25. **Result:** Implemented optional ordinary user TOTP (`POST /api/identity/totp/enable`, `/verify`, `/disable`) via `X-Identity-Context`, `AccountTotpPanel.tsx`, and `totp_used_steps` atomic replay protection, and resolved all security review blockers and majors (session rotation preservation on `disable` with `browser_session_sets` CAS update, `ObjectId` `oauthRefreshToken`/`oauthAccessToken`/`oauth_token_families` revocation, exact step `claimMatchedTotpStep` keyed by `{ userId, step, secretDigest }` across enroll/login/disable/admin without pre locking invalid guesses, login 2FA ambient session stripping and `browser_session_sets` enrollment, per `userId` rate limits, pre enrollment `mfaVerifiedAt == null` session revocation/denial, and promoted admin exclusion). `AC-11` remains **partial**.

### Engine findings (installed `better-auth@^1.6.25`)

* `twoFactor` `verifyTOTP` (`totp/index.mjs:188-223`) decrypts `twoFactor.secret` with `ctx.context.secretConfig` (UTF-8 secret passed to `createOTP`, `window = 1` = 90s), skips `assertTwoFactorNotLocked` and `beginAttempt(5)` when `session.session` exists, and rotates the session on initial verification while deleting the incoming session.
* `disableTwoFactor` (`two-factor/index.mjs:206-231`) also creates a new session and deletes the incoming session; `handleOwnerTotpDisable` extracts the rotated session from `Set-Cookie`, CAS updates `browser_session_sets`, and excludes the new session ID from `deleteMany`.
* `enableTwoFactor` (`two-factor/index.mjs:146-158`) overwrites `secret` and `backupCodes` immediately even when `verified === true`, requiring an explicit `409 ERR_TOTP_ALREADY_ENABLED` guard.
* `verifyTwoFactor` resolves `getSessionFromCtx(ctx)` before `better-auth.two_factor`, requiring ambient `better-auth.session_token` cookie stripping during challenge verification.
* `oauthRefreshToken.userId` is coerced to MongoDB `ObjectId` by `@better-auth/mongo-adapter`, requiring both string and `ObjectId` filters on token/family revocation.

### Session policy & tested commit boundary

* Pre enrollment password only sessions (`mfaVerifiedAt == null`) are revoked on TOTP enrollment (`handleOwnerTotpVerify`) and denied by `session-adapter.ts` once `twoFactorEnabled === true` (documented in `docs/SESSION_MODEL.md`).
* Branch: `v2`
* Verified implementation SHA: `314847d10dd951296f193289017d97ee6cf18880` (following `39209af` and `562751a`)
* Review record: `docs/reviews/2026-11-25-p4-optional-user-totp.md` (initial review Verdict: Blocked; all blockers and majors resolved and re-verified at `314847d10dd951296f193289017d97ee6cf18880`)

### Verification commands and execution evidence

1. Command: `npm --prefix frontend run lint && npm --prefix frontend run build:ui && npm run typecheck:backend`
   * Result: 0 ESLint errors, Vite SPA build succeeded, 0 backend TypeScript diagnostics
2. Command: `npm run test:p4-user-totp && npm run test:p4-recovery && npm run test:p4-admin-mfa && npm run test:p3-dashboard-browser`
   * Result: `test:p4-user-totp` 2/2 passed (context isolation, pending/enrolled guards, 10 way concurrent `409` replay, cross step/cross endpoint replay, login 2FA ambient session isolation + registry attachment, disable rotated session preservation + `ObjectId` OAuth token/family revocation, promoted admin `403`); `test:p4-recovery` 5/5 passed; `test:p4-admin-mfa` 2/2 passed; `test:p3-dashboard-browser` Playwright passed
3. Command: `npm run test:local-consumer-e2e && npm run security:integration-check && npm run security:docs-check`
   * Result: 11/11 local consumer E2E flows passed, 0 integration contract violations, 0 documentation consistency errors

### Remaining open gaps (P4 release decisions)

* **Operator lost factor recovery custody (open release decision)**: Operator assisted lost factor recovery custody and runbook remain open; admin lost factor recovery must never be email only.
* **Live mail provider delivery**: Password reset and email change verification/notification were verified with the local mail sink (`getTestMailSinkMessages`); live mail provider delivery remains separate.

## Slice P4 verified email change (`AC-11` complete)

**Date:** 2026-11-26. **Result:** Implemented and locally verified `/api/identity/email-change/request` and `/api/identity/email-change/confirm` (`backend/src/routes/identity-email-change.ts`, `backend/tests/security/p4-email-change.test.ts`). `AC-11` is now **locally verified** (with live mail provider delivery separate, and operator lost factor recovery custody open).

* **Account binding & recent auth:** Both endpoints resolve `X-Identity-Context` via `resolveOwnerDashboardContext` (an ambient session for B never targets B when context is A). `request` verifies current password, supersedes prior unconsumed requests for the same user, and requires admin TOTP + recent MFA (5 minute window) for admin roles. Note: admin accounts are not enrolled in ordinary user `browser_session_sets`, so `/api/identity/email-change/*` is unsupported for admin accounts and fails closed (`401`).
* **Atomic proof & uniqueness:** `confirm` runs inside a MongoDB transaction (`mongoSession.withTransaction`), atomically consumes the single use `email_change_requests` proof, checks `newEmail` uniqueness at commit (`409` on collision, preserving old address and authority), guards `email: oldEmail` on update (`409` if already changed), advances `tokenVersion` from the account's effective version (`userDoc.tokenVersion ?? 1`, so legacy accounts with missing `tokenVersion` persist `2`) along with `sessionVersion` and `lookupVersion`, preserves `_id`/`sub`/`role`/`twoFactorEnabled` (verified with real TOTP enrollment and post change TOTP sign in), revokes A's old stored sessions (`session`, `identity_contexts`, `browser_session_sets`), revokes A's issued OAuth credentials (`oauthRefreshToken`, `oauthAccessToken`, `oauth_token_families`), rejects A's pre change `refresh_token` (`401`) and pre change `authorize` (`302` without `code=`) against a real registered PKCE client while B's pre change `refresh_token` remains usable (`200`), and notifies `oldEmail` via the local mail sink. Registered in `backend/scripts/run-all-security.ts` for CI execution. Dedicated in flight issuance concurrency coverage remains separate.

## Slice P5.1 owner Sessions and Connected Apps

**Date:** 2026-11-26. **Result:** Implemented `/api/identity/sessions`, `/api/identity/sessions/:sessionId/revoke`, `/api/identity/apps`, and `/api/identity/apps/:clientId/disconnect` (`backend/src/routes/identity-owner-portal.ts`, `backend/src/routes/identity.ts`) and extended `/account` with `AccountSessionsAppsPanel.tsx` (`frontend/components/AccountSessionsAppsPanel.tsx`, `frontend/pages/AccountDashboard.tsx`). Verified in `p5-owner-sessions-apps.test.ts` (registered in `run-all-security.ts`) and `test:p5-owner-portal` (registered in CI). Profile editing, admin masking, export, and deletion remain for separate P5 slices.

## Slice P4 password reset, browser TOTP E2E, and replay exception reconciliation

**Date:** 2026-11-26. **Result:** Verified password reset with TOTP enabled (`p4-password-reset-totp.test.ts`), added ordinary user TOTP browser E2E (`test:p4-user-totp-browser` registered in CI), and reconciled the enrollment replay exception. `AC-11` remains **partial** (email/contact change and operator lost factor recovery custody remain open).

* **Password reset with TOTP (`backend/src/utils/auth.ts`, `backend/src/identity/mail-service.ts`, `backend/tests/security/p4-password-reset-totp.test.ts`):** Wired `sendResetPassword` (local mail sink in non production) and `onPasswordReset` in Better Auth `emailAndPassword` (`revokeSessionsOnPasswordReset: true`). Verified that resetting a password preserves `twoFactorEnabled: true`, revokes the affected account's prior Better Auth sessions, `browser_session_sets` entries, `identity_contexts`, and `oauthRefreshToken`/`oauthAccessToken`/`oauth_token_families`, keeps a second account in the same browser active, and still requires TOTP on next sign in.
* **Ordinary user TOTP browser E2E (`backend/tests/e2e/p4-user-totp-browser.test.ts`, `.github/workflows/ci.yml`):** Verified `/account` TOTP enrollment via `AccountTotpPanel.tsx`, sign out, TOTP sign in via `/two-factor`, consumer OAuth PKCE flow, and authorized TOTP disable.
* **Enrollment replay exception (`backend/src/routes/auth-two-factor.ts`):** `handleVerifyTotp` skips `claimMatchedTotpStep` when `twoFactor.verified === false` (enrollment verification) so enrollment does not block same window sign in. Enrollment still completes once (`handleOwnerTotpEnable` rejects `verified === true` with `409 ERR_TOTP_ALREADY_ENABLED`), sign in follows the documented same window policy, and accepted login codes cannot be reused (`409 ERR_TOTP_REPLAY`).
