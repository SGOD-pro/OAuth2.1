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
