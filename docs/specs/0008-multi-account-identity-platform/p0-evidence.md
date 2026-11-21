# P0 engine compatibility evidence

**Date:** 2026-11-22. **Result:** Compatibility proof locally passed; production enrollment and chooser remain unimplemented. No deployment or main merge.

## Provenance and boundary

- Fetched `origin/v2`; starting HEAD `55704fc693249a9c8118e565b307ce26783077cf`, clean worktree. Historical handoff SHA was not treated as current.
- Local verification commit: `74f2ce8c80082cb36153124e44cc1a018f9f12ba`, branch `v2`, clean worktree at the final P0 suite run. Published implementation commit: `31af32010f81925a13605835deed074170e473f2`. Both have identical Git tree `b9599e432413dc73b13609b33cabc515041619c5`. HTTPS push credentials were unavailable, so the connected GitHub API published the identical tree with new commit metadata. This ledger/status reconciliation follows in a documentation-only commit.
- Strengthened engineering rules were already in root AGENTS.md. Only nested instructions found were frontend/AGENTS.md; no frontend source changed.
- Node `24.22.3`; locked Better Auth/core/Mongo adapter/OAuth provider `1.7.1`; MongoDB `7.0.24`, WiredTiger, disposable single-member replica set. No engine version upgrade. Core is now an explicit exact dependency because the boundary imports its exported context API.
- Each suite instantiates the real engine from existing authProvider options/plugins and user-create hook. The fixture adds a disposable proof model, username field, prepared indexes, failure injection and authorization barrier. Mongo, credentials, password verification, OAuth and consent are not mocked.
- Category: one Node process per suite, real local Mongo process and transactions, in-process Request/Response engine HTTP calls. Concurrent operations are async calls in that process, not separate backend workers or browser tabs. No live Google/mail/Redis/key-service/restore evidence is claimed.

## Current source trace

| Source | Behavior and P0 consequence |
|---|---|
| `backend/src/utils/auth.ts` | Better Auth credentials/admin/twoFactor/JWT/OAuth plugins. Mongo adapter explicitly has transaction false. User-create before hook supplies tokenVersion. Production engine stays unchanged. |
| `backend/src/db/mongo.ts` | Shared Mongo client and proxy Db; background connection/test override. No external ClientSession propagation. P0 does not inject a global mutable session into this proxy. |
| `backend/src/routes/auth.ts`, signup | Sanitizes input and checks client/private signup policy, then calls engine signup. Membership/audit writes follow engine success outside a shared transaction. Still legacy signup, not V2 proof-before-create. |
| Same file, session/MFA | Engine login distinguishes challenge from completion. TOTP/backup completion derives session identity, marks MFA and conditions membership on validated OAuth context. Current login/authorize/consent read ambient sessions. |
| Same file, authorize/consent/continue | Client/redirect/private checks surround engine delegation. current_client_id and oauth_transaction_id cookies remain browser-wide; consent/continue have ambient fallbacks. P0 does not bypass these interceptors. |
| Same file, exchange/refresh | Client, eligibility, membership, scoped family and atomic tokenVersion issuance fences remain unchanged. |
| Admin routes, `backend/src/utils/admin-sync.ts`, provisioning scripts | Custom user/account/membership/assignment writers include explicit verified provisioning. P2 must guard or replace creation bypasses. They are not proof-aware in P0. |
| `backend/src/db/state.ts`, db-setup script | Custom TTL/lookup/family/transaction indexes; setup migrates credential issuers. Existing email lookup index is not evidence of normalized V2 uniqueness. |
| Installed engine internal adapter/signup | createUser/linkAccount use createWithHooks and getCurrentAdapter. Signup/createOAuthUser use runWithTransaction. Credential issuer comes from createLocalAccountIssuer. |
| Installed Mongo adapter | Transaction callback receives a session-bound engine adapter, not a raw ClientSession. Table-index creation occurs separately from that session; unique field metadata requires physical indexes too. |
| Installed OAuth provider | Uses getSessionFromCtx. Authorization codes are typed JSON verification records carrying userId/sessionId. Custom oauthAuthorizationCode is not the plugin's sole code store. |

## Collection and writer inventory

Observed engine models from the instantiated schema:

| Collections | Writers/data |
|---|---|
| `user`, `account`, `session`, `verification` | Core identity/credentials, password/provider tokens, recovery/challenges/sessions and plugin authorization codes |
| `twoFactor`, `jwks` | Engine MFA seed/backup state and JWT signing keys |
| `oauthClient`, `oauthResource`, `oauthClientResource` | OAuth client/resource configuration and compound links |
| `oauthRefreshToken`, `oauthAccessToken`, `oauthConsent`, `oauthClientAssertion` | OAuth token/grant/assertion persistence |
| `p0Proof` | Fixture-only digest/mailbox/expiry model. No production route or migration creates it. |

Custom runtime/state collections: `oauthAuthorizationCode`, `oauth_token_families`, `oauth_transactions`, `user_app_registrations`, `app_admins`, `admin_audit`, `auth_events`, `rate_limits`, `origin_cache`. Core/plugin collections also have custom auth/admin/state readers and writers. This is an inventory for later protection work, not P6 writer-coverage/encryption evidence.

## A. Shared transaction capability

`backend/src/identity/engine-transaction.ts` owns a transaction-enabled Mongo adapter factory. It rejects an engine using another factory, disabled transaction support and nested ambient transactions. Exported engine context propagates the transactional adapter to proof operations and engine identity/credential hooks.

The fixture atomically consumes a nonexpired proof, calls engine createUser and linkAccount, and retains the engine password hash/verify and credential issuer helpers. Account sessions are established after commit.

Ten cases passed:

1. Identity hook failure restores proof and leaves zero user/account/session records.
2. Credential hook failure rolls back the identity and restores proof.
3. Real Mongo credential storage rejection, validation error 121, rolls back identity/proof.
4. Nested transaction context fails closed.
5. Expired/missing proof creates no identity.
6. Concurrent consumption has one committed winner; replay fails.
7. Concurrent email collision creates one complete identity; losing proof survives.
8. Concurrent username collision has the same atomic outcome.
9. Ambient production engine is rejected by this boundary.
10. Real engine login verifies the committed credential.

This proves capability A without a second credential system. It does not implement OTP, real mailbox proof issuance, normalization, browser binding, production migration, idempotency, budgets or bypass closure. The fixture's verified flag represents a synthetic prevalidated proof, not real mailbox verification.

## B. Request-local session capability

`backend/src/identity/selected-engine-session.ts` accepts a server-resolved user/session/token tuple, never a JS token list. It replaces ambient Cookie/Authorization on a cloned internal request, uses the engine signature helper/configured cookie name, and checks selected IDs using cache-disabled getSession. Only authorize/consent dispatch is allowed. Responses remove Set-Cookie and use no-store.

Six cases passed:

1. A pauses inside engine authorization while B completes authorization before A resumes. Consent flows remain independent; incoming cookies remain unchanged; response headers/bodies expose neither raw session token.
2. B then A consent yields separate codes whose engine records retain correct immutable userId/sessionId.
3. Real PKCE exchange verifies signed RS256 ID tokens against engine JWKS with issuer/audience/sub/nonce. Refresh plus UserInfo retains each subject; code replay fails.
4. Wrong selected user/token fails without fallback; get-session dispatch is forbidden.
5. Cross-origin consent is denied by engine with no session token in response.
6. Expired/revoked A fails while B remains usable.

This proves capability B at the engine boundary. P3 still owns browser registry/ownership/CSRF, durable transaction selection/revision, issuance-vs-revocation fencing, MFA freshness/purpose, prompt/max_age and Hono policy wiring, plus real browser/separate-worker tests.

Multi-session is available but not enabled. Its set-active endpoint changes ambient cookies; its device-session listing serializes session records. Existing login/session responses can contain raw tokens. P0 exposes no account-list API. P3 must guard/sanitize token-bearing browser responses and cannot simply enable unwrapped multi-session routes. HttpOnly does not remove a token from JSON.

## Engine limitations and compatible alternatives

- **Cold schema:** lazy table-index creation outside the active transaction caused catalog-change conflicts. Prepare collections, required unique field indexes and compound engine indexes before accepting registration. The fixture does; P2 needs a production migration/readiness gate. Missing/ambiguous uniqueness must block enrollment.
- **Transaction failure semantics:** installed Mongo adapter has no outer retry policy and aborts after commit errors, which can mask the original error. No transient/unknown-commit recovery proof is claimed. P2 must define idempotency and ambiguous-commit handling without blind signup retries. After-commit hook failure is not proof of rollback.
- **Raw ClientSession:** not exposed by public transaction callback. Proven alternative: custom proof/lookup models through the same engine transaction adapter. Direct db.collection writes do not automatically join it. Native Mongo writes would need a separately proven propagation extension.
- **Policy layering:** the selected-session helper is engine-only, not a public route. Later wiring must apply the selected principal to Hono and engine checks while preserving eligibility/MFA/private access/consent/issuance fences.
- **Schema/config convention:** P0 adds no activation flag or production migration. P2 must version durable schemas from 1, audit collisions, prepare indexes outside transactions and reject unsupported reader/writer versions. Proof consumption/revocation remain forward-only. These requirements are not existing migration commands.

## Verification ledger

Both P0 suites were rerun at implementation SHA `74f2ce8c80082cb36153124e44cc1a018f9f12ba`, clean worktree. Other checks ran on the same implementation source tree during preparation. Assertions were not weakened and scenarios were not skipped.

| Command/check | Result | Category |
|---|---|---|
| `npm --prefix backend run test:p0-transactions` | 10 passed, 0 failed, 0 skipped | Real engine/Mongo replica-set transactions, one backend process |
| `npm --prefix backend run test:p0-sessions` | 6 passed, 0 failed, 0 skipped | Deterministic in-process engine HTTP harness and real Mongo replica set |
| `node --import tsx tests/security/oauth-security-hardening.test.ts`, backend | 29 passed, 0 failed | Existing hardened Hono/engine regression suite |
| `node --import tsx tests/security/membership-lifecycle.test.ts`, backend | 23 passed, 0 failed | Existing membership regression suite |
| `node --import tsx tests/security/consumer-mfa-continuation.test.ts`, backend | 24 passed, 0 failed | Existing MFA continuation regression suite |
| All ten files named by backend test:unit | All ten exited 0 after setup | Existing unit suites, direct Node/tsx loader execution |
| TypeScript 5.9.3 strict noEmit on fixture/both P0 suites and imported source | Passed | Type check |
| Backend build and build:node | Both passed | Existing Lambda/Node bundles; P0 modules are not production-wired |
| Security docs consistency and integration contract checks | Passed | Static contracts |
| git diff --check | Passed | Diff hygiene |

Unix sockets are forbidden in this environment. Initial tsx CLI IPC and Mongo Unix-socket startup failed. New suites use node --import tsx and Mongo --nounixsocket. Existing suites used that loader and a scratch launcher forwarding to cached Mongo 7.0.24 with --nounixsocket. Frontend dependencies were installed for admin-store units. Initial environment failures were rerun successfully; database behavior/assertions were unchanged. No scratch launcher or raw test log is committed.

Type check, from backend:

```bash
npm exec --yes --package=typescript@5.9.3 -- tsc --noEmit --target esnext --module esnext --moduleResolution bundler --strict --skipLibCheck --types node tests/fixtures/p0-engine.ts tests/security/p0-engine-transactions.test.ts tests/security/p0-engine-sessions.test.ts
```

P0 suites are blocking entries in the security master runner/manifest. CI now includes pushes/PRs targeting v2. The full master security run, hosted CI, real browser, separate-worker V2 tests and deployment were not executed locally. Adding CI triggers does not prove a hosted CI pass.

## Next gate

Review/accept this bounded proof, then follow PHASES dependencies for P1 policy and P2 verified enrollment. AC-03's full signup and AC-07/08's browser platform remain pending. No P1-P9 work was bundled into P0.
