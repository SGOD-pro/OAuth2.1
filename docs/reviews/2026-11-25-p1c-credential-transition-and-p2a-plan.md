# Review, v2, 2026-11-25 (P1c Credential Transition Fix and P2a Plan)

**Reviewed by**: Gemini 4 Hydrogen (High) (author on Gemini 4 Hydrogen (High); same model fallback disclosed as an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, transactional Confidential to Public credential cleanup and safe retry, in flight issuance commit linearization across authorization, code exchange, and refresh rotation, plus P2a planning spec ([0008-p2a-mail-and-intents.md](../specs/0008-multi-account-identity-platform/0008-p2a-mail-and-intents.md))
**Verdict**: Approve

## Summary of Reviewed Changes

1. **Partial failure and atomic cleanup** ([admin-client-transition.ts](../../backend/src/routes/admin-client-transition.ts), [admin-client-detail.ts](../../backend/src/routes/admin-client-detail.ts)):
   * Updating `oauthClient` during Confidential to Public conversion (unsetting `clientSecret` / `client_secret`, setting `clientType: "public"`, `tokenEndpointAuthMethod: "none"`, `clientSecretRevokedAt`, incrementing `credentialVersion`) now runs inside `session.withTransaction(...)` atomically alongside deleting `oauthAccessToken`, `oauthRefreshToken`, `oauthAuthorizationCode`, `oauth_token_families`, and Better Auth `verification` authorization code records for the client.
   * Better Auth's secondary adapter sync (`adminUpdateOAuthClient`) runs only after the primary database transaction commits, so an aborted cleanup failure leaves zero mutated policy, redirect, or secret fields in `oauthClient`.
   * A non transactional fallback path (when `startSession` is absent on mock DB adapters) restores a tracked snapshot of the prior client record if cleanup throws.

2. **Retry behavior and idempotency**:
   * When an initial Confidential to Public conversion aborts due to cleanup failure, `oauthClient` retains `clientType: "confidential"` and its original `clientSecret` hash, and existing access tokens remain usable until conversion succeeds. Retrying the `PATCH` succeeds cleanly with `200 OK` and purges all confidential codes, refresh/access tokens, families, and `verification` entries.
   * Retrying `PATCH` `{ clientType: "public" }` after completion is idempotent (`200 OK`, keeps `public` without secret). If a `pendingCredentialCleanup` marker exists from a fallback state, retry runs full cleanup and clears the marker.

3. **In flight issuance commit guards** ([auth-client-fence.ts](../../backend/src/routes/auth-client-fence.ts), [auth-token-linearize.ts](../../backend/src/routes/auth-token-linearize.ts), [auth-authorize.ts](../../backend/src/routes/auth-authorize.ts), [auth-consent.ts](../../backend/src/routes/auth-consent.ts), [auth-token-code.ts](../../backend/src/routes/auth-token-code.ts), [auth-token-refresh.ts](../../backend/src/routes/auth-token-refresh.ts), [auth-token-refresh-validate.ts](../../backend/src/routes/auth-token-refresh-validate.ts), [pkce.ts](../../backend/src/utils/pkce.ts)):
   * Added `commitClientIssuanceLinearization` and `finalizeAuthorizeCodeWithFence` checking `disabled`, `isAmbiguous`, effective client type (supporting both V2 `clientType` and legacy `oauthClient` records lacking explicit `clientType`), and monotonic `credentialVersion`.
   * Guarded in flight `/oauth2/authorize`, `/oauth2/consent`, `/oauth2/continue`, `grant_type=authorization_code`, and `grant_type=refresh_token` commits. When a concurrent conversion increments `credentialVersion` before issuance commits, the in flight request fails closed (`401`/`400`), purges newly created code/token/family artifacts (including base64url/hex hashed Better Auth token variants), and leaves zero active credentials.
   * `buildClientIssuanceFence` preserves unit test compatibility (`refresh-lease-fencing.test.ts`) when invoked directly with an unbacked stub context lacking Mongo document identifiers, while enforcing the DB fence on every database backed client request.

4. **P2a slice plan review**:
   * [0008-p2a-mail-and-intents.md](../specs/0008-multi-account-identity-platform/0008-p2a-mail-and-intents.md) captures registration intents, OTP generation/attempt caps, atomic budgets, encrypted mail outbox, provider 5s timeouts/3 retry bounds, bounce suppression, one use proof delivery via `HttpOnly` cookie, and zero account/session test assertions while keeping P2a implementation pending and deferring account creation to P2b.

## Verification Evidence

* `npm run typecheck`: 0 diagnostics.
* `npm run test:p1c-credential-transition`: 4 passed, 0 failed (covers simulated cleanup write failure with rollback + safe retry + idempotent retry, plus deterministic concurrent Confidential to Public barrier tests for `/oauth2/authorize`, `authorization_code` exchange, and `refresh_token` rotation).
* `npm run test:p1c-admin-api`: 5 passed, 0 failed.
* `npm run test:p1c-admin-browser`: BAC P1C 01 through BAC P1C 06 passed against built SPA UI and shared Docker MongoDB.
* `npm run test:unit`: All 16 unit suites passed, 0 failed (including `test:runtime-resilience` and `test:refresh-lease-fencing`).
* `npm run test:all-security`: All 43 security suites passed, 0 failed.
* `npm run security:integration-check && npm run security:docs-check`: 0 violations, 0 errors.
* Rule 7 check: Every new and modified source/test file is strictly under 300 lines.
