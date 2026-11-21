# Consumer integration contract

**Authority:** Normative consumer contract. Updated 2026-11-22.
**Version boundary:** Main `828acc5` incorporates reviewed security PR #2; this docs branch includes that baseline. V2 account chooser/session/privacy changes below are targets, not available endpoints by documentation alone. Read [architecture](ARCHITECTURE.md), [flows](AUTHENTICATION_FLOWS.md), [sessions](SESSION_MODEL.md) and [phases](PHASES.md).

## 1. Centralized identity, consumer-owned authorization

Start login with a top-level browser redirect to `/api/auth/oauth2/authorize`. The consumer never collects/proxies IdP passwords, email OTPs or TOTP codes. It never connects to IdP MongoDB or copies IdP credential/session tables. IdP authenticates an immutable subject; each consumer owns its business data and authorization.

An ordinary user of an open app needs no app membership in V2. This does not make a paid/admin/business resource public. Private app membership and app-admin assignments remain IdP access controls; consumer business permissions remain additional checks.

## 2. Three independent client dimensions

| Concept | Legacy/hardened contract | V2 contract |
|---|---|---|
| Public Application, open user access | `isPublic=true`, registration/history bookkeeping | `accessPolicy=open`, eligible users may consent without ordinary membership |
| Private Application | `isPublic=false`, explicit membership | `accessPolicy=private`, assigned users only |
| Public OAuth client | Cannot keep a secret | `clientType=public`, NO client_secret, S256 required |
| Confidential OAuth client | Server-held CLIENT_SECRET and registered authentication method | `clientType=confidential`, client authentication plus S256 |
| Callback environment | `isDev` | Retained independently; only exact configured dev loopbacks |

A private app can use a public client; an open app can use a confidential client. Super admins continue client registration and disabling. Do not implement unauthenticated dynamic client registration or remove callbacks, consent, quotas or disabled-client checks when removing open membership gates.

## 3. Stable protocol endpoints and data API boundary

| Action | Method | Path |
|---|---|---|
| Discovery | GET | `/.well-known/openid-configuration` |
| Signing keys | GET | `/.well-known/jwks.json` |
| Authorize | GET | `/api/auth/oauth2/authorize` |
| Code exchange/refresh | POST | `/api/auth/oauth2/token` |
| UserInfo | GET | `/api/auth/oauth2/userinfo` |
| Revoke | POST | `/api/auth/oauth2/revoke` |
| Introspect | POST | `/api/auth/oauth2/introspect` |

Keep these URLs and immutable subjects stable. Discovery advertises only supported implemented metadata. Consumer browser APIs get only registered origin permissions appropriate to their client type; server-to-server calls validate client credentials. Identity APIs `/api/identity/*` are IdP-only and never expose account lists or owner dashboard controls to a consumer origin.

Scopes retain `openid`, `profile`, `email`, `offline_access` where supported/approved. UserInfo returns only claims authorized by scope and owner privacy settings. `sub` is required stable identity; do not key a business account on email/username. Optional fields may be absent. Admin email masking does not prevent a user from explicitly sharing email with a consented consumer, and consumer consent cannot grant the admin dashboard general email access.

Other registered-app data endpoints remain possible through explicit resource audience, documented scopes and owner permissions. They do not become generic decrypt/export APIs. Preserve existing app APIs through scoped policy adapters; publish any incompatible resource contract separately with fixtures/migration.

## 4. Authorization and callback contract

1. Create one server-side or tested OIDC-library transaction per login tab: random state >=128 bits, high-entropy verifier, S256 challenge, random nonce, original safe local destination and expiry. No shared single-verifier cookie across simultaneous tabs.
2. Redirect with registered client_id, exact redirect_uri, response_type=code, requested scopes, state, nonce, code_challenge and method S256. No password/OTP/device fingerprint query parameters. For explicit account switching request `prompt=select_account` when V2 support is published.
3. At callback validate and consume state/transaction for both success and errors. Reject unknown, expired or replayed transactions. Never trust callback role/email fields outside validated tokens.
4. Exchange once with verifier and exact redirect. Confidential clients use registered client authentication; public clients send no secret. Validate HTTP status and token schema. A timeout does not justify blindly retrying a consumed code.
5. Verify ID token signature against configured JWKS, RS256, issuer, audience/azp, expiry, nonempty subject, nonce and requested auth_time; verify at_hash when present. Resource APIs separately validate access token purpose/audience/scopes. Do not treat a decode-only JWT operation as verification.
6. Create a rotated consumer session. Prefer random opaque Secure HttpOnly host-only cookie plus shared server-side TTL/revocation storage. Enforce business authorization on every API. Cookie attributes do not make unsigned role JSON trustworthy.

## 5. V2 chooser, login and MFA behavior

The IdP displays accounts signed in to that browser profile. It does not enumerate OS/Google accounts, other devices or accounts from a consumer-provided email. Selecting an active eligible account can continue without password; a signed-out entry requires login. A new login adds an account rather than globally replacing another one.

Consent, private assignment, account status and required assurance are still checked. Consumer cannot set `mfa=true`, force privileged claims through scopes or rely on device recognition as authentication. App-admin access always needs completed MFA; stale privileged actions step up on the IdP.

| OIDC input | Target behavior after implemented support |
|---|---|
| `prompt=select_account` | Choose account and bind it to this transaction |
| `prompt=login` | Fresh authentication for the selected subject |
| `prompt=consent` | Display approval for requested scopes |
| `prompt=none` | No UI; explicit OIDC error when login/selection/consent is required |
| `max_age` | Selected subject's actual auth age; required auth_time |
| `login_hint` | Display hint only; no account ownership proof |

`none` cannot combine with other prompts. An ambiguous two-account silent request returns account_selection_required rather than silently using a global cookie. Consumer must handle login_required/consent_required/interaction_required without redirect loops. Request only supported tested behavior; do not assume a library plugin covers this full contract.

## 6. Concrete framework integration recipes

Executable fixtures live under [test/](../test/), including Next.js and React+Express consumers. They are verification fixtures, not a blanket production endorsement. V2 implementation must update both old/new consumer journeys without installing a duplicate identity system.

| Consumer pattern | Required implementation |
|---|---|
| Next.js BFF | Server authorization transaction and code exchange; server token store; opaque cookie; no IdP credentials in React forms |
| Express/FastAPI BFF | Same server transaction/session contract; audience/scope validation on business APIs; ownership checks |
| Browser SPA/mobile | Public client, tested OIDC implementation, PKCE/state/nonce; memory-based web token storage, no persistent bearer/refresh in web storage |
| Resource API | Access token signature/iss/aud/exp/sub/scopes; online status for immediate revocation; no ID token as bearer |

Consumer env: explicit issuer/client/callback; server-only secret for confidential clients and session secret. No production localhost fallback. IdP Mongo/provider/key settings never go into consumer env. Prefer BFF where token exposure to JS is unnecessary.

Refresh families rotate atomically. Multi-instance BFFs coordinate refresh through a shared durable lock/fence/session version. A losing worker cannot overwrite a newer token or restore a revoked one. Reauthentication after uncertainty is safer than rollback upserts that resurrect credentials.

## 7. Logout, grant revocation and deletion

| Operation | Consumer effect |
|---|---|
| Local logout | Retire current consumer session only |
| IdP account/browser logout | Explicit IdP operation; preserve unrelated account sessions |
| Token/family revoke | Authenticated and client-owned; preserve unrelated families/accounts |
| User disconnects app | Stop using revoked grant; retire local app session and obtain new consent if appropriate |
| IdP account deletion | Online validation denies; consumer owns its own data retention and deletion |

Offline validation may accept access tokens until expiry (existing maximum 900 seconds); consumer-local sessions can persist longer unless actively checked. Introspection/short sessions are required when immediate invalidation matters. Calling the revoke API alone cannot change an offline verifier's result.

A signed optional deletion-event contract is proposed in [DATA_LIFECYCLE.md](DATA_LIFECYCLE.md). Do not assume that event endpoint exists, that all consumers support it or that notification means data erasure. IdP does not cascade into consumer databases. Account dashboard explains this boundary.

## 8. The 10 Golden Rules for AI Agents

1. Keep credentials, email OTP and TOTP input at the central IdP.
2. Never connect consumer applications directly to IdP MongoDB.
3. Never copy IdP credential/session/token tables into consumers.
4. Keep CLIENT_SECRET server-side; public clients use NO client_secret.
5. Never persist bearer tokens or confidential secrets in browser storage.
6. Fail closed on missing config; no production localhost/client-ID fallback.
7. Separate runtime environment from development callback policy.
8. Separate client authentication type, access policy and isDev.
9. Check business authorization separately from authentication.
10. Preserve exact callbacks, S256, state, nonce and per-tab transaction binding.

## 9. 18 Security Review Questions

1. Is client type explicit independently of open/private access?
2. Are dev/production callback rules explicit?
3. Is callback exactly registered and production HTTPS?
4. Are secrets absent from browser bundles and persistent web storage?
5. Is S256 enforced without downgrade?
6. Is state checked on both successful and error callbacks?
7. Is nonce transaction-bound and validated?
8. Are concurrent login tabs isolated and transactions single-use?
9. Are issuer and audience pinned?
10. Are RS256 signature, expiry, subject and token purpose verified?
11. Are access tokens and ID tokens used for their intended roles?
12. Are return destinations limited to approved local paths?
13. Is consumer session integrity-protected, rotated and revocable?
14. Are business authorization and owner checks independent?
15. Are scopes/privacy and missing optional claims handled?
16. Are private membership and administrative MFA enforced?
17. Are offline versus immediate revocation/deletion limits explained?
18. Do real consumer/browser tests and contract checks pass at the reviewed SHA?
