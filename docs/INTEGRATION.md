# SWYRA Auth: consumer integration contract

**Authority:** Normative consumer contract. Updated 2026-11-19.
**Current runtime baseline:** `161ad99ca4ba0de88cff1267b33807db61da306c`.
V2 account selection and privacy behavior is planned, not available merely because
this document describes it. See [architecture](ARCHITECTURE.md), [security](SECURITY.md),
[phases](PHASES.md) and [0008](specs/0008-multi-account-identity-platform/index.md).

## 1. Centralized login

Use Authorization Code flow with PKCE S256 through `/api/auth/oauth2/authorize`.
Consumer apps never collect IdP passwords, OTPs or TOTP codes, relay credentials,
access MongoDB, or store copies of IdP credential tables. Business data and app
permissions remain the consumer's responsibility. Keep client secrets server-side.

## 2. Client policy

| Concept | Existing runtime | Planned V2 |
|---|---|---|
| Public Application, open user access | `isPublic=true`, automatic connection/membership bookkeeping | `accessPolicy=open`, no ordinary membership prerequisite |
| Private Application, restricted access | `isPublic=false`, explicit membership, controlled signup | `accessPolicy=private`, preserve explicit membership and controlled provisioning |
| Public OAuth client | No securely retained client secret | `clientType=public`, NO client_secret, PKCE required |
| Confidential OAuth client | Server-held CLIENT_SECRET and registered authentication method | `clientType=confidential`, client authentication plus PKCE |
| Development callbacks | Explicit `isDev` handling | Retain independently of access and client authentication |

The legacy `isPublic` field must not be used to infer secret handling. Existing clients
keep their current policy until audited migration. An open app still needs registered
callbacks, an active client, eligible account, granted scopes, and user consent.
An app's own business authorization can still deny a correctly authenticated user.

Super admins register/manage clients and platform configuration. App admins manage
only explicitly assigned clients. Internal roles are `super-admin`, `app-admin`,
`user`. Existing consumer app-admin tokens use `role=admin` with the target
`scoped_client_id`. Super admins do not gain consumer administration privileges.
Existing assignments and protocol fields must not change without versioned migration.

## 3. Existing protocol endpoints

| Purpose | Method | Path |
|---|---|---|
| Discovery | GET | `/.well-known/openid-configuration` |
| Public signing keys | GET | `/.well-known/jwks.json` |
| Authorization | GET | `/api/auth/oauth2/authorize` |
| Code exchange/refresh | POST | `/api/auth/oauth2/token` |
| UserInfo | GET | `/api/auth/oauth2/userinfo` |
| Revocation | POST | `/api/auth/oauth2/revoke` |
| Introspection | POST | `/api/auth/oauth2/introspect` |

Keep endpoint paths stable. Proposed `/api/identity/*` APIs are IdP-internal and
must not be used by consumer apps to enumerate browser accounts or manage identity.
Dynamic external client registration remains disabled.

## 4. Authorization transaction requirements

1. Generate random state (at least 128 bits), a high-entropy PKCE verifier, its S256
   challenge, and a random OIDC nonce. Bind them to one expiring browser transaction.
2. Redirect with registered `client_id`, exact `redirect_uri`, `response_type=code`,
   requested `scope`, `state`, `nonce`, `code_challenge`, and
   `code_challenge_method=S256`. Request only needed scopes.
3. At callback, validate stored transaction and state before processing success or
   OAuth errors. Consume the transaction once, expire it, and defend concurrent-tab
   flows with separate transaction records rather than one shared verifier cookie.
4. Exchange the code with its verifier and redirect URI. Confidential clients also
   authenticate using their registered method. Validate HTTP status and token schema.
   Do not blindly retry consumed codes or timeouts.
5. Validate ID token signature, RS256 algorithm, issuer, audience/authorized party,
   expiry, required subject, nonce, auth_time when requested, and at_hash if present.
   Validate access tokens separately for the intended resource API and scopes.
6. Create the consumer's own protected session with session rotation. Check ownership
   and app permissions on every protected business API. Do not treat an ID token as
   a resource access token or use email as a stable subject.

JWTs are signed, not encrypted. `openid`, `profile`, `email`, and `offline_access`
are separate permissions. V2 releases email/profile claims only when granted and
consistent with privacy settings; consumers must tolerate omitted optional claims.
The current custom mint path includes email/name even without those scopes, tracked
as a baseline privacy gap. Do not rely on that disclosure in new integrations.

## 5. Planned account chooser and SSO

When V2 ships, the IdP displays accounts authenticated in that browser profile, not
all accounts physically present on a device. A valid eligible account session can
continue without a password when policy permits. Consent, reauthentication, private
membership, and administrative MFA still apply. A remembered signed-out entry needs
fresh login. Consumers never receive the account list.

| OIDC request | Required target behavior |
|---|---|
| `prompt=select_account` | Ask for an account; bind selection to this OAuth transaction |
| `prompt=login` | Reauthenticate the selected account |
| `prompt=consent` | Obtain consent for this request |
| `prompt=none` | No UI; return an OIDC error if login, consent or account selection is needed |
| `max_age=N` | Reauthenticate when authentication age exceeds N; return required auth_time |
| `login_hint` | Display hint only, never proof of account/session ownership |

`none` cannot combine with other prompt values. Exact supported metadata and error
behavior are published only after implementation tests. Existing library support is
not assumed to satisfy the multi-account design. Never implement silent selection
by changing a browser-wide current user while another tab is authorizing.

## 6. Framework integration recipes and session storage

The previous illustrative Next.js recipe serialized unsigned user/role JSON into an
HttpOnly cookie. HttpOnly does not prevent client-side forgery. That recipe is removed.
The previous SPA recipe stored access tokens in sessionStorage and omitted complete
OIDC validation; it is not a production integration template.

Use the following required framework contracts and the versioned consumer fixtures
under [test/](../test/) for executable examples. Fixtures are test evidence, not a
blanket production endorsement. Complete application-specific review is required.

| Framework | Required implementation |
|---|---|
| Next.js BFF | Server-side authorization transactions and token exchange; random opaque session handle in Secure HttpOnly host-only cookie; server-side TTL/revocation store |
| Express/FastAPI BFF | Same transaction/session contract; isolate token storage from browser; validate signatures, issuer, audience, expiry, subject and required scopes |
| Browser SPA/mobile public client | No client secret; tested OIDC library for transaction and token validation; access tokens in memory; no persistent refresh/bearer tokens in web storage |
| Resource API | Access tokens only; RS256/JWKS validation with issuer/audience/expiry/subject and scope checks; online status checks if immediate revocation is required |

An encrypted/authenticated cookie can be considered only with reviewed key rotation,
expiry, revocation and replay behavior. Unsigned identity or role JSON must never
be trusted. Cookie flags do not provide cryptographic integrity. Prefer a BFF when
browser token exposure is unnecessary. Protect cookie-backed mutations against CSRF.

Use exact issuer/callback configuration with no localhost or client-ID production
fallback. Keep secrets out of public environment prefixes and repository files.
A production IdP can host explicitly configured development clients; runtime mode is
not client mode. Validate all three client dimensions independently.

## 7. Refresh, logout and deletion

Refresh families rotate with one durable winner. Serialize refreshes per consumer
session using a shared store for multiple instances. An in-process mutex or sticky
sessions alone do not provide cross-process coordination. Losing workers must handle
a clean reauthentication result without resurrecting a consumed token.

Distinguish local consumer logout, IdP account logout, browser-wide signout, removing
a remembered account, device/session revocation, consent revocation, and deleting the
whole account. One account's logout must not sign out another account unintentionally.

Offline JWT validation can accept a revoked token until its expiry, currently up to
900 seconds. For immediate rejection, resource servers must perform online status
checks and retire local consumer sessions. Calling revocation alone cannot change an
offline verifier's result. IdP deletion does not delete consumer-owned business data.
An authenticated consumer deletion-notification contract remains planned separately.

## 8. The 10 Golden Rules for AI Agents

1. Keep IdP credentials at the centralized IdP.
2. Never connect consumer apps directly to IdP MongoDB.
3. Never copy IdP credential/session/token tables into a consumer.
4. Keep CLIENT_SECRET server-side; public clients use NO client_secret.
5. Never persist bearer tokens or confidential secrets in browser storage.
6. Fail closed on missing configuration; no production localhost fallback.
7. Separate runtime environment from client development mode.
8. Separate client authentication type, access policy, and callback environment.
9. Authenticate identity separately from business authorization.
10. Preserve exact redirects, S256, state, nonce and transaction binding.

## 9. 18 Security Review Questions

1. Is the client public or confidential independently of user access policy?
2. Is development/production callback mode explicit?
3. Is the callback exactly registered and production HTTPS?
4. Are secrets absent from browser bundles and web storage?
5. Is PKCE S256 enforced without downgrade?
6. Is state checked on both successful and error callbacks?
7. Is nonce generated, transaction-bound and verified?
8. Are transactions one-use and safe across multiple tabs?
9. Are issuer and audience pinned?
10. Are RS256 signature, expiry and subject verified?
11. Are ID tokens and access tokens validated for separate purposes?
12. Are return destinations limited to approved local paths?
13. Is the app session integrity-protected, rotated and revocable?
14. Is business authorization checked separately?
15. Are scopes/consent and optional claims handled correctly?
16. Are private memberships and admin scope/assurance checked?
17. Is immediate vs offline revocation behavior documented?
18. Do real integration tests and both contract checks pass?
