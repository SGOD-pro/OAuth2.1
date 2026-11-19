# SWYRA Auth: security architecture and trust model

**Status:** NORMATIVE / AUTHORITATIVE SECURITY SPECIFICATION.
**Updated:** 2026-11-19. V2 requirements below are planned unless identified as existing.
**Baseline:** `161ad99ca4ba0de88cff1267b33807db61da306c`.

These are required controls, not a claim that every runtime path meets them.
See the [current source review](reviews/2026-11-19-identity-platform-baseline.md),
[architecture](ARCHITECTURE.md), [integration contract](INTEGRATION.md),
[data lifecycle](DATA_LIFECYCLE.md), and [delivery gates](PHASES.md).

## 1. Trust boundaries

The browser, consumer apps, request parameters, account selectors, device signals, and
forwarded headers are untrusted. Edge-to-origin gateway authentication authenticates
the proxy, not the user. Require independent role, audience, subject, client policy,
and resource ownership validation in the backend. No consumer direct MongoDB access.

Retain gateway secret checks on protected management surfaces. Only trust forwarding
headers from configured proxies; verify actual hosting peer behavior. Use TLS, secure
headers, a restrictive frontend CSP, and explicit CORS policies. Protocol endpoints
needed by consumers differ from IdP session, account-list, profile, and admin APIs.
Registered callback origins do not gain access to those identity-management surfaces.

## 2. Existing protocol controls to preserve

- Authorization Code flow uses `/api/auth/oauth2/authorize`, PKCE `S256`, and exact
  registered redirects. Keep this project's random state contract; clients verify
  state on both success and error callbacks. Require nonce validation when sent.
- No implicit or resource-owner-password grant. No password relay through consumers.
- Public OAuth clients have NO client_secret. Confidential secrets stay server-side.
- Pin `RS256`; validate issuer, intended audience, required subject, expiry, and token
  type. ID tokens establish login at the client; resource APIs accept access tokens.
- Authorization codes are single-use and bound to client, redirect, PKCE, account,
  session, consent, and the specific authorization transaction.
- Refresh families remain client/account/session bound with durable atomic rotation.
  Preserve forward-only revocation. A bounded concurrent-refresh grace must not revive
  a consumed token or administrator-revoked family. No timeout-driven blind retries.
- Private app membership, client enabled state, and app-admin assignments remain
  authoritative. Removing open-app membership gates never removes these controls.
- Preserve NoSQL primitive validation, operator/prototype-key rejection, and explicit
  writable-field allowlists. Never accept role or email verification from signup input.

## 3. Mandatory V2 account eligibility

A single shared server-side predicate must check that the immutable account exists,
is verified, is active, is not banned/disabled/deleting/deleted, has current session
and revocation versions, and satisfies the transaction's policy. Enforce it at login,
chooser selection, authorization, code exchange, refresh, UserInfo, introspection,
management APIs, and data decryption. Missing state fails closed.

Do not accept a token merely because a plugin returned `active=true`. Apply the same
client, account, session/family, expiry, scope, and revocation checks to every
introspection path. User ID lookup is authoritative; email fallback must not resolve
a different account or revive a deleted subject. Do not elevate signed claims using
a database role. A demoted user must not regain old authority from token contents.

Online IdP denial must take effect when revocation/deletion commits. Offline resource
servers can accept a signed access token until expiry, currently up to 900 seconds.
Revocation endpoints cannot reach into offline verifiers. Require online status checks
for immediate denial and define consumer notification/local-session cleanup separately.

## 4. Enrollment, verification, and recovery

No durable user/account/credential record before a valid email OTP and atomic proof
consumption. Registration intents are expiring untrusted state and grant no login.
Use purpose-bound server-keyed OTP verifiers, limited guesses, resend invalidation,
constant-shape responses, mailbox and IP/browser budgets, and server-side expiry checks.
TTL background deletion is cleanup, not an expiry enforcement mechanism.

Initial proposed limits: 6-digit code, 5-minute expiry, 5 guesses per intent,
60-second resend cooldown, 3 sends per mailbox per 15 minutes, 10 per day, and a
30-minute intent lifetime. These are design values, not current configuration.
Resend must not reset mailbox-wide guess/send budgets. Random intent IDs have at
least 128 bits of entropy. Never log codes, proofs, passwords, recovery tokens, or seeds.

Verify changed email before activation, require recent reauthentication, notify the
old address, and revoke affected sessions/grants according to documented policy.
Do not auto-link accounts by email without an authenticated ownership proof. Admin
provisioning/invitations cannot assert mailbox ownership. Existing unverified or
admin-asserted verification records need an explicit migration policy and review.

## 5. Multiple accounts and session safety

- Browser session sets contain only independently authenticated account sessions.
- Account choice uses CSRF-protected POSTs and validated server-side transactions.
- Account lists are IdP-origin only, `Cache-Control: no-store`, never embeddable or
  available via cross-origin credentialed CORS. Protect against login CSRF and fixation.
- Concurrent tabs bind to their own selected account and consent. Recheck status
  immediately before issuing or exchanging codes; fail on selection races.
- Sign out one account, remove a remembered account, sign out every account in this
  browser, revoke one device, and revoke all account sessions are distinct operations.
- Removing a remembered label does not silently revoke other devices. Account logout
  revokes the chosen session and its bound grants according to the selected operation.
- Require recent authentication for delete/export, password/email changes, MFA changes,
  and elevated administrative actions. No credential-free sensitive operation merely
  because the chooser contains a valid long-lived session.

## 6. Administrative assurance and authorization

Keep `super-admin`, `app-admin`, and `user` explicit and mutually exclusive per account.
App admins require active assignments by stable user ID and canonical client ID.
Super admins have platform authority only, never automatic consumer admin claims.
Multiple separately authenticated accounts on one browser do not merge privileges.

TOTP enrollment and completed MFA are mandatory for both administrator roles.
An unenrolled admin receives only enrollment authority. Every admin API, including
Better Auth plugin routes, bearer tokens, role promotion, impersonation, and recovery,
must enforce the same assurance and recent-MFA policy. Initial elevated freshness
limit: 5 minutes, recorded server-side. Email OTP alone never satisfies admin MFA.

TOTP secrets use reviewed engine encryption plus the account key lifecycle where
compatible; backup codes are hashed and consumed atomically. Prevent TOTP replay in
accepted time steps. Recovery is a separate audited flow which revokes old sessions,
not a generic flag that skips MFA. Add passkeys later for phishing resistance.

Preserve structured errors and request IDs: `ERR_GATEWAY_FORBIDDEN`,
`ERR_SUPER_ADMIN_REQUIRED`, `ERR_CROSS_TENANT_FORBIDDEN`, `ERR_ROLE_FORBIDDEN`,
`ERR_IDENTITY_CONFLICT`, `ERR_AUDIENCE_FORBIDDEN`, `ERR_PASSWORD_CHANGE_REQUIRED`.
Never include private user data in error descriptions or request correlation IDs.

## 7. Privacy and cryptography

Encrypt account PII under versioned per-account data keys using authenticated encryption.
Bind account ID, record/field purpose, and key/schema version as associated data.
Use library-managed safe nonces and reviewed key-service policies. Passwords use
salted adaptive hashes; encryption is not a substitute. Non-recoverable session/token
secrets should use digests where engine compatibility permits.

Admin list/search/export/log serializers must omit full email and nonessential PII.
An email local part remains identifying data. Tokens are signed, not encrypted;
release `email`/`profile` claims only under granted scopes and privacy policy.
Never return plaintext data keys or broad decryption capability to consumers/admins.

Cryptographic erasure is complete only when every applicable key copy and recoverable
wrapping path is destroyed and verified. Backup-restorable wrapped data keys under a
shared surviving master key are not erased. Define residual metadata, backup retention,
logs, third-party data, and pending key-deletion delays honestly. See
[DATA_LIFECYCLE.md](DATA_LIFECYCLE.md).

## 8. Abuse and availability

Fingerprinting is a spoofable privacy-sensitive risk signal, not identity, MFA, or
DDoS protection. Apply edge filtering, distributed multi-dimensional quotas, bounded
mail and worker queues, request/body/time/concurrency ceilings, and cost alarms.
Never let a missing fingerprint bypass a limit or block legitimate account recovery.

The existing emergency limiter is process-local. It is not evidence of a fleet-wide
serverless bound. V2 signup, OTP, recovery, and admin authentication fail closed when
durable sensitive-operation budgets cannot be enforced. Public cacheable metadata
can have a separately documented degraded mode. Limits need distributed tests.

Bloom filters never make security decisions. On uncertainty or unavailable/stale
filters use authoritative storage and its quotas. Prevent filter-driven enumeration.

## 9. Verification and release

The authoritative executable suite inventory is
[security-suite-manifest.json](security/security-suite-manifest.json), not a fixed
count in prose. Run `npm run test:all-security`, `npm run security:docs-check`, and
`npm run security:integration-check` in isolated infrastructure. Record exact commit,
commands, counts, skipped cases, dependencies, and blocked checks. A static linter is
not a penetration test. Existing review summaries are reported evidence only.

V2 requires adversarial multi-tab/multi-process tests, OTP races/replays, MFA bypass,
privacy projections, deletion/token races, key loss, backup restore, consumer isolation,
and outage/load tests. No production data, test email spam, live destructive actions,
or external penetration scanning is authorized by this design change.

## 10. Reference standards

- [OAuth security BCP, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final)
- [OWASP MFA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [OWASP denial of service guidance](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)

These sources inform the design. This repository does not claim NIST certification,
formal OIDC conformance, phishing-resistant TOTP, or Google-equivalent security.
