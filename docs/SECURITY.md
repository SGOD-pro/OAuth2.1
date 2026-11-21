# V2 security architecture and trust model

**Status:** NORMATIVE / AUTHORITATIVE requirements. Updated 2026-11-22.
This is a design contract, not a statement that all V2 controls are implemented. Security PR #2 is integrated into main `828acc5`; preserve it during V2 runtime work; baseline and exact reviewed references are in [ARCHITECTURE.md](ARCHITECTURE.md).

## 1. Trust boundaries and assets

Untrusted: browser JS, user/consumer inputs, selected account IDs, callbacks, forwarded headers from untrusted peers, device signals and provider webhooks until authenticated. A trusted gateway header identifies the gateway, not a user. Separate subject, role, client audience, session purpose, assurance and resource ownership at every backend boundary.

Protect credentials, account PII, signed tokens, MFA secrets, session/proof handles, user keys, client secrets, signing keys and mail budgets. Consumer apps receive scoped claims, never IdP passwords/OTP/TOTP inputs, account lists, raw session credentials, key access or Mongo credentials. Identity-management APIs use IdP-only CORS and CSRF; allowed consumer origins do not gain access to them.

## 2. Threat-to-control matrix

| Threat | Required controls | Acceptance evidence |
|---|---|---|
| Create account with wrong/unverified email | Proof-before-create, strict bypass closure, atomic unique finalization | Wrong/expired/replayed code creates zero identities/credentials/sessions |
| Credential stuffing/password guessing | Distributed source/target/global budgets, adaptive hash, cost admission | Rotating IPs, multi-process counters and store-loss tests |
| OTP/TOTP/recovery replay | Purpose/generation binding, expiry, atomic tries/consume, accepted-step replay protection | Concurrent guesses and duplicate accepted code rejected |
| Login CSRF/session fixation | Origin/CSRF, rotated opaque handles, browser-bound intents | Attacker cannot attach victim/attacker session through guessed entry |
| Cross-tab subject confusion | Explicit transaction/context subject, revision and final fence | Interleaved A/B authorization and dashboard mutations remain isolated |
| Broken object authorization | Server-derived owner and scoped role/client checks | Foreign session/grant/export/deletion ID rejected |
| Cross-client privilege escalation | Exact audience/client binding, active assignments and assurance | App admin cannot enter platform or another app; super admin not consumer admin |
| Revocation/refresh/deletion races | Atomic monotonic versions, shared issuance fences, family/grant state | Separate workers with deterministic barriers; no credential resurrection |
| NoSQL/regex/prototype injection | Primitive schemas, operator-key rejection, escaped bounded search, allowlists | Controlled 400 with no unsafe query or unintended update |
| Token/code interception or mix-up | Exact redirects, PKCE S256, state/nonce, issuer/audience pinning | Code substitution, malicious redirects and nonce/state mismatch rejected |
| XSS/clickjacking/data leakage | CSP on actual served UI, escaping, local assets, anti-framing, no-store/referrer controls | Injection tests, header checks at edge and browser, no secrets in logs |
| Mail flooding/provider abuse | Durable multi-dimensional send budgets, encrypted bounded outbox | Provider outage/retry/cost-cap tests, no verification on acceptance |
| Data theft/key recovery | Protected adapter, per-account AEAD/keys, independent destruction ledger | Cross-account decrypt denial and pre-deletion snapshot restore test |
| DDoS/resource exhaustion | Hosting edge, gateway, quotas, deadlines, bounded expensive concurrency | Staging load/failure evidence; no fingerprint-only protection |

## 3. Protocol and token invariants

Consumers use `/api/auth/oauth2/authorize` and Authorization Code with PKCE S256. Preserve existing token, UserInfo, introspection, revocation, discovery and JWKS URLs. No implicit/password grant, credential relay, wildcard redirects or dynamic public registration. Validate registered redirects before redirecting errors.

Project contract requires random state verified by consumer on success/error, OIDC nonce and transaction binding. Pin issuer, intended audience and RS256 algorithm; validate expiry, subject, token purpose, authorized party when relevant and requested `auth_time`. Never treat ID tokens as API access tokens. Unknown key IDs cause a bounded configured-JWKS refresh, not arbitrary `jku` retrieval.

Access tokens are signed, not encrypted. Release claims only under granted scopes and owner privacy choices. Consumers tolerate missing email/profile. Online IdP endpoints reject revoked accounts/families; offline verifiers may accept an otherwise valid JWT for its remaining lifetime (currently up to 900 seconds). Immediate revocation requires online status checks and retiring consumer-local sessions.

Targeted family revoke affects `(clientId,familyId)` and does not increment global account versions. Global password reset/ban/revoke/deletion atomically advances tokenVersion and nondecreasing revocation timestamps. Issuance uses durable conditional transitions, not a final read followed by unfenced writes. Account/session/grant/policy checks apply equally to custom and plugin-active branches.

## 4. Algorithm and secret-purpose choices

| Purpose | Selected direction | Forbidden shortcut |
|---|---|---|
| Random credentials/handles | OS CSPRNG, at least 128-bit identifiers and 256-bit secret tokens | Math.random, UUID/time-derived OTP or predictable tokens |
| Password | Retain audited engine adaptive hash; inspect lockfile implementation, measure cost; Argon2id migration only through reviewed engine hooks | Reversible encryption, SHA-256 password hash or silent algorithm replacement |
| OTP verifier | Domain-separated HMAC-SHA-256 with separate secret and constant-time compare | Unsalted six-digit hash susceptible to offline enumeration |
| TOTP | RFC 6238 through engine; 30-second step and narrowly reviewed drift window | Custom TOTP, client-supplied MFA flags, accepting same step twice |
| PII encryption | AES-256-GCM, versioned per-account DEK, unique nonce, canonical AAD | XOR encryption, fixed nonce, one shared deletable key |
| Lookup indexes | Versioned purpose-separated HMAC-SHA-256 | Raw mailbox hash described as anonymous; trusting filter for uniqueness |
| Access/ID tokens | Existing RS256/JWKS profile and short expiry | Algorithm negotiation from untrusted headers, unsigned tokens |
| Service mail/events | Authenticated transport, signed body/timestamp/nonce or provider SDK verification | Unauthenticated callback marks account verified |
| Sessions/reset/backup | Digests/one-way storage where supported and atomic one-use semantics | Raw tokens in logs, account list or persistent browser storage |

Email verification establishes mailbox control. Email is not an out-of-band administrative MFA substitute. Password plus TOTP is MFA but is not phishing resistant. Passkeys/WebAuthn are a later explicit extension; do not advertise them as built. No generic collection of 'cybersecurity algorithms' substitutes for a threat/control/test mapping.

Key purposes are separated: JWT signing, engine secrets, OTP verifier, lookup index, mail payload, webhook signing and account data/wrapping. Use least-privilege secret access and rotation. Do not silently reuse `BETTER_AUTH_SECRET` for every new purpose. In-flight versions must be bounded and old proofs invalidated safely on key rotation.

## 5. Enrollment and recovery invariant

[AUTHENTICATION_FLOWS.md](AUTHENTICATION_FLOWS.md) is authoritative for OTP state and bypass closure. No user/credential/session before valid proof consumed in the finalization transaction. No admin-created `emailVerified=true` without verified claiming. Ordinary existing unverified users need an audited re-verification rollout; grace cannot bypass bans, revocation, password-change or deletion checks.

Password reset never disables MFA or converts unverified identity to verified. Recovery credentials are single-use and audited; administrative lost-factor recovery cannot be email-only. Unenrolled admins have setup-only authority and cannot use plugin admin APIs, bearer/cookie alternatives or social login to bypass it.

## 6. Accounts, sessions and administration

[SESSION_MODEL.md](SESSION_MODEL.md) defines explicit context binding. A chosen label/fingerprint is never authorization. Reauthenticate the same subject for sensitive operations and bind action receipts to payload/purpose. A session set carries no aggregated privileges. Role changes, reset/recovery, bans and deletion invalidate prior elevated authority.

Every administrative path, including direct engine/plugin endpoints, enforces explicit role, canonical client scope, audience, completed TOTP and recent MFA. Keep `user`, `app-admin` and `super-admin` distinct per identity. Super admins have platform authority, not automatic consumer admin rights. Optional user TOTP is enforced once enabled, not displayed as a decorative setting.

## 7. Privacy, encryption and deletion

[DATA_LIFECYCLE.md](DATA_LIFECYCLE.md) owns field classification, adapter coverage, key inventory and deletion states. Admin lists/search/logs/exports return chosen username or legacy local-part label plus opaque ID; UI column hiding is insufficient. Full owner contact is available to owner and necessary delivery components, not general administrator decrypt privileges.

Delete first commits durable access denial/version change and recoverable work, then destroys keys and purges residual records. Shared surviving wrapping keys plus restorable account DEKs do not meet irreversible erasure. Missing key/deletion services fail closed for protected reads. Never restore erased keys or denied users while rolling back/repairing a deployment. Exact retention and exceptional operational access require documented narrow policy and audit, not a super-admin wildcard.

## 8. Availability and device risk

[ABUSE_DEFENSE.md](ABUSE_DEFENSE.md) defines admission, risk, cache and filter contracts. Maintain fail-closed auth/admin behavior on dual quota-store failure, including signup/OTP/reset and future identity routes outside `/api/auth/*`. A process-local limiter is insufficient for a fleet-wide sensitive budget.

Fingerprints are optional short-lived risk observations, not identity/MFA or DDoS prevention. Never require persistent canvas/audio tracking, infer account linking from browser similarity or authorize from a trusted-device string. Missing signals never bypass rate limits. Bloom/XOR/approximate structures remain optional performance experiments and cannot decide security state.

## 9. Security release and open-source requirements

Use [security-suite-manifest.json](security/security-suite-manifest.json) as executable inventory, not fixed prose counts. New tests ship with each slice and enter CI/manifests in that implementation, preserving current assertions. Evidence distinguishes source inspection, function mocks, application-instance tests, real disposable services, separate workers, browser flows, live provider, key-service and restore tests.

Open-source release includes license and dependency provenance/SBOM, dependency/secret history review and actual credential rotation, supported Node/DB/Redis versions, versioned migrations and self-host instructions, a private vulnerability disclosure route with response process, security release/update policy and an external review before claiming public readiness. Generated secret-bearing gateway config remains untracked. No production data in fixtures or unsolicited live penetration testing.

## 10. Primary references

- [OAuth security BCP, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [TOTP, RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)
- [Argon2, RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- [NIST authentication guidance](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [Better Auth multi-session documentation](https://better-auth.com/docs/plugins/multi-session)

These sources guide specific decisions; they do not certify SWYRA or verify its runtime behavior. Google-like UX is a product goal, not a security assurance level.
