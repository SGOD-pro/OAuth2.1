# 0008. Verified multi-account identity platform

**Date:** 2026-11-19.
**Status:** Proposed implementation specification. No runtime implementation in this change.
**Baseline:** `main` at `161ad99ca4ba0de88cff1267b33807db61da306c`.

## Problem and intended behavior

SWYRA currently has one active IdP browser context and app-coupled registration
bookkeeping. The target lets a person create distinct verified accounts, keep multiple
account sessions on one browser profile, select a valid session for consumer login,
control their privacy, and delete an account without a large synchronous data cascade.
It retains registered clients, private-app memberships, super-admin authority and
app-admin isolation. It does not promise feature/security equivalence with Google.

## Decisions and assumptions

- Multiple accounts mean distinct verified mailboxes, one identity per normalized email.
  Keep password login. Email OTP is required for enrollment, not a replacement for
  TOTP or automatic proof of administrative assurance.
- Open applications require no membership prerequisite. Registered clients, consent,
  requested scopes, disabled-client checks and protocol protections remain mandatory.
- Private applications retain explicit memberships and controlled provisioning.
  Creating a platform account does not assign it to a private app.
- Split proposed `clientType`, `accessPolicy`, and existing `isDev`. Do not infer
  confidentiality from legacy `isPublic`.
- Keep existing endpoints and stable `userId` subjects. Pairwise subject migration is
  a separately versioned future decision, not silently introduced here.
- Replace the one-active-IdP-account policy only after independent sessions are proven.
  Super and app admins remain different accounts with separate purpose-bound sessions.
- Administrative TOTP is mandatory. No admin email verification by assertion alone.
- Ordinary admin output uses username or local-part display labels. Email is not an
  authorization key and the local part is not unique or anonymous.
- Per-account keys cover classified data. Key destruction does not replace revocation,
  metadata cleanup, deletion logs, or consumer-side deletion obligations.
- First-party resettable browser IDs plus coarse risk signals support abuse detection.
  No fingerprint-derived authentication or claim that fingerprints stop DDoS.
- Bloom filters are optional future hints; database constraints remain authoritative.

## Required components and invariants

| Component | Minimum proposed fields | Invariant |
|---|---|---|
| Registration intent | Random ID, encrypted email, keyed lookup/verifier, purpose, expiry, attempts, send budget, proof status | No account before verification; atomic consume; no raw password or code |
| Identity | Random `userId`, username, verified contact, account status/version, role | Unique email/username; no ID reuse or privilege injection |
| Browser session set | Random handle digest, entries of account/session references, version, expiry | Bound to authenticated sessions; 10-entry initial cap; not physical device identity |
| Per-account session | Account/session IDs, browser-set reference, auth/MFA times, expiry, assurance, revocation version, purpose | No session sharing or ambient admin privilege across accounts |
| Authorization transaction | Random ID, selected subject/session/version, client, redirect, state, nonce, PKCE, scope, consent, expiry | Selection and issuance bound to one transaction; single-use code |
| Consent | Account/client, granted scopes, grant version, timestamps | No public-app membership prerequisite; scope expansions require consent |
| Private membership/admin assignment | Immutable account/client IDs, explicit role/status | Ordinary open-app history cannot grant admin/private access |
| Protected data | Ciphertext, nonce/tag, schema/key version and AAD binding | Cross-account decrypt fails; deleted account denied before key/cache use |
| Deletion job/tombstone | Account ID/version, state, checkpoints, key inventory, retry and proof references | Durable denial first; monotonic states; no plaintext PII in tombstone |

Exact collection names and plugin schema mappings are finalized in bounded implementation
specifications after inspecting actual engine behavior. Do not implement the above as
unreviewed parallel collections that bypass the engine's session/token guarantees.

## Endpoint contracts

Existing protocol paths remain unchanged. The following are proposed IdP-internal API
contracts, not currently available endpoints and not consumer integration requirements.
All identity operations require strict origin/CSRF checks, typed bodies, request limits,
no-store responses, and server-side subject binding.

| Proposed action | Suggested route | Required authority |
|---|---|---|
| Start/resend registration | `POST /api/identity/registration/start`, `/resend` | Anonymous bounded registration transaction; generic response |
| Verify mailbox code | `POST /api/identity/registration/verify` | Intent ID and code; atomic attempt and proof handling |
| Finalize account | `POST /api/identity/registration/complete` | One-use verified proof, chosen username, password; atomic uniqueness |
| List signed-in accounts | `GET /api/identity/accounts` | IdP browser session-set proof only, never consumer access token |
| Choose account | `POST /api/identity/accounts/select` | CSRF, bound OAuth transaction, validated selected session |
| Remove remembered account | `POST /api/identity/accounts/remove` | Browser-set ownership; explicit operation semantics |
| Own profile/privacy | `GET/PATCH /api/identity/me` | Bound account session; field allowlist; recent auth for sensitive changes |
| Own grants/sessions | `GET /api/identity/me/grants`, `/sessions` | Account ownership; no other account IDs from request trusted |
| Revoke a grant/session | `POST /api/identity/me/grants/:id/revoke`, `/sessions/:id/revoke` | Owned object; recent auth as policy requires |
| Request/retrieve export | `POST/GET /api/identity/me/export` | Recent reauthentication; owner-only short-lived retrieval |
| Delete account/status | `POST /api/identity/me/deletion`, `GET /api/identity/me/deletion` | Recent reauthentication and explicit confirmation; status bound to deletion receipt |

A deletion status receipt has narrow read-only authority after session revocation,
is stored as a digest, expires, and cannot decrypt data or authorize account recovery.
No GET changes account/session state. Publish exact routes, errors and schemas only
with the implementing slice. Keep new identity routes outside broad consumer CORS.

## Acceptance criteria

- **AC-1:** Every token/session/online status boundary denies ineligible accounts,
  including plugin-active introspection; deletion and revocation win issuance races.
- **AC-2:** Invalid, expired, exhausted, resent or replayed OTPs create zero durable
  users/accounts/credentials/sessions/memberships. Concurrent valid finalization produces
  exactly one account under database unique constraints and atomic proof consumption.
- **AC-3:** Users choose normalized unique usernames. Identical email local parts from
  different domains do not collide as identities or leak full emails in admin output.
- **AC-4:** Open apps authorize eligible consented users without app membership;
  private apps reject unassigned users; all three client dimensions remain independent.
- **AC-5:** Two accounts stay signed in independently. Selecting A in tab A and B in
  tab B issues codes/tokens for the correct account without global-context races.
- **AC-6:** Expired/revoked sessions require login. OIDC prompt/max_age/nonce semantics
  are tested, including ambiguous `prompt=none` and invalid prompt combinations.
- **AC-7:** App/super admin authority always requires completed TOTP and recent MFA,
  with enrollment-only sessions and no plugin/social/bearer/recovery bypass.
- **AC-8:** Own-account dashboard, exports, privacy settings, grants and session
  revocation enforce server-side ownership; full email is absent from ordinary admin
  lists/search/export/log paths, and claims follow consented scopes.
- **AC-9:** Protected account fields use reviewed AEAD and per-account key versions;
  secrets/PII never escape through backups, queues, caches, tokens or logs contrary
  to the declared field inventory. Document residual metadata explicitly.
- **AC-10:** Deletion commits durable denial before asynchronous cleanup, destroys all
  recoverable account key paths before claiming erasure, and survives worker failure
  and pre-deletion backup restore without account resurrection.
- **AC-11:** Distributed quotas and edge controls bound signup/OTP/recovery costs and
  load. Fingerprints and Bloom filters never become security authorities.
- **AC-12:** Existing clients/API paths and private/admin isolation pass regression
  checks. Open-source release includes license/provenance and disclosure procedures,
  secret/dependency audit, self-host instructions and measured release evidence.

## Build plan

See [PHASES.md](../../PHASES.md) for ordering and exit tests. All unchecked.

- [ ] 0. Close baseline token/account eligibility gaps with real-route regression tests.
- [ ] 1. Separate client authentication type from open/private access and audit migration.
- [ ] 2. Add verified enrollment, safe username constraints and bounded mail delivery.
- [ ] 3. Enforce mandatory administrative TOTP and recovery/promotion revocation rules.
- [ ] 4. Add independent account sessions and transaction-bound chooser/OIDC behavior.
- [ ] 5. Add privacy dashboard, minimized serializers, scope controls and own-account APIs.
- [ ] 6. Select and prove account key service, then migrate classified data encryption.
- [ ] 7. Add deletion denial, key destruction, bounded cleanup and restore validation.
- [ ] 8. Validate distributed abuse controls and load/cost budgets before open rollout.
- [ ] 9. Complete release provenance, documentation, security reporting and external review.

## Unresolved decisions and limits

Key-service choice, verified-email provenance migration, email normalization collisions,
mail delivery provider, production quota sizing, admin recovery custody, precise data
retention, and consumer deletion notification contract require measured decisions in
those slices. They do not block documenting the target or phase 0 hardening.
No code implementation, model training, deployment or data migration is included here.

## Validation

[Baseline review](../../reviews/2026-11-19-identity-platform-baseline.md) separates
reported tests, independently executed checks, source findings and blocked database
suites. Future implementation must record real browser, multi-process, replica-set,
Redis, key-service and restore evidence at the exact reviewed commit.
