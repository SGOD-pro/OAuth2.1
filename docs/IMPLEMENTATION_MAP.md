# V2 implementation map: where, what and how

**Status:** Planned work, no files below are implemented by this docs change. Updated 2026-11-22.
Baseline inspected: main `161ad99` and security branch `0a5727e`. Preserve hardening before implementation. Source paths in code formatting are navigation targets or proposed files, not claims they already exist.

## 1. Rules for changing the existing code

Use the existing credential engine and protocol routes. Extract narrow policy/services from the large `auth.ts` file as needed, keeping route contracts stable and regression evidence intact. Do not rename collections or move unrelated code simply to match this proposed layout. New module names may be consolidated when the implementing slice demonstrates a smaller compatible design.

| Existing file | Change | Why / how to verify |
|---|---|---|
| `backend/src/app.ts` | Mount proposed identity router, same-origin CORS/CSRF, sensitive admission and no-store headers | `/api/identity/*` must not inherit consumer token-route exceptions; direct-origin and CSRF tests |
| `backend/src/routes/auth.ts` | Route signup/login through enrollment/session services; bind authorize/consent/code/refresh to selected context | Close plugin signup bypass; preserve tokenVersion/family fences; A/B interleaving and old consumers |
| `backend/src/utils/auth.ts` | Engine adapter/hooks, supported multi-session and profile/username integration, protected writer mapping | No duplicate auth framework; inspect installed APIs and real engine writes |
| `backend/src/utils/account-eligibility.ts` | Extend existing shared predicate to V2 status/session/key/consent policy inputs as appropriate | No early grace bypass, no raw email-as-sub, all online endpoints deny deletion |
| `backend/src/db/state.ts` | Add versioned transaction/index/state helpers; preserve refresh rotation/revocation | Mongo transaction/conditional-write race tests; no process-only locks |
| `backend/src/db/mongo.ts` | Support request/worker sessions and transaction context propagation | All finalization writes share the same database session; real replica-set proof |
| `backend/src/middleware/admin-auth.ts` | Require purpose/context plus existing role/audience/MFA on all admin branches | Consumer/platform scope, bearer/cookie conflict and setup-only denial |
| `backend/src/routes/app-admin-auth.ts` | Retain zero-password-relay contract; integrate MFA continuation with selected session | Consumer app never collects IdP credentials; no alternate admin login bypass |
| `backend/src/routes/admin.ts` | Three client dimensions; invitations; minimized user projections/search; deletion separate from admin removal | Super-only client trust flags, private-member survival, no PII leaks |
| `backend/src/utils/admin-sync.ts` | Preserve explicit roles; invitation claiming activates assignments only after proof/MFA | No auto-verification or resurrection of revoked memberships |
| `backend/src/utils/security.ts` | Central normalization/username/owner serializers and request validation helpers | Reserved names, collisions, injection and stable subject tests |
| `backend/src/middleware/rate-limit.ts` | Extend sensitive endpoint classifiers and durable cost budgets | New routes cannot accidentally get public fallback; failover/outage tests |
| `backend/src/middleware/cors.ts`, `csrf.ts` | Explicit UI-only identity policy; preserve origin cache safety | Consumer origin cannot list browser accounts, read profile or mutate owner context |
| `backend/src/cache/redis.ts`, `origin-cache.ts` | Typed quotas/safe metadata caches; versioned invalidation | Stale positives never authorize; keep existing CORS lease/tombstone tests |
| `backend/src/config/schema.ts`, `index.ts`, `env.ts` | Typed proposed policy settings, key references, limits and cross-field validation | Production cannot enable enrollment without queue/provider/proof keys; no runtime unvalidated bypass |
| `backend/scripts/db-setup.ts` | Add indexes only with migrations/dry-run validation | Missing unique indexes stop enrollment; duplicate reports before enforcement |
| `backend/scripts/create-admin.ts`, `migrate-app-admins.ts`, `migrate-identity-roles.ts` | Verified invitation/bootstrap policy, no asserted mailbox ownership | Existing admin migration never creates unenrolled privileged authority |
| `.github/workflows/ci.yml` | Add new suites and replica-set/mail/Redis infrastructure as slices land | Docs-only checks; real process/browser fixtures; no skipped checks labeled pass |
| `backend/template.yaml`, `backend/deploy.sh`, `scripts/prepare-vercel-config.mjs` | Narrow worker IAM, queue/key secret wiring and route headers | No key/provider secret in browser bundle or generated tracked gateway config |

## 2. Proposed backend modules and responsibilities

| Proposed path | Responsibility | Slice |
|---|---|---|
| `backend/src/routes/identity.ts` | Thin identity API routing, schema/CSRF/context gates | P2 onward |
| `backend/src/identity/registration.ts` | Intent, generations, proof consume, idempotent finalization | P2 |
| `backend/src/identity/engine-adapter.ts` | Transaction-aware engine creation/session validation/protected writer boundary | P0, P2, P3, P6 |
| `backend/src/identity/client-policy.ts` | Resolve independent client dimensions and migration compatibility | P1 |
| `backend/src/identity/sessions.ts` | Browser registry, session status, account-bound contexts | P3 |
| `backend/src/identity/authorization-context.ts` | Selected OAuth principal, revision/consent/issuance fence | P3 |
| `backend/src/identity/mfa-policy.ts` | Common enrollment/challenge/recent-auth/recovery policy using engine | P4 |
| `backend/src/identity/profile.ts`, `privacy.ts` | Owner projection and optional-claim policy | P5 |
| `backend/src/identity/data-protection.ts`, `key-service.ts` | Field envelopes, key provider interface, version/AAD and denial | P6 |
| `backend/src/identity/deletion.ts`, `export.ts` | Durable jobs, subject binding and status receipts | P5, P7 |
| `backend/src/identity/risk.ts` | Versioned explainable risk rules, short-lived observations | P8 |
| `backend/src/mail/service.ts`, `templates.ts`, `transport.ts` | Budgeted encrypted outbox and provider-neutral delivery | P2 |
| `backend/src/workers/mail.ts`, `export.ts`, `deletion.ts` | Separate bounded leased worker entrypoints | P2, P5, P7 |
| `backend/scripts/migrations/` | Versioned dry-run/checkpoint/apply/status migrations | Each data slice |

Interfaces must take explicit immutable subject/context and transaction/session, not read an ambient globally selected user. Services never accept an owner ID from request body as proof. Keep jobs out of synchronous login responses except durable enqueue/denial commits.

## 3. Frontend change map

| Existing file/group | Required change | Acceptance |
|---|---|---|
| `frontend/src/App.tsx` | Add page inventory from USER_EXPERIENCE; standalone own-account and login routes | Account portal works without OAuth query; legacy URLs preserved |
| `frontend/components/Layout.tsx`, `hooks/useOAuthParams.ts` | Distinguish validated OAuth continuation from standalone identity pages | No invented callback on missing params; malformed consumer flow still rejected |
| `frontend/pages/SignIn.tsx` | Shared email/username login and Add account continuation | Does not sign out A to add B; no browser token storage |
| `frontend/pages/TwoFactor.tsx`, `pages/admin/AdminTwoFactor.tsx` | Shared challenge UI with separate authority/purpose | No dashboard data before MFA; stale step-up resumes exact operation |
| `frontend/pages/Consent.tsx`, `AuthCallback.tsx` | Render bound account/app/scopes and safe continuation | Switching account invalidates old consent; callback state/nonce retained |
| `frontend/pages/ForgotPassword.tsx`, `ResetPassword.tsx` | Generic request, reset proof, policy-preserving reauth | TOTP retained, old credentials revoked |
| `frontend/pages/SignOut.tsx` | Explicit account/browser/consumer logout semantics | No accidental global signout when selecting another account |
| `frontend/pages/admin/RegisterAppModal.tsx`, `EditAppModal.tsx` | Separate clientType/accessPolicy/isDev with explanations | Private/open and public/confidential combinations exercised |
| `frontend/pages/admin/ProvisionAdminModal.tsx`, `AdminSecurity.tsx` | Verified invite status and mandatory MFA lifecycle | No temporary-password email or verification checkbox |
| `frontend/pages/admin/AdminLogs.tsx`, `lib/adminStore.ts` | Minimized server fields and account/context-aware state | Cache cannot reuse account A data for B; no hidden full email |
| `frontend/lib/auth-client.ts`, `api.ts`, `csrf.ts`, `security.ts` | Supported engine hooks plus narrow identity context transport | No session tokens returned to JS; CSRF and context version checks |
| `frontend/components/AdminRoute.tsx` | Purpose-specific UX guards only | Backend remains authority; direct HTTP tests remain mandatory |
| New `frontend/pages/account/*`, registration/chooser pages | Implement inventory in USER_EXPERIENCE using existing primitives | Owner flows and denial/loading/expiry/accessibility states |

New frontend hooks may manage the current tab context in memory. No global zustand 'activeUser' may choose the server subject. Client cache keys include context/account version and are purged on context logout/revoke. Reuse existing theme tokens and CSS motion; no broad UI redesign/dependency additions in authentication slices.

## 4. Data migration sequence

| Migration | Before apply | Apply/checkpoint | Rollback boundary |
|---|---|---|---|
| M0 baseline | Security PR integrated; schema/collection inventory | Record reader/writer versions and source SHA | No baseline security downgrade |
| M1 client policy | Classify auth methods and `isPublic`; report ambiguous clients | Add explicit fields/version with compatibility reads, scoped writers | Keep private policies; no automatic secret rotation |
| M2 identity lookup | Audit normalized email collisions and existing verification provenance | Add username/lookup uniqueness, registration/proof/outbox indexes | Disable new registration; never unverify/merge user identities by guess |
| M3 browser sessions | Installed engine integration proven | Add registry/context/session linkage; old sessions reauth into new set | Stop adding accounts; retain revocation and context-bound sessions |
| M4 assurance | Admin invite/recovery paths audited | Ensure verified claiming and completed MFA; rotate outdated elevated sessions | Never remove MFA to roll back UI |
| M5 privacy | Inventory old response/claim consumers | Minimized serializers, grants/privacy versions and context-bound APIs | Consumers tolerate missing optional fields; no fallback full-email release |
| M6 encryption | Key backend selected, writer/backup inventory proven | Dual readers, protected writers, checkpointed backfill, plaintext purge | No plaintext write fallback or erased-key restoration |
| M7 deletion | Independent ledger/restore and key destruction proven | Durable denial/outbox, workers, final receipts, residual cleanup | Irreversible after denial/destruction; pause workers, never reactivate |

Migration scripts are not added by this docs change. Each implementing PR defines exact CLI, dry-run JSON counts, duplicate/ambiguity report, batch size, lease/fence, restart checkpoint and previous-reader compatibility test. Document actual commands only when they exist.

## 5. Test placement and traceability

Extend existing `oauth-security-hardening.test.ts`, `adversarial-role-tampering.test.ts`, `membership-lifecycle.test.ts`, `test-rate-limit-failure-modes.ts`, `cors-cache-correctness.test.ts` and real process/browser harnesses rather than copying away their assertions. New proposed suites: verified-registration, multi-account-browser, identity-owner-privacy, protected-adapter, deletion-restore and risk-quota tests under the existing unit/security/e2e directories.

For every acceptance criterion in 0008, record suite/scenario, exact commit, service versions and test category. Add scripts and `docs/security/security-suite-manifest.json` entries with runtime implementation. A docs-only PR must not list future routes in the current executable `security-route-manifest.json` or claim nonexistent suites ran.
