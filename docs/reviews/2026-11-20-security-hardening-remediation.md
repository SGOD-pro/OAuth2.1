# OAuth 2.1 Security Hardening and Remediation Report

**Date:** 2026-11-20  
**Branch:** `fix/oauth-security-hardening`  
**Base HEAD:** `161ad99ca4ba0de88cff1267b33807db61da306c` (`origin/main`)  
**Scope:** Remediation of findings SEC-01 through SEC-06 and follow up security blockers across four bounded slices: Account Eligibility, Scope and Privacy Enforcement, Administrative MFA, and Verification and Abuse Controls.  
**Verdict:** All security defects and blocker findings have been remediated with real route regression coverage and verified across passing suites. V2 feature development remains deferred until this security remediation is reviewed and integrated.

---

## 1. Remediation Summary by Slice

### Slice 1: Account Eligibility and Token Lifecycle (SEC-01, SEC-02)
* **Authoritative Account Eligibility Policy:** Implemented in [backend/src/utils/account-eligibility.ts](file:///home/swyra/projects/OAuth2.1/backend/src/utils/account-eligibility.ts) through `checkAccountEligibility(user, options)`. Uniformly rejects missing, banned (`banned === true`), disabled (`disabled === true`), inactive (`isActive === false` or `status === "inactive"`), deleting (`status === "deleting"`), and deleted (`deletedAt` or `status === "deleted"`) accounts.
* **Rollout Grace Safety:** Removed early return in rollout verification grace. Accounts within an email verification grace window never bypass account status, password change, or revocation checks.
* **Same Second Revocation Handling:** Enhanced `checkAccountEligibility` and token verification with millisecond timestamps (`tokenIssuedAtMs` and `revokedMs`) and monotonic account token versions (`tokenVersion`). When tokens and revocations occur in the same second, millisecond precision accurately distinguishes credentials issued before revocation from credentials issued after revocation. Integer second legacy tokens within the revocation second fail closed safely.
* **Atomic Authorization Fences:** Added atomic authorization fences in [backend/src/routes/auth.ts](file:///home/swyra/projects/OAuth2.1/backend/src/routes/auth.ts) across both authorization code exchange and refresh token rotation. If an account is revoked concurrently while exchange or refresh is in flight, the atomic fence immediately purges all minted access tokens, refresh tokens, and token families, returning `400 invalid_grant` or `401 invalid_grant`.
* **Token Minting and Issuance Guard:** Updated `mintJwtAccessToken` in [backend/src/routes/auth.ts](file:///home/swyra/projects/OAuth2.1/backend/src/routes/auth.ts) to verify database user eligibility, millisecond revocation timestamps, and token versions before signing or returning RS256 JWTs.
* **Authorization Endpoint:** Added fresh database account eligibility enforcement in `GET /api/auth/oauth2/authorize`. Active sessions bound to ineligible users immediately redirect to the registered redirect URI with `302 error=access_denied`.
* **UserInfo Endpoint:** Enforced fresh database account eligibility in `GET /api/auth/oauth2/userinfo`. Banned, disabled, or revoked account tokens immediately return `401 Unauthorized`.
* **Dual Branch Token Introspection:**
  * Plugin active branch: Verifies account eligibility, client active state, and revocation status even when Better Auth identifies the token as active.
  * Custom JWT fallback branch: Cryptographically verifies RS256 signature, validates expiration, checks token presence in `oauthAccessToken` revocation backstop, and verifies account eligibility via immutable subject lookup.
* **Subject Immutability:** Removed email fallback identity resolution from authorization, token issuance, userinfo, and introspection. Identity lookup is strictly anchored to immutable `id` or `_id` to prevent identity spoofing or account takeover via email recycling.

### Slice 2: Scope and Privacy Enforcement (SEC-05)
* **Scope Restricted Claims:** Updated `mintJwtAccessToken` and `/oauth2/userinfo` to release `email` and `email_verified` claims strictly when `email` scope is granted, and `name` strictly when `profile` scope is granted. Protocol level claims (`sub`, `iss`, `aud`, `client_id`, `role`, `scoped_client_id`) are preserved.
* **Server Side Data Minimization:** Updated `GET /api/admin/users`, `GET /api/admin/clients/:clientId/users`, `GET /api/admin/clients/:clientId/app-admins`, and Better Auth user listing (`GET /api/auth/admin/list-users`) to project masked display labels (`toApprovedDisplayLabel`), sanitize cleartext email fields, and mask email shaped name fields (`isEmailShaped`). Cleartext emails are never returned in listings.

### Slice 3: Administrative MFA (SEC-04)
* **Mandatory Admin Enrollment:** Added `checkAdminMfa` to [backend/src/middleware/admin-auth.ts](file:///home/swyra/projects/OAuth2.1/backend/src/middleware/admin-auth.ts), enforced across `requireAdmin`, `requireSuperAdmin`, and `requireScopedAdmin`. Administrators without enrolled TOTP (`twoFactorEnabled !== true`) receive setup only authority (`403 ERR_MFA_ENROLLMENT_REQUIRED`), permitting access only to MFA setup and sign out endpoints (`/api/auth/two-factor/*`, `/api/admin/me`, `/api/auth/sign-out`).
* **Genuine MFA Challenge and Session Verification:** Replaced simulated test signed bearer claims with genuine protocol execution. Administrators undergo enrollment via `/api/auth/two-factor/enable`, RFC 6238 TOTP computation and verification via `/api/auth/two-factor/verify-totp`, challenge cookie validation, password only rejection, and session cookie issuance.
* **Privileged Admin Access Verification:** Completed MFA sessions access privileged endpoints (`/api/admin/clients`, `/api/auth/admin/list-users`) with HTTP 200 (never accepting 404).
* **Sensitive Operation Freshness:** Enforced `requireRecentMfa` requiring MFA verification within the last 15 minutes (`ERR_MFA_STEP_UP_REQUIRED`). Stale sessions older than 15 minutes are blocked on administrative mutations (`POST`, `PUT`, `PATCH`, `DELETE`).
* **Single Use Recovery Codes:** Verified single use backup code challenge verification and proved that replaying the same recovery code is rejected.
* **Admin Setup Endpoint:** Added `GET /api/admin/me` in [backend/src/routes/admin.ts](file:///home/swyra/projects/OAuth2.1/backend/src/routes/admin.ts) allowing unenrolled administrators to inspect their identity and MFA status to initiate enrollment.

### Slice 4: Verification and Abuse Controls (SEC-03, SEC-06)
* **Typed Transport Configuration:** Added `EMAIL_DELIVERY_WEBHOOK_URL`, `AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE`, and `AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER` to Zod schema in [backend/src/config/schema.ts](file:///home/swyra/projects/OAuth2.1/backend/src/config/schema.ts) and typed getters in [backend/src/config/index.ts](file:///home/swyra/projects/OAuth2.1/backend/src/config/index.ts). If email verification is enabled without a usable webhook URL, the application fails closed explicitly.
* **Production Transport Security:** In production mode, webhook URLs must use HTTPS and cannot target loopback addresses.
* **Bounded Timeout and Error Handling:** Configured `sendVerificationEmail` in [backend/src/utils/auth.ts](file:///home/swyra/projects/OAuth2.1/backend/src/utils/auth.ts) with `AbortSignal.timeout(5000)`, explicit non 2xx status rejection, and zero logging or leakage of verification tokens or URLs.
* **Deployment and Configuration Documentation:** Documented webhook configuration and rollout modes in [docs/CONFIGURATION.md](file:///home/swyra/projects/OAuth2.1/docs/CONFIGURATION.md) and [docs/DEPLOYMENT.md](file:///home/swyra/projects/OAuth2.1/docs/DEPLOYMENT.md).
* **Safe Rollout Policy:** Supported rollout grace periods in `checkAccountEligibility`:
  * `AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE="enforce_new"`: Enforces verification strictly on accounts created after `AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER`, while grandfathering existing accounts without falsely marking them verified in the database.
  * `AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE="enforce_all"`: Strictly requires `emailVerified: true` for all accounts once external email delivery is operational.
* **Fail Closed Dual Store Rate Limiting:** Updated [backend/src/middleware/rate-limit.ts](file:///home/swyra/projects/OAuth2.1/backend/src/middleware/rate-limit.ts) so that when backing stores fail, sensitive authentication budgets strictly fail closed with `429 Too Many Requests` rather than falling back to an unshared in memory limiter.

---

## 2. Verification Evidence at Exact HEAD

### Verification Suite Results

| Suite or Script | Command | Result | Details |
|---|---|---|---|
| Doc Consistency | `npm run security:docs-check` | **PASS** | 6 checks passed cleanly (0 errors) |
| Integration Contract | `npm run security:integration-check` | **PASS** | 5 normative checks passed (0 violations) |
| Unit Test Suite | `npm run test:unit` | **PASS** | 10 unit suites passed cleanly (0 failures) |
| OAuth Hardening | `npm run test:oauth-hardening` | **PASS** | 23/23 comprehensive regression checks passed |

### Test Methodology Breakdown

To ensure rigorous evidence, tests in [backend/tests/security/oauth-security-hardening.test.ts](file:///home/swyra/projects/OAuth2.1/backend/tests/security/oauth-security-hardening.test.ts) are categorized by methodology:

#### A. Genuine Protocol Execution vs Simulated State
* **Genuine MFA (SEC-04-D):** Executes genuine Better Auth flows including password authentication, 2FA challenge issuance, RFC 6238 TOTP computation and verification, session cookie issuance, and HTTP 200 privileged access. Does not rely on test signed mock bearer claims.
* **Simulated State (SEC-04-A, SEC-04-B, SEC-04-C):** Probes access control boundaries with simulated database user states and token claims to verify middleware enforcement rules in isolation.

#### B. Concurrency Tests vs Sequential Tests
* **Multi Worker Concurrency Race (SEC-01-I):** Spawns an independent `worker_threads` worker with separate database connection against disposable MongoDB. Uses deterministic barriers (`setTokenBarrierHookForTesting`) to trigger worker account revocation while code exchange or refresh token rotation is in flight. Proves that the atomic authorization fence halts token issuance and purges all surviving tokens and token families.
* **Sequential Pre Revocation Fixtures (SEC-01-H, SEC-01-J):** Validates deterministic rejection of older credentials and same second credentials issued before revocation timestamps under sequential test execution.

#### C. Infrastructure Limitations and Blocked Checks
* **Redis CORS Invalidation Suite (`tests/security/cors-cache-correctness.test.ts`):** **BLOCKED**. This suite attempts to spawn a disposable Docker container running Redis Alpine (`docker run -d ... redis:8.8.3-alpine`). In the sandbox environment, no Docker daemon is available (`/var/run/docker.sock` does not exist). In accordance with instructions, this is reported as **BLOCKED**, never marked as PASS.

### Detailed Test Assertions in `oauth-security-hardening.test.ts`
1. **SEC-01-A:** `checkAccountEligibility` rejects missing, banned, disabled, inactive, deleting, deleted, and unverified accounts.
2. **SEC-01-B:** `mintJwtAccessToken` rejects ineligible accounts (missing, banned, disabled).
3. **SEC-01-C:** `mintJwtAccessToken` rejects tokens revoked before issue time (`tokensRevokedBefore`).
4. **SEC-01-J:** Same second credential issuance and revocation handling with millisecond precision and monotonic token versions. Tokens issued after revocation within the same second succeed; tokens issued before revocation within the same second are rejected; legacy integer second tokens fail closed safely.
5. **SEC-05-A:** `mintJwtAccessToken` minimizes claims strictly to granted scopes (`openid`, `email`, `profile`).
6. **SEC-01-D:** `GET /oauth2/authorize` rejects active session of banned user with `302 error=access_denied`.
7. **SEC-01-E:** `GET /oauth2/userinfo` rejects tokens for banned or revoked accounts with `401`.
8. **SEC-02-A:** `POST /oauth2/introspect` returns `active: true` for active user and `active: false` for banned or revoked user.
9. **SEC-05-B:** `GET /oauth2/userinfo` releases claims only under granted scopes (omits email without `email` scope, omits name without `profile` scope).
10. **SEC-04-A:** Unenrolled administrator is denied privileged access (`403 ERR_MFA_ENROLLMENT_REQUIRED`) and allowed setup access (`GET /api/admin/me` returning 200).
11. **SEC-04-B:** Enrolled administrator with unverified session receives `403 ERR_MFA_REQUIRED`.
12. **SEC-04-C:** Sensitive operation (`DELETE /api/admin/clients/:id`) requires recent MFA (< 15 min), rejecting stale MFA (> 15 min) with `403 ERR_MFA_STEP_UP_REQUIRED`.
13. **SEC-03-A:** Email verification safe rollout grandfathering verified without falsifying database records.
14. **SEC-06-A:** Auth sensitive rate limiter fails closed under dual store outage with `429`.
15. **SEC-05-C:** Admin user listing (`GET /api/admin/users`) strips plain email and enforces server side masked display labels.
16. **SEC-01-F:** Token introspection enforces immutable subject ownership without email fallback.
17. **SEC-01-G:** Refresh token exchange (`POST /oauth2/token`) rejects banned or disabled users with `401 invalid_grant`.
18. **SEC-03-B:** Verification grace window never skips revocation, password change, or account status checks.
19. **SEC-01-H:** Revocation wins code exchange and refresh with older credentials using credential issuance timestamps (`createdAt` or `iat`).
20. **SEC-01-I:** Revocation wins overlapping code exchange and refresh under concurrent multi worker race with deterministic barrier, proving zero surviving tokens across access tokens, refresh tokens, and token families.
21. **SEC-04-D:** Better Auth internal admin routes (`/api/auth/admin/*`) enforce mandatory MFA and sensitive action freshness, verified with genuine enrollment, RFC 6238 TOTP challenge verification, HTTP 200 privileged access, stale MFA step up rejection, and single use recovery codes.
22. **SEC-03-C:** Email verification delivery transport validation, typed configuration, bounded 5000ms timeout, non 2xx handling, and secret free logging.
23. **SEC-05-D:** Admin privacy projections across app admin listings (`GET /api/admin/clients/:clientId/app-admins`) and email shaped name fields.

---

## 3. Remaining Blockers Before V2

1. **External Email Transport:** Production deployment requires provisioning an SMTP, SES, or Resend delivery channel and configuring `EMAIL_DELIVERY_WEBHOOK_URL` before switching `AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE="enforce_all"`.
2. **Upstash Redis Configuration:** Distributed rate limiting requires configuring `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` in production to prevent fallback to MongoDB or fail closed behavior under load.
3. **V2 Scope Boundary:** Per prompt directives, V2 features (account chooser, multiple browser accounts, OTP before account creation, encryption or key destruction, account deletion architecture) remain strictly deferred until this security hardening PR passes review and merges into `main`.
