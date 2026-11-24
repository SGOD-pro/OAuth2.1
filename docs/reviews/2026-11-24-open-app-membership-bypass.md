# Review, v2, 2026-11-24

**Reviewed by**: Gemini 3.8 Flash High (author on Gemini 3.8 Flash High / Antigravity; same model fallback disclosed as independent reviewer model is unavailable in this session)
**Scope**: Branch v2, open app membership bypass, client_secret_post engine authentication, and test runner cleanup failure handling
**Verdict**: Approve

## Summary

This change delivers the open app membership bypass slice and two critical security follow-ups in SWYRA Auth:
1. Open application membership bypass: When OPEN_APP_MEMBERSHIP_BYPASS_ENABLED is enabled, eligible users authorize open applications without creating ambient rows in user_app_registrations. Ambient writes across signup, password login, social callback interception, MFA continuation, authorize, and consent are cleanly skipped. When the flag is disabled, documented compatibility registration behavior is strictly preserved.
2. Private application assignment enforcement: Private applications strictly require authoritative active assignments. Revocation of private access immediately closes all protocol pathways including code exchange, refresh token grants, UserInfo, and token introspection.
3. Client secret post engine authentication: Confidential clients registered with client_secret_post authenticate through the installed Better Auth engine probe with preserved body credentials, preventing premature code consumption or family revocation on unauthenticated requests.
4. Security runner lifecycle robustness: Test runner cleanup failures now produce an explicit failed suite outcome, and database operation deadline timers are cleared reliably when drops settle.

## Open App Membership Bypass Verification

1. Ambient Write Elimination:
Under OPEN_APP_MEMBERSHIP_BYPASS_ENABLED, open public and open confidential applications authorize users without writing any records to user_app_registrations.
Tested across email signup, password login, social callback interceptors, MFA continuation, authorization code issuance, and consent submission.

2. Backward Compatibility:
When OPEN_APP_MEMBERSHIP_BYPASS_ENABLED is set to false, existing behavior is preserved, ensuring existing consumer deployments continue operating without regression.

3. Private Application Isolation:
Private applications always enforce authoritative active membership. Unassigned users receive a 302 access_denied redirect.
Platform super-admins without explicit application assignment are strictly excluded from private client authorization.
When private application access is revoked, existing refresh tokens fail exchange with HTTP 401, UserInfo requests are rejected with HTTP 403, and token introspection returns active false.

## Client Secret Post Authentication

1. Credential Preservation:
Requests using client_secret_post preserve body credentials during engine authentication probes instead of incorrectly mutating headers to Basic auth.

2. Mutation Defense:
Unauthenticated code exchange attempts with wrong body credentials fail with HTTP 400 invalid_client, leaving the authorization code pending and available for exchange by the legitimate client.
Unauthenticated replay attempts with wrong credentials leave legitimate active token families untouched.

## Test Runner Cleanup Robustness

1. Explicit Failure Attribution:
When database dropping fails, coordinateSuiteCleanup propagates the error, and run-all-security records an explicit failed outcome rather than reporting a false pass.

2. Timer Cleanup:
Database cleanup timeouts clear their timers inside finally blocks, avoiding unhandled timer leaks during test execution.

## Evidence and Verification Results

* Open app membership bypass suite (`tests/security/open-app-membership-bypass.test.ts`): All 4 tests passed.
  * Open public client authorizes with zero rows in user_app_registrations (passed)
  * Open confidential client authorizes with zero rows in user_app_registrations (passed)
  * Compatibility row written when bypass is disabled (passed)
  * Ambient writes skipped in signup and signin when bypass is enabled (passed)
* Private app policy enforcement suite (`tests/security/private-app-policy-enforcement.test.ts`): All 3 tests passed.
  * Unassigned user denied with 302 access_denied (passed)
  * Super-admin denied without explicit assignment (passed)
  * Revocation immediately invalidates refresh, UserInfo, and introspection (passed)
* Client secret post authentication suite (`tests/security/client-secret-post-auth.test.ts`): All 2 tests passed.
  * Bad secret rejected without consuming code (passed)
  * Bad secret replay preserves token family (passed)
* Runner lifecycle cleanup suite (`tests/security/runner-lifecycle-cleanup.test.ts`): All 5 tests passed.
  * Stubborn descendant terminated via SIGKILL escalation (passed)
  * Signal code exit detection (passed)
  * Bounded database cleanup deadline (passed)
  * Process termination precedes database drop (passed)
  * Cleanup failure propagated from coordinateSuiteCleanup (passed)
* Unit test suites (`npm run test:unit`): All 16 suites passed.
* Local consumer E2E (`npm run test:local-consumer-e2e`): All 11 flows passed.
* Full security suite (`npm run test:all-security`): All 37 security suites passed (100 percent).
* Integration contract check (`npm run security:integration-check`): 0 violations.
* Documentation consistency check (`npm run security:docs-check`): 0 errors.
* File line counts: All modified and added source files remain strictly under 300 lines.
* Prose check: Verified zero punctuation hyphens or dashes in added review prose.
