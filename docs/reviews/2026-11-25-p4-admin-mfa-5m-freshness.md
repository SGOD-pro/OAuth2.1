# Review, v2, 2026-11-25 (P4 Admin MFA Five Minute Freshness and CI Dashboard Coverage)

**Reviewed by**: Gemini 4 Hydrogen (Low) (author on Gemini 4 Hydrogen (Low); same model fallback disclosed because an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, aligning `requireRecentMfa` with the 5 minute policy, deterministic inside/outside 5 minute tests for both platform and app admins, and adding `test:p3-dashboard-browser` to CI
**Verdict**: Approve

## Review Findings & Security Assessment

1. **Five Minute Freshness Boundary** ([admin-mfa.ts](../../backend/src/middleware/admin-mfa.ts)):
   * Updated `MAX_MFA_AGE_MS` from `15 * 60 * 1000` to `5 * 60 * 1000` and updated the `ERR_MFA_STEP_UP_REQUIRED` message to state `(< 5 minutes)`.
2. **Deterministic Coverage for Both Roles** ([p4-admin-mfa-enrollment.test.ts](../../backend/tests/security/p4-admin-mfa-enrollment.test.ts)):
   * Verified both platform (`admin`) and scoped (`app-admin`) roles: just inside 5 minutes (`4m30s` ago) succeeds on sensitive mutations, while just outside 5 minutes (`5m10s` ago) fails closed with `403 ERR_MFA_STEP_UP_REQUIRED` (`< 5 minutes`). Setup only authority and app admin assignment boundaries remain preserved.
3. **CI Dashboard Browser Coverage** ([ci.yml](../../.github/workflows/ci.yml)):
   * Added `Run P3 Account Dashboard Browser E2E Suite (Playwright)` (`npm run test:p3-dashboard-browser`) to the CI pipeline.

## Post Review Verification

* `npm run typecheck:backend`: 0 diagnostics.
* `npm run test:p4-admin-mfa`: 2 passed, 0 failed.
* `npm run test:p3-dashboard-browser`: passed.
* `npm run test:local-consumer-e2e`: 11 passed, 0 failed.
* `npm run security:integration-check` & `npm run security:docs-check`: 0 violations, 0 errors.
