# Review, `fix/mauth-account-switch-auth-consistency`, 2026-10-30

**Reviewed by**: Senior Staff Engineer
**Scope**: 15 files, branch vs main (merge base 845f4ac)
**Verdict**: Approve

## Summary
In this branch, you addressed administrator identity isolation and account switching. You removed hardcoded email addresses, replaced unverified session cookie token lookups with cryptographic verification through the official Better Auth API, added defense against conflicting credentials, and improved the frontend account switch flow. All initial review findings regarding session cookie scoping, user provisioning role guards, audit conflict detection, predicate alignment, and test coverage have been resolved and verified with automated tests.

## Addressed Findings

### Resolved: Session cookie fallback scoping, `backend/src/middleware/admin-auth.ts`
- **Issue**: The cookie session fallback previously normalized accounts with `role: "super-admin"` by discarding any client scope string instead of failing closed.
- **Resolution**: Updated the cookie role evaluation condition so `cookieSessionUser.role === "super-admin"` strictly requires `scopedClientId === null || scopedClientId === undefined`. Any super admin account carrying an unexpected scope string fails closed to standard user privileges.

### Resolved: User provisioning role guard, `backend/src/routes/admin.ts`
- **Issue**: Standard users created with a client scope could acquire client administrator records in `user_app_registrations`.
- **Resolution**: Added validation rejecting `scopedClientId` for standard users with error `ERR_USER_CANNOT_BE_SCOPED` (HTTP 400). Restricted client registration linking and `user_app_registrations` provisioning strictly to accounts where `explicitRole === "app-admin"`.

### Resolved: Identity audit conflict detection, `backend/scripts/audit-operator-identities.ts`
- **Issue**: The audit script ignored active memberships when evaluating super admin accounts and had unreachable conflict logic.
- **Resolution**: Factored out and exported `evaluateIdentityAccount`. The audit now inspects `allAssigned` and flags any super admin holding client assignments in `app_admins` or `user_app_registrations` as an invalid conflicting identity.

### Resolved: Application administrator predicate alignment, `frontend/lib/role-predicates.ts`
- **Issue**: Frontend `isAppAdminUser` required a non empty `scopedClientId` string, rejecting multi app administrators whose client assignments are tracked in registrations.
- **Resolution**: Aligned frontend logic with the backend predicate to support multi app administrators with null or undefined scope on their user record.

### Resolved: Audit unit test coverage and runner registration
- **Issue**: `backend/scripts/audit-operator-identities.ts` lacked automated unit tests, and `account-switch-e2e.test.ts` was not included in `run-all-security.ts`.
- **Resolution**: Created `backend/tests/unit/audit-identities.test.ts` covering all classification branches and conflict states, added it to `npm run test:unit`, and added `tests/security/account-switch-e2e.test.ts` to `backend/scripts/run-all-security.ts`.

## Verification
- Unit test suite: `npm --prefix backend run test:unit` passed cleanly across all 7 test suites, including `test:audit-identities` and `test:admin-scoping`.
- Security suites: `npm --prefix backend run test:all-security:local` passed all 6 security test files.
- Integration and transition suites: `test:app-mgmt-auth`, `test:client-mode-transition`, `test:role-tampering`, and `test:account-switch` all passed.
- Linter and documentation checks: `security:docs-check` (0 errors) and `security:integration-check` (0 violations) passed.
- Frontend build: `npm --prefix frontend run build` succeeded with zero errors.
- Real browser flow: Verified in browser with session sign out, form reset, and super admin login to dashboard.
