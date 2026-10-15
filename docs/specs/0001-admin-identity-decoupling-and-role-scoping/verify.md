# Verify: Admin identity decoupling and role scoping · spec 0001 · updated 2026-10-14
_Steps derived from spec 0001 acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## UI / manual
- [x] Visit `/admin/login` while holding an active consumer application admin session → Alert banner displays explaining active consumer session detected and form is hidden behind one click sign out button → AC-5
- [x] Click "Sign out to continue" on `/admin/login` → Session is cleared and page reloads to show clean sign in form → AC-5
- [x] Authenticate with Global Super Admin credentials at `/admin/login` → Successful redirect to `/admin` dashboard with full unscoped administrative access → AC-1, AC-5

## Commands
- [x] `npm --prefix backend run test:admin-scoping` → Runs unit test suite asserting Super Admin cold start preservation, multi app registration tracking, dynamic role resolution per client, introspect post issuance resolution, removal resilience with surviving registrations, and scoped admin checks with 0 failures → AC-1, AC-2, AC-3, AC-4, AC-7
- [x] `npm run security:integration-check` → Verifies integration contract rules and client isolation policies with 0 violations → AC-7
- [x] `npm --prefix backend run build` → Backend TypeScript compilation and esbuild bundle generation succeeds with 0 errors → AC-3, AC-7
- [x] `npm --prefix frontend run build` → Frontend TypeScript and Vite bundle generation succeeds with 0 errors → AC-5

## Acceptance-criteria coverage
- AC-1 (Super Admin protection in syncAppAdminIdentity): Covered by `test:admin-scoping` Test 1
- AC-2 (Multi app registration tracking): Covered by `test:admin-scoping` Test 2
- AC-3 (Dynamic per client role resolution in tokens, userinfo, and introspect): Covered by `test:admin-scoping` Test 3 and Test 6
- AC-4 (Multi app admin removal resilience in removeAppAdminIdentity): Covered by `test:admin-scoping` Test 4 and Test 4b
- AC-5 (Admin login session switching and clean recovery): Covered by UI step at `/admin/login` and frontend build
- AC-6 (Admin creation and migration conflict protection): Covered by script checks in `create-admin.ts` and `migrate-app-admins.ts`
- AC-7 (Scoped admin middleware and token isolation): Covered by `test:admin-scoping` Test 5 and `security:integration-check`

## Value sourcing verification
- `role` claim in JWT: Verified via `resolveUserRoleForClient` returning `role: "admin"` only for matching clients
- `role` claim in introspect: Verified via `resolveUserRoleForClient` reflecting current database status even when token has stale claims
- `scoped_client_id` in JWT and introspect: Verified via `resolveUserRoleForClient` returning specific client ID or null
- Userinfo endpoints: Verified via `resolveUserRoleForClient` applied in both direct JWT decode and proxy paths
- Scoped admin middleware: Verified via `checkUserIsClientAdmin` accepting multi app registrations and active `app_admins`
- Removal resilience: Verified via `removeAppAdminIdentity` inspecting both `app_admins` and `user_app_registrations` before resetting user role
- Admin session guard: Verified via `AdminRoute` and `AdminLogin` inspecting `role === "admin"` and `scopedClientId === null`
