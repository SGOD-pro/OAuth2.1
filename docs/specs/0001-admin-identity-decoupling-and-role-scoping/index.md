# 0001. Admin identity decoupling and role scoping

**Date**: 2026-10-14
**Status**: Accepted

## Summary

This decision decouples central Global Super Admin identities from consumer application administrator assignments. Background synchronization sweeps and cold starts will no longer overwrite Super Admin privileges, token minting and userinfo endpoints will resolve administrator roles dynamically per client application, and management middleware will honor multi app administrator memberships. This eliminates administrative lockouts and stops consumer application administrators from inheriting privileges across applications.

## Requirements

**User stories**:
- As a Global Super Admin, I want my unscoped administrator privileges protected across serverless cold starts so that background synchronization sweeps never lock me out of the central console.
- As an Application Administrator, I want to manage one or more consumer applications without acquiring administrator privileges on other client applications.
- As a Multi App Administrator, I want to manage my assigned applications through scoped administrative APIs without being rejected by cross tenant token mismatches.
- As an Administrator logging into the central console, I want active consumer application sessions to clear cleanly so that I can authenticate with Super Admin credentials without getting trapped in access denied loops.

**Acceptance criteria**:
- **AC-1**: `syncAppAdminIdentity` and `selfHealAppAdmins` never overwrite `scopedClientId`, `account` password, or `banned` status when the target user is already a Global Super Admin (`role === "admin" && scopedClientId === null`).
- **AC-2**: When a non super admin user manages multiple applications, per client admin memberships are recorded in `user_app_registrations` with `appRole: "admin"`, leaving their primary `scopedClientId` intact.
- **AC-3**: Function `resolveUserRoleForClient` dynamically resolves role claims during access token minting, token introspection, and across both direct JWT and proxy 200 OK paths of `GET /oauth2/userinfo`: returning `role: "admin"` only if the user is a Global Super Admin or explicitly provisioned for that specific `clientId`, and returning `role: "user"` for all other clients.
- **AC-4**: Function `removeAppAdminIdentity` checks remaining `app_admins` records for an administrator: updating `scopedClientId` to a remaining active client if one exists, or resetting to `role: "user"` and null `scopedClientId` only when zero admin assignments remain and the user is not a Super Admin.
- **AC-5**: Admin console login page (`AdminLogin.tsx`) automatically signs out non super admin sessions on navigation and displays a clean banner requesting Global Super Admin credentials, preventing session lockouts.
- **AC-6**: Scripts `create-admin.ts` and `migrate-app-admins.ts` detect and prevent conflicts between Global Super Admin accounts and scoped `app_admins` records.
- **AC-7**: Middleware `requireScopedAdmin` and helper `getAuthenticatedUser` in `backend/src/middleware/admin-auth.ts` evaluate per client administrator privileges through `user_app_registrations` (`appRole: "admin"`) and `app_admins`, allowing multi app administrators to manage assigned applications without false cross tenant rejections.

## Decision

**Chosen option**: Option 1: Fix in place with dynamic role resolution (see [rationale.md](./rationale.md))

Decouple Global Super Admin accounts from scoped application administrator records, preserve multi app admin assignments in `user_app_registrations`, resolve role claims dynamically per target client in token minting and userinfo routes, and support multi app authorization in administrative middleware.

## Feature design

**Data model sketch**:
- `user` collection:
  - `_id`: ObjectId
  - `email`: string (unique)
  - `role`: string ('admin' | 'user')
  - `scopedClientId`: string | null (null for Global Super Admin; client ID for legacy single app admin, or null)
  - `banned`: boolean (never set to true for Global Super Admin)
  - `updatedAt`: Date
- `app_admins` collection:
  - `_id`: ObjectId
  - `clientId`: string
  - `email`: string
  - `isActive`: boolean
  - Compound unique index on `{ clientId: 1, email: 1 }`
- `user_app_registrations` collection:
  - `_id`: ObjectId
  - `userId`: string | ObjectId (foreign key to `user._id`)
  - `clientId`: string (foreign key to client)
  - `appRole`: string ('admin' | 'user')
  - `registeredAt`: Date
  - Compound unique index on `{ userId: 1, clientId: 1 }`
  - Index on `{ clientId: 1, userId: 1, appRole: 1 }`

**State transitions**:
- Unregistered user -> App Admin assigned -> upsert `user_app_registrations` with `appRole: "admin"` -> active admin for target client.
- App Admin removed -> remove entry in `user_app_registrations` -> check remaining `app_admins` -> update primary `scopedClientId` or reset to `role: "user"` if zero remaining.
- Super Admin assigned as App Admin -> record `user_app_registrations` with `appRole: "admin"` -> `scopedClientId` remains null -> never demoted.

**API surface**:
| Surface | Method / Type | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| `resolveUserRoleForClient` | Internal Function | `database: Db`, `userDoc: any`, `clientId: string` | `{ role: string, scopedClientId: string \| null }` | Internal | N/A |
| `syncAppAdminIdentity` | Internal Function | `database: Db`, `params: SyncAppAdminParams` | `void` | Internal | Logs warning on error |
| `removeAppAdminIdentity` | Internal Function | `database: Db`, `params: { email, clientId }` | `void` | Internal | Logs warning on error |
| `requireScopedAdmin` | Middleware | Context with target client ID | Passes to next handler | Bearer / Session | 403 forbidden |
| `/api/auth/oauth2/token` | POST | `grant_type`, `code`, `client_id`, `code_verifier` | Access token JWT, Refresh token | Public / Client Auth | 400 invalid_grant |
| `/api/auth/oauth2/userinfo` | GET | Bearer token | User claims (sub, email, role, scoped_client_id) | Bearer JWT | 401 invalid_token |
| `/api/auth/oauth2/introspect` | POST | `token`, `token_type_hint` | Active flag, client_id, sub, role, scoped_client_id | Basic Auth | 401 unauthorized |
| `/admin/login` | GET / React Route | None (cookie session) | Admin Console Login Form | Session Cookie | Error banner |

**Value sourcing**:
| Action | Value produced / displayed | Source |
|---|---|---|
| Mint Access Token | `role` claim in JWT | `resolveUserRoleForClient(db, userDoc, clientId).role` |
| Mint Access Token | `scoped_client_id` claim in JWT | `resolveUserRoleForClient(db, userDoc, clientId).scopedClientId` |
| Return Userinfo (JWT path) | `role` and `scoped_client_id` | `resolveUserRoleForClient(db, userDoc, payload.client_id)` |
| Return Userinfo (Proxy 200 path) | `role` and `scoped_client_id` | `resolveUserRoleForClient(db, userDoc, resolvedClientId)` |
| Scoped Admin Authorization | Tenant access verification | `requireScopedAdmin` checking `isSuperAdmin`, `scopedClientId`, `user_app_registrations`, and `app_admins` |
| Admin Session Guard | Access to `/admin/*` routes | Session user where `role === "admin" && scopedClientId === null` |

**Key invariants**:
1. A Global Super Admin (`role === "admin" && scopedClientId === null`) is permanently protected from demotion during background self heal routines or app admin updates.
2. An Application Administrator receives `role: "admin"` and `scoped_client_id: "<clientId>"` only in tokens minted for that specific client, and receives `role: "user"` for any other application.
3. Passwords and credentials belonging to Global Super Admins are never overwritten by application admin passwords.
4. Passwords are never relayed between applications, maintaining Zero Password Relay.
5. Scoped management APIs permit administration by any user with verified Global Super Admin status or explicit `appRole: "admin"` membership for the target client.

**Security model**:
- Global Super Admins have unrestricted access to the IdP administration console and bypass private application registration requirements.
- Application Administrators have access restricted to their assigned applications, validated via `resolveUserRoleForClient`, `requireScopedAdmin`, and `user_app_registrations`.
- Non super admin sessions are forbidden from accessing central IdP administrative routes.

**Critical test scenarios**:
- Happy path: Global Super Admin credentials authenticate at `/admin/login`, and cold start `selfHealAppAdmins` leaves `scopedClientId: null` intact, verifies **AC-1**, **AC-5**.
- Multi app admin: User assigned as admin for Client A and Client B receives `role: "admin"` when authenticating to Client A, and `role: "user"` when authenticating to Client C, verifies **AC-2**, **AC-3**.
- Scoped middleware: Multi app admin successfully invokes management endpoint for Client B when `user.scopedClientId` is Client A, verified via `user_app_registrations`, verifies **AC-7**.
- Userinfo consistency: Requesting `/oauth2/userinfo` with a Bearer token issued for Client A returns `role: "admin"` and `scoped_client_id: "Client-A"`, across both direct JWT and proxy 200 OK paths, verifies **AC-3**.
- Removal resilience: Removing an app admin from Client A when they still administer Client B preserves their admin role for Client B without demoting them to a standard user, verifies **AC-4**.
- Session switching: Visiting `/admin/login` with an active consumer app session signs out cleanly without error toast loops, verifies **AC-5**.
- Migration guard: Running `migrate-app-admins.ts` or `create-admin.ts` against existing database skips altering Super Admin records, verifies **AC-6**.

## Build plan

- [x] 1. Update `syncAppAdminIdentity` in `backend/src/utils/admin-sync.ts` with Super Admin protection and `user_app_registrations` role tracking, satisfies **AC-1**, **AC-2**.
- [x] 2. Update `removeAppAdminIdentity` in `backend/src/utils/admin-sync.ts` to inspect remaining client assignments before resetting user role, satisfies **AC-4**.
- [x] 3. Implement `resolveUserRoleForClient` helper and integrate into `mintJwtAccessToken`, `/oauth2/userinfo` (both direct JWT and proxy 200 OK paths), `/oauth2/introspect`, and `hasAppAccessBypass` in `backend/src/routes/auth.ts`, satisfies **AC-3**.
- [x] 4. Update `requireScopedAdmin` and `getAuthenticatedUser` in `backend/src/middleware/admin-auth.ts` to evaluate multi app memberships via `user_app_registrations` and `app_admins`, satisfies **AC-7**.
- [x] 5. Update `create-admin.ts` and `migrate-app-admins.ts` in `backend/scripts/` to guard against conflicting `app_admins` entries, satisfies **AC-6**.
- [x] 6. Update `AdminLogin.tsx` and `AdminRoute.tsx` in `frontend/pages/admin/` and `frontend/components/` to handle scoped session clean sign out, satisfies **AC-5**.
- [x] 7. Run security test suites (`npm run test:admin-scoping`, `npm run security:integration-check`) and verify isolation invariants, satisfies **AC-1**, **AC-2**, **AC-3**, **AC-4**, **AC-5**, **AC-6**, **AC-7**.

## Consequences

**Positive**:
- Eliminates random admin lockouts caused by Lambda cold starts.
- Enforces strict tenant isolation: app admins can never escalate privileges into other clients or the central IdP console.
- Smooths developer and administrator login UX by automatically handling session transitions.
- Supports multi application management for enterprise administrators without false cross tenant rejections.

**Negative / tradeoffs**:
- Adds one indexed query against `app_admins` or `user_app_registrations` during token minting and scoped middleware for non super admin users.
- Requires existing multi app admins to re authenticate to receive scoped tokens.

**Neutral**:
- Legacy single client admin accounts continue working without database migrations.

## Migration plan

**Strategy**: in place backward compatible enhancement
**Phases**:
1. Deploy updated backend identity sync, middleware, and role resolution logic.
2. Run `migrate-app-admins.ts` to ensure all existing `app_admins` entries have matching `user_app_registrations` rows with `appRole: "admin"`.
3. Deploy frontend login UX updates.
**Rollback**: Revert code changes; database documents remain backward compatible.
**Risks**: None; existing unscoped Super Admins remain untouched.

## Follow up

- [ ] Add regression integration test verifying that `selfHealAppAdmins` execution against a mock database with shared Super Admin emails does not mutate `scopedClientId`.
