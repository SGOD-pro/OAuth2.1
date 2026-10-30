# 0007. Explicit administrator identities and portal isolation

**Date**: 2026-10-30
**Status**: In Progress

## Summary

This decision defines explicit domain roles (super-admin, app-admin, user) and enforces mutual exclusion between central MAuth platform management and consumer application administration. Background synchronization routines and identity provisioning will never grant a single identity dual authority. Super admins retain complete control over OAuth client registration and administrator provisioning through MAuth platform APIs, but never receive consumer application administrator tokens or access consumer admin portals. Application administrators can manage only their explicitly assigned client applications and are strictly forbidden from entering the MAuth dashboard or invoking platform APIs.

## Requirements

**User stories**:
- As a Global Super Admin, I want to manage MAuth platform resources, registered applications, and administrative provisioning without my identity inheriting consumer application permissions or accidentally accessing consumer portals.
- As an Application Administrator, I want to manage assigned consumer client applications through scoped APIs without gaining unauthorized access to the MAuth platform console or other client tenants.
- As a Multi App Administrator, I want to administer multiple assigned consumer applications with authoritative per client records keyed by user ID and canonical client ID.
- As a Security Operator, I want clear machine readable error codes and request IDs that separate edge gateway perimeter rejections from role and scope authorization rejections.

**Acceptance criteria**:
- **AC-1**: Explicit domain roles (`super-admin`, `app-admin`, `user`) are typed and enforced across backend routes, session handlers, token generation, and the Better Auth admin plugin.
- **AC-2**: A single identity cannot simultaneously hold super-admin and app-admin privileges. Provisioning scripts and APIs reject assigning an existing super-admin as an app-admin.
- **AC-3**: Function `resolveUserRoleForClient` returns `role: "user"` and `scopedClientId: null` for super-admin identities on any consumer client, ensuring super admins never receive consumer app admin tokens.
- **AC-4**: Per client application administrator permissions are authoritative and keyed by stable user ID plus canonical client ID in `user_app_registrations` and `app_admins`. Email matching alone never grants privileges.
- **AC-5**: Management endpoints distinguish gateway rejections from role or scope rejections using stable machine readable codes (`ERR_GATEWAY_FORBIDDEN`, `ERR_SUPER_ADMIN_REQUIRED`, `ERR_CROSS_TENANT_FORBIDDEN`, `ERR_ROLE_FORBIDDEN`) and include request IDs.
- **AC-6**: Central platform management routes (`/api/admin/clients`, `/api/admin/stats`, `/api/admin/logs`, `/api/admin/users`) strictly require super-admin domain authority and reject app-admin callers.
- **AC-7**: Safe idempotent migration script provides a read only audit mode and an explicit apply mode that invalidates affected sessions and refresh families without mutating credentials.
- **AC-8**: Frontend guards (`AdminRoute.tsx`, `AdminLogin.tsx`, `AdminTwoFactor.tsx`) fail closed on missing or unresolved roles and display clear guidance without redirect loops.

## Decision

Adopt Option 1: Explicit Mutually Exclusive Roles with Authoritative User ID Keys.

## Feature design

**Role definitions**:
- `super-admin`: MAuth platform dashboard and global management only. Primary `scopedClientId` is strictly null.
- `app-admin`: Admin portals of assigned client applications only. Bound to assigned client IDs in `user_app_registrations` with `appRole: "admin"`.
- `user`: Standard platform user with no administrative authority.

**Key invariants**:
1. Super-admin identities never receive `role: "admin"` or `scoped_client_id` in tokens issued for consumer applications.
2. App-admin identities can never authenticate to central MAuth console routes or invoke global platform management endpoints.
3. Cold starts, synchronization sweeps, and self healing routines never alter super-admin status or convert roles.
4. Removing or altering one application assignment for a multi app administrator does not ban the identity or modify other active assignments.

## Build plan

- [ ] 1. Define domain role types and update `isSuperAdmin`, `isAppAdmin`, and `checkUserIsClientAdmin` with request ID tracking and structured error codes in `backend/src/middleware/admin-auth.ts`.
- [ ] 2. Update `resolveUserRoleForClient` and consumer access checks in `backend/src/routes/auth.ts` to deny super-admin consumer admin grants and require authoritative user ID keys.
- [ ] 3. Configure Better Auth admin plugin access controls in `backend/src/utils/auth.ts` to recognize `super-admin` and deny platform privileges to `app-admin`.
- [ ] 4. Reconcile provisioning and identity lifecycle paths in `backend/src/utils/admin-sync.ts`, `backend/src/routes/admin.ts`, and `backend/scripts/create-admin.ts`.
- [ ] 5. Implement read only audit and apply migration in `backend/scripts/migrate-identity-roles.ts`.
- [ ] 6. Align frontend console guards and session handling in `frontend/components/AdminRoute.tsx`, `frontend/pages/admin/AdminLogin.tsx`, and `frontend/pages/admin/AdminTwoFactor.tsx`.
- [ ] 7. Update documentation in all canonical docs (`SECURITY.md`, `ARCHITECTURE.md`, `INTEGRATION.md`, `CONFIGURATION.md`, `TROUBLESHOOTING.md`, `DEPLOYMENT.md`).
- [ ] 8. Verify all security suites and unit tests.

