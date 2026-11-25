# Review, v2, 2026-11-25 (P4 Verified Private App Invitations)

**Reviewed by**: Gemini 4 Hydrogen (Low) (author on Gemini 4 Hydrogen (Low); same model fallback disclosed because an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, implementing private app invitation issuance, revocation, and atomic single use claim (`app-invitations.ts`, `admin-invitations.ts`, `identity-invitations.ts`), local mail sink verification, and tightened 5 minute MFA assertions
**Verdict**: Approve

## Review Findings & Security Assessment

1. **Claim Atomicity & Single Use** ([app-invitations.ts](../../backend/src/identity/app-invitations.ts)):
   * `claimPrivateAppInvitation` atomically transitions `{ tokenDigest, status: "pending", expiresAt: { $gt: now }, targetEmail }` to `status: "claimed"` via `findOneAndUpdate`, guaranteeing at most one winner under concurrent claims (`200` vs `409`).
2. **Role Boundaries & Separation** ([app-invitations.ts](../../backend/src/identity/app-invitations.ts), [admin-invitations.ts](../../backend/src/routes/admin-invitations.ts)):
   * `app-admin` inviters are restricted to `roleCeiling: "user"` on their assigned `scopedClientId`; attempting `app-admin` ceiling or another client fails closed (`403`).
   * `admin`/`super-admin` provisioning via invitations is blocked (`400 ERR_INVALID_ROLE_CEILING`), keeping super admin provisioning operator controlled.
   * Ordinary invitations only upsert `user_app_registrations` without elevating `user.role`; explicit `app-admin` invitations set `role: "app-admin"` and `scopedClientId`.
3. **MFA Gating & Mailbox Proof**:
   * Both issuance (`POST /api/admin/clients/:clientId/invitations`) and revocation (`DELETE /api/admin/clients/:clientId/invitations/:inviteId`) require `requireScopedAdmin` and `requireRecentMfa` (5 minutes).
   * Claim (`POST /api/identity/invitations/claim`) requires an authenticated session with `emailVerified === true` matching `targetEmail`.

## Post Review Verification

* `npm run typecheck:backend`: 0 diagnostics.
* `npm run test:p4-invitations`: 2 passed, 0 failed.
* `npm run test:p4-admin-mfa`: 2 passed, 0 failed (tightened to exact `404` status on fresh MFA).
* `npm run test:p3-dashboard-browser`, `npm run test:local-consumer-e2e`, `npm run security:integration-check`, `npm run security:docs-check`: all passed.
