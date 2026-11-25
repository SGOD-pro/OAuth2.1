# Review, v2, 2026-11-25 (P4 Backup Code Recovery and Transactional Invite Claim)

**Reviewed by**: Gemini 4 Hydrogen (Low) (author on Gemini 4 Hydrogen (Low); same model fallback disclosed because an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, requiring MongoDB transactions for `claimPrivateAppInvitation`, and implementing `POST /api/identity/recovery/backup-code` with rate limiting, single use backup code consumption, old session invalidation, setup only authority, and fresh TOTP restoration
**Verdict**: Approve

## Review Findings & Security Assessment

1. **Mandatory Transaction for Invitation Claims** ([app-invitations.ts](../../backend/src/identity/app-invitations.ts)):
   * `claimPrivateAppInvitation` now fails closed with `503 ERR_TRANSACTION_REQUIRED` if `mongoClient.startSession` is unavailable, ensuring invite consumption and membership/app admin grant never commit partially.
2. **Backup Code Consumption & Session Invalidation** ([identity-recovery.ts](../../backend/src/routes/identity-recovery.ts)):
   * Rate limited per IP and normalized email (`429 ERR_RATE_LIMITED` after 5 attempts per 15 minutes).
   * Verifies password and consumes the single use backup code via Better Auth's TOTP engine (`verifyBackupCode` with `disableSession: true`), then atomically deletes all existing `session` and `twoFactor` records for the user, increments `tokenVersion`, sets `twoFactorEnabled: false`, and issues a restricted recovery session (`twoFactorVerified: false`, `mfaVerifiedAt: null`) inside `session.withTransaction`.
   * Concurrent submissions with the same backup code allow at most one winner (`200` vs `401`), old elevated sessions fail (`401`), and the recovery session is restricted to setup only routes (`403 ERR_MFA_ENROLLMENT_REQUIRED` on privileged actions) until fresh TOTP enrollment and verification complete, restoring the exact role and `scopedClientId`.
   * Operator lost factor recovery custody and optional user TOTP remain open for later P4 slices.

## Post Review Verification

* `npm run typecheck:backend`: 0 diagnostics.
* `npm run test:p4-recovery`: 2 passed, 0 failed.
* `npm run test:p4-invitations`: 3 passed, 0 failed.
* `npm run test:p4-admin-mfa`: 2 passed, 0 failed.
* `npm run test:local-consumer-e2e`, `npm run security:integration-check`, `npm run security:docs-check`: all passed.
