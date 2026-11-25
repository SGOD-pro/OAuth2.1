# Review, v2, 2026-11-25 (P4 Backup Code Recovery Failure and Rate Limit Gaps)

**Reviewed by**: Gemini 4 Hydrogen (Low) (author on Gemini 4 Hydrogen (Low); same model fallback disclosed because an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, closing P4 backup code recovery atomicity, shared rate limiting, and session cookie attribute gaps
**Verdict**: Approve

## Review Findings & Security Assessment

1. **Atomic Backup Code Consumption & Recovery Authority** ([identity-recovery.ts](../../backend/src/routes/identity-recovery.ts)):
   * Verified that Better Auth stores encrypted backup codes in `twoFactor.backupCodes` using `symmetricEncrypt`/`symmetricDecrypt` with `ctx.secret`. Moved backup code verification, CAS consumption, old session deletion, `tokenVersion` increment, `twoFactorEnabled: false` reset, and restricted recovery session insertion into a single MongoDB replica set `session.withTransaction`.
   * If any step fails before commit, the transaction rolls back and the backup code remains preserved and retryable.
2. **Shared Rate Limiting & Fail Closed Store**:
   * Replaced the local in memory counter with `recoveryIpRateLimit` and `recoveryAccountRateLimit` using `createRateLimiter(..., { sensitivity: "auth" })` backed by the shared rate limit infrastructure.
3. **Cookie Attributes & Role Preservation**:
   * Recovery session cookie uses `ctx.authCookies.sessionToken.attributes` including `Secure` when `config.env === "production"` or `attrs.secure` is set.
   * Verified setup only authority and exact role/scope restoration across both `app-admin` and platform `admin`. Optional user TOTP and operator lost factor recovery custody remain open.

## Post Review Verification

* `npm run typecheck:backend`: 0 diagnostics.
* `npm run test:p4-recovery`: 3 passed, 0 failed.
* `npm run test:p4-invitations`: 3 passed, 0 failed.
* `npm run test:p4-admin-mfa`: 2 passed, 0 failed.
* `npm run test:local-consumer-e2e`, `npm run security:integration-check`, `npm run security:docs-check`: all passed.
