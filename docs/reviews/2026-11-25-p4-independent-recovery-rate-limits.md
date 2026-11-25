# Review, v2, 2026-11-25 (P4 Independent Account and IP Recovery Rate Limits)

**Reviewed by**: Gemini 4 Hydrogen (Medium) (author on Gemini 4 Hydrogen (Medium); same model fallback disclosed because an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, independent trusted IP and normalized email digest rate limits before password verification on `POST /api/identity/recovery/backup-code`, shared `rate_limits` counter verification, and fail closed outage handling
**Verdict**: Approve

## Review Findings & Security Assessment

1. **Key Derivation & Pre Auth Enforcement** ([rate-limit.ts](../../backend/src/middleware/rate-limit.ts), [identity-recovery.ts](../../backend/src/routes/identity-recovery.ts)):
   * Added `keyFn` to `createRateLimiter` so `recoveryAccountRateLimit` keys on `digestToken(email.trim().toLowerCase())` (`limit: 5` per 15 minutes) while `recoveryIpRateLimit` keys on `getTrustedClientIp(c)` (`limit: 10` per 15 minutes).
   * Both middlewares execute before `handleBackupCodeRecovery`, enforcing quotas prior to password verification including for unknown accounts.
2. **Shared Counters & Outage Behavior**:
   * Both limiters write to the shared `rate_limits` collection (`RATE#rl:recovery:ip:...` and `RATE#rl:recovery:acct:...`) and use `sensitivity: "auth"`.
   * Under simulated store failure (`__simulateRateLimitStoreFailure(true)`), requests fail closed with HTTP 429 (`[RATE_LIMIT_CRITICAL]`).

## Post Review Verification

* `npm run typecheck:backend`: 0 diagnostics.
* `npm run test:p4-recovery`: 4 passed, 0 failed (concurrent single use, cross IP unknown account limit, cross account IP limit, shared `rate_limits` storage, fail closed outage, failed commit preservation, platform admin restoration).
* `npm run test:p4-admin-mfa`: 2 passed, 0 failed.
* `npm run test:local-consumer-e2e`: 11 passed, 0 failed.
* `npm run security:integration-check` & `npm run security:docs-check`: 0 violations, 0 errors.
