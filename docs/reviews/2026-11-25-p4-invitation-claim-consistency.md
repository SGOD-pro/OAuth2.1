# Review, v2, 2026-11-25 (P4 Invitation Claim Consistency and Local System Walkthrough)

**Reviewed by**: Gemini 4 Hydrogen (Low) (author on Gemini 4 Hydrogen (Low); same model fallback disclosed because an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, transactional `claimPrivateAppInvitation` rollback and privileged role preservation, and local system walkthrough across OTP signup, two account selection, open/private app login, and invite claim
**Verdict**: Approve

## Review Findings & Security Assessment

1. **Transaction Rollback & Retryability** ([app-invitations.ts](../../backend/src/identity/app-invitations.ts)):
   * Wrapped invitation consumption (`findOneAndUpdate` to `claimed`) and membership/app admin grant inside `session.withTransaction` on the MongoDB replica set. If the grant throws, the invitation rolls back to `pending` and remains retryable.
2. **Role Preservation & TOTP Gating**:
   * Existing `admin` and `super-admin` roles are preserved when claiming an `app-admin` invite.
   * Newly assigned `app-admin` accounts without TOTP remain blocked from admin routes (`403 ERR_MFA_ENROLLMENT_REQUIRED`) until TOTP enrollment and verification complete.
3. **Automation vs Manual Coverage & Mail Sink Boundary**:
   * OTP signup (`test:p2b-browser`), two account selection (`test:p3-two-tab`), `/account` dashboard (`test:p3-dashboard-browser`), open/private app login (`test:local-consumer-e2e`), and invite claim (`test:p4-invitations`) all passed in automated Playwright and protocol suites against shared Docker MongoDB (`rs0`). No separate manual human browser click through was performed, and invitation delivery used `localInviteMailSink` rather than a live SMTP provider.

## Post Review Verification

* `npm run typecheck:backend`: 0 diagnostics.
* `npm run test:p4-invitations`: 3 passed, 0 failed.
* `npm run test:p4-admin-mfa`: 2 passed, 0 failed.
* `npm run test:p2b-browser`, `npm run test:p3-two-tab`, `npm run test:p3-dashboard-browser`, `npm run test:local-consumer-e2e`, `npm run security:integration-check`, `npm run security:docs-check`: all passed.
