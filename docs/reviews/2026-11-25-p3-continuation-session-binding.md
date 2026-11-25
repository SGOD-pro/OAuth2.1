# Review, v2, 2026-11-25 (P3 OAuth Continuation Session Binding)

**Reviewed by**: Gemini 4 Hydrogen (Low) (author on Gemini 4 Hydrogen (Low); same model fallback disclosed because an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, finishing P3 session binding for `/api/auth/oauth2/continue`, subject consistency across authorize, consent, and continuation, and route level verification
**Verdict**: Approve

## Review Findings Addressed Before Completion

1. **Selected session dispatch allowlist included `/api/auth/oauth2/continue`** ([selected-engine-session.ts](../../backend/src/identity/selected-engine-session.ts)):
   * `dispatchSelectedEngineSession` previously rejected `POST /api/auth/oauth2/continue` with an unhandled error (`Selected-session dispatch only supports authorize and consent`). Added `POST /api/auth/oauth2/continue` to the allowlist so request local engine dispatch succeeds for continuation flows.
2. **Subject consistency across authorize, consent, and continuation** ([auth-consent.ts](../../backend/src/routes/auth-consent.ts)):
   * Extracted `resolveConsentOrContinueSession` shared by both `handleOAuthConsent` and `handleOAuthContinue`. Whenever `tx` has `selectedEntryId` and `browserSetId`, continuation resolves the exact browser entry and engine session via `resolveVerifiedBrowserEntry`, enforces subject and session ownership, evaluates private app access against the selected user, dispatches through `dispatchRequestWithBrowserEntry`, revalidates `verifySelectedTransactionStillActive`, and commits through `captureAndBindCode` with the original `selectionRevision`.
   * Stale or revoked selections fail closed with HTTP 401 `ERR_SESSION_REVOKED`, and legacy transactions without a selection preserve ambient session continuation.

## Post Review Verification

* `npm run typecheck:backend`: 0 diagnostics.
* `npm run test:p3-continuation`: 3 passed, 0 failed (uses selected subject despite conflicting ambient cookie, fails closed on stale/revoked selection, preserves legacy continuation).
* `npm run test:p3-binding`, `npm run test:p3-two-tab`, `npm run test:local-consumer-e2e`, `npm run security:integration-check`, and `npm run security:docs-check`: all passed.
