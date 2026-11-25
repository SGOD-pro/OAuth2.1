# Review, v2, 2026-11-25 (P3 Slice 2: Account Chooser and Per Tab OAuth Selection)

**Reviewed by**: Gemini 4 Hydrogen (Medium) (author on Gemini 4 Hydrogen (Medium); same model fallback disclosed because an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, OAuth V2 P3 account chooser UI (`AccountChooser.tsx`, `SignIn.tsx`, `Consent.tsx`), atomic `signOutBrowserEntry`, per tab `oauth_transactions` selection binding (`POST /api/identity/accounts/select`) with revision CAS, request local `authorize`/`consent` dispatch, OIDC `prompt`/`max_age`/`nonce` enforcement, and issuance commit revalidation while keeping dashboard contexts open for the next P3 slice
**Verdict**: Approve

## Review Findings Addressed Before Completion

1. **Preserved Better Auth signed `oauth_query` across per tab consent URLs** ([oauth-selection.ts](../../backend/src/identity/oauth-selection.ts), [Consent.tsx](../../frontend/pages/Consent.tsx)):
   * Appending `transaction_id` and `selection_revision` directly into Better Auth's signed query string invalidated the consent HMAC signature (`400` from `/oauth2/consent`). Captured the unmodified `signedOauthQuery = locUrl.search.slice(1)` into the `oauth_query` query parameter before appending `transaction_id` and `selection_revision`, preserving Better Auth signature verification and per tab transaction binding.
2. **Atomic MongoDB transaction for single account sign out** ([browser-session-registry.ts](../../backend/src/identity/browser-session-registry.ts)):
   * Wrapped engine `session` deletion and `browser_session_sets` Compare and Set update (`handleDigest` rotation + `$inc: { version: 1 }`) inside a single `session.withTransaction` boundary so version conflicts roll back cleanly without leaving the engine session deleted while the registry shows active, and supporting idempotent retries for already signed out entries while preserving all other account sessions.
3. **Prioritized `transactionId` over `state` on transaction lookup and kept files under 300 lines** ([oauth-transactions.ts](../../backend/src/db/oauth-transactions.ts), [auth-authorize.ts](../../backend/src/routes/auth-authorize.ts)):
   * Resolved `getOAuthTransaction` by `transactionId` before falling back to `state` so concurrent tabs stay strictly isolated, and kept `auth-authorize.ts` (295 lines) and `browser-session-registry.ts` (297 lines) under 300 lines.

## Security & Reliability Assessment

* **Tab isolation**: Each `/oauth2/authorize` creates an independent `transactionId` with `selectionRevision: 0`. `POST /api/identity/accounts/select` requires active `swyra-browser` proof, revalidates the referenced entry and engine session via `resolveVerifiedBrowserEntry`, enforces CAS on `expectedRevision`, binds `(browserSetId, selectedEntryId, selectedUserId, selectedSessionId)`, and dispatches `authorize` and `consent` through the request local adapter (`session-adapter.ts`) without mutating browser wide session cookies.
* **Issuance revalidation & OIDC rules**: Rejects invalid mixed `prompt=none login`, emits `account_selection_required` / `login_required` for `prompt=none`, enforces `max_age` and `prompt=login` staleness, preserves `nonce`, `prompt=consent`, PKCE `S256`, private app membership checks, and revalidates `verifySelectedTransactionStillActive` before returning any authorization code (purging codes if concurrently revoked).
* **Open scope**: Dashboard contexts (`POST /api/identity/contexts`) remain pending for the next P3 slice.

## Post Review Verification

* `npm run typecheck:backend && npm --prefix frontend run lint && npm --prefix frontend run build:ui`: 0 errors.
* `npm run test:p3-selection`: 2 test groups passed, 0 failed (atomic concurrent sign out + idempotent retry preserving B, CAS revision conflicts, interleaved two tab selection/consent yielding distinct `sub` and `nonce`, `prompt=none` semantics, private client denial, and revoked selection failing closed at consent).
* `npm run test:p3-two-tab`: Real Playwright browser with two interleaved tabs passed end to end (add B preserving A, interleaved chooser + consent + PKCE token exchange verifying `sub` and `nonce`, sign out A from chooser while B stays usable).
* `npm run test:p3-registry`, `npm run test:p3-adapter`, `npm run test:browser-e2e`, `npm run test:local-consumer-e2e`, `npm run test:all-security` (50 suites), `npm run security:integration-check`, and `npm run security:docs-check`: all passed.
