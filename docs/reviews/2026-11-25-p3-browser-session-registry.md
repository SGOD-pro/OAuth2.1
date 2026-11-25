# Review, v2, 2026-11-25 (P3 Slice 1: Browser Session Registry and Request Local Session Adapter)

**Reviewed by**: Gemini 4 Hydrogen (High) (author on Gemini 4 Hydrogen (High); same model fallback disclosed because an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, OAuth V2 first P3 slice implementing server side `browser_session_sets` registry (`swyra-browser` / `__Host-swyra-browser`), `GET /api/identity/accounts`, `POST /api/identity/accounts/sign-out`, `POST /api/identity/accounts/remove`, request local [session-adapter.ts](../../backend/src/identity/session-adapter.ts), and ordinary login / verified registration session enrollment while preserving existing MFA and admin boundaries
**Verdict**: Approve

## Review Findings Addressed Before Completion

1. **Removed duplicate session token header extraction and kept source file size under 300 lines** ([session-adapter.ts](../../backend/src/identity/session-adapter.ts), [auth-sign-in.ts](../../backend/src/routes/auth-sign-in.ts)):
   * Consolidated Better Auth `set-cookie` session token parsing into `attachOrdinaryBrowserSessionToResponse`, keeping `auth-sign-in.ts` under 300 lines while retaining capacity denial telemetry (`session_set_full`).
2. **Verified Compare and Set concurrency safety at capacity** ([browser-session-registry.ts](../../backend/src/identity/browser-session-registry.ts)):
   * Confirmed bounded CAS retries reload active unrevoked sets by `setId` only after initial proof verification, returning `capacity_exceeded` (`ERR_SESSION_SET_FULL`) when `entries.length >= 10` without evicting or revoking any existing entry and deleting only the orphaned excess login session.
3. **Verified token, email, and privilege isolation** ([identity-accounts.ts](../../backend/src/routes/identity-accounts.ts), [session-adapter.ts](../../backend/src/identity/session-adapter.ts)):
   * `/api/identity/accounts` emits only opaque `entryId`, safe `label`, live computed `status`, and timestamps after batched `user` and `session` checks. Request local authorize/consent dispatch validates browser proof, account active status, `tokenVersion`, session expiry/revocation, and real `authProvider.api.getSession` with cache disabled, keeping `SelectedEngineSession` tokens strictly inside server memory and preserving admin MFA boundaries (`incomplete MFA challenges never enroll`).

## Post Review Verification

* `wc -l`: Every modified and added P3 source and test file is strictly under 300 lines.
* `npm run typecheck:backend`: 0 diagnostics.
* `npm run test:p3-registry`: 3 passed, 0 failed (verified registration + ordinary sign in coexistence, proof rotation and digest only DB storage, zero token/email leaks, expiring/signing out A leaves B active, invalid proof rejection and isolation, 10 account capacity non eviction + remove to re enroll).
* `npm run test:p3-adapter`: 2 passed, 0 failed (request local OAuth authorize/consent isolation against conflicting ambient cookies, revalidation denial on `tokenVersion` bump while B stays active, production `__Host-swyra-browser` cookie attributes, ordinary entry cannot bypass admin/MFA gates).
* `npm --prefix backend run test:p0-sessions`, `npm --prefix backend run test:p0-transactions`, `npm run test:p2b-complete`, `npm run test:p2b-bypasses`, `npm run test:p2b-browser`, `npm run test:browser-e2e`, `npm run test:local-consumer-e2e`, `npm run test:unit`, `npm run security:integration-check`, `npm run security:docs-check`: all passed.
