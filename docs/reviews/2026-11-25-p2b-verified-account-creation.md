# Review, v2, 2026-11-25 (P2b Verified Account Completion and Bypass Closure)

**Reviewed by**: Gemini 4 Hydrogen (High) (author on Gemini 4 Hydrogen (High); same model fallback disclosed because an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, OAuth V2 Slice P2b transactional verified account creation (`POST /api/identity/registration/complete`, optional proof bound `POST /api/identity/username/check`), `/register/profile` UI and `/register/verify` continuation link, replica set transaction boundary, idempotency replay handling, and closure of unverified provisioning bypasses in `verified` mode
**Verdict**: Approve

## Review Findings Addressed Before Completion

1. **Concurrent two intent username write conflict classification** ([registration-complete.ts](../../backend/src/identity/registration-complete.ts)):
   * Initially a concurrent request with a distinct verified intent claiming the same normalized username hit MongoDB WiredTiger `WriteConflict` (code `112`) while the winner transaction was still uncommitted, causing the loser to receive `ERR_PROOF_CONSUMED` before the winner's `identity_lookup` entry became visible outside the snapshot. Added a single bounded retry (25ms yield) when `intentState.status === "verified"` and updated `resolveConflictAfterAbort` so concurrent distinct intent collisions resolve deterministically to `ERR_USERNAME_TAKEN` with the loser's proof intact and retryable.
2. **Pre-created collections and `disableMigration` vs `disableMigrations` split** ([registration-tx-engine.ts](../../backend/src/identity/registration-tx-engine.ts), [indexes.ts](../../backend/src/db/indexes.ts)):
   * Pre created identity collections and unique partial/composite indexes (`user.usernameLookup`, `registration_intents.completeIdempotencyKey`, `identity_lookup`, `identity_profiles`, `identity_outbox`, `auth_events`) outside MongoDB transactions and set `disableMigration: true` on transaction schema tables so cold database completion transactions never trigger disallowed runtime index creation inside multi document transactions.
3. **Auth engine admin and super admin MFA ordering in bypass closure** ([auth.ts](../../backend/src/routes/auth.ts), [utils/auth.ts](../../backend/src/utils/auth.ts)):
   * Blocked direct engine `POST /api/auth/sign-up/email`, `POST /api/auth/admin/create-user`, direct Better Auth API calls, and social auto provisioning via `databaseHooks.user.create.before` guarded by an `AsyncLocalStorage` verified creation context when `IDENTITY_REGISTRATION_MODE === "verified"`, while preserving default `disabled` compatibility and existing account sign in.

## Security & Reliability Assessment

* **Proof validation before password hashing**: Input syntax (`normalizeUsername`, `isStrongPassword`, `acceptedTermsVersion`), `swyra_reg_browser` binding, `swyra_reg_proof` digest lookup, proof deadline checks, and `completeIdempotencyKey` replay checks all execute before invoking password hashing.
* **Single MongoDB replica set transaction**: Proof consumption (`status: "verified" -> "consumed"`), email uniqueness, normalized username uniqueness, `user` creation (`role: "user"`, `scopedClientId: null`, `emailVerified: true`), `account` credential linking, `identity_lookup`, `identity_profiles` (`keyRef: null` until P6), `auth_events` (no plaintext full email), and `identity_outbox` execute inside one `createEngineTransactionBoundary` transaction. Username collisions abort the transaction and preserve `"verified"` proof state; injected mid transaction failures leave zero partial records; post commit `signInEmail` session failures preserve the committed account with an explicit `requiresSignIn: true` outcome.
* **File sizing & frontend checks**: All modified and added source and test files are strictly under 300 lines; `CompleteRegistration.tsx` uses accessible form constraints, `autocomplete="new-password"`, password unmask toggle (`aria-pressed`), and focus routing on error.

## Post Review Verification

* `npm run typecheck:backend`: 0 diagnostics.
* `npm --prefix frontend run lint && npm --prefix frontend run build:ui`: 0 ESLint errors, clean Vite TypeScript build.
* `npm run test:p2b-complete`: 4 test groups passed, 0 failed.
* `npm run test:p2b-bypasses`: 2 test groups passed, 0 failed.
* `npm run test:p2b-browser`: Playwright flow verified default off `/register/profile` gate, full `/register` to `/register/verify` to `/register/profile` completion via loopback mail sink, username collision retry preserving proof, and zero admin roles or private app memberships.
* `npm run test:p2a-browser` & `npm run test:local-consumer-e2e`: passed with 0 failures (11 local consumer flows).
* `npm run test:unit`: 16 unit suites passed, 0 failed.
* `npm run test:all-security`: 47 security suites passed, 0 failed.
* `npm --prefix backend run build && npm --prefix backend run build:node`: Lambda and Node production bundles built cleanly.
* `npm run security:integration-check && npm run security:docs-check`: 0 violations, 0 errors.
