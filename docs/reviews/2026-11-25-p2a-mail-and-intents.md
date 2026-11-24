# Review, v2, 2026-11-25 (P2a Email Verification and Durable Mail Outbox)

**Reviewed by**: Gemini 4 Hydrogen (High) (author on Gemini 4 Hydrogen (High); same model fallback disclosed as an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, OAuth V2 Slice P2a browser bound registration intents, OTP generation/attempt caps, atomic send budgets, encrypted outbox, leased worker, authenticated bounce callbacks, and registration/verification UI behind default disabled mode
**Verdict**: Approve

## Review Findings Addressed Before Completion

1. **Duplicate submit idempotency for suppressed emails** ([identity-registration.ts](../../backend/src/routes/identity-registration.ts)):
   * Initially idempotency lookup checked only `mail_outbox`, omitting suppressed recipients that intentionally skip outbox writes. Moved idempotency key lookup to `registration_intents` so repeated clicks return the exact same generic `202` response regardless of suppression state.
2. **Timeout retries under real HTTP transport** ([mail-service.ts](../../backend/src/identity/mail-service.ts)):
   * Initially `canRetry` checked only `err.transient === true`, which missed standard Node `fetch` `TimeoutError`, `AbortError`, and network `TypeError` failures on the 5 second provider timeout. Updated `isTransient` so genuine timeouts and network failures execute up to 3 bounded retries reusing the single `idempotencyKey`.
3. **Concurrent aggregate verification race & resend contact recovery** ([registration-budgets.ts](../../backend/src/identity/registration-budgets.ts), [registration-crypto.ts](../../backend/src/identity/registration-crypto.ts)):
   * Handled first write `E11000` race in non transactional aggregate verification counters cleanly via fallback atomic conditional `$inc`. Stored separate AEAD encrypted `encryptedEmail` on `registration_intents` (`intent-contact-aead-v1` info domain) so `/resend` works after outbox payload scrub and cleared it cleanly on inline expiry.

## Security & Reliability Assessment

* **Browser binding & same origin lock**: `swyra_reg_browser` `HttpOnly` cookie is required on `/resend`, `/verify`, and `/intent/:intentId`; `cors.ts` blocks third party OAuth consumer origins on `/api/identity/*`; CSRF protection guards all registration mutations; all identity responses emit `Cache-Control: no-store`.
* **Transactional budgets & zero account guarantee**: Send budgets (`60s` cooldown, `3/15m`, `10/day` mailbox; `10/15m` IP; `5/15m` browser; global daily cap) commit atomically inside `session.withTransaction` alongside `registration_intents` and `mail_outbox`, aborting with HTTP 503 and zero sends on backing store loss. Both failed and successful OTP verifications leave `user`, `account`, `session`, `oauthConsent`, `user_app_registrations`, `oauthAccessToken`, and `oauthRefreshToken` strictly at zero added records.
* **Proof custody**: Proof tokens use 256 CSPRNG bits stored only as keyed HMAC digests (`proofDigest`), minted at most once via conditional `pending -> verified` update, scoped to `min(now + 600s, intent.expiresAt)`, invalidated on `resend`, and emitted solely via `HttpOnly` `swyra_reg_proof` cookie.
* **Worker & callbacks**: Leased worker uses monotonic `fence`, checks deadline, active pending generation, global cap, and `mail_suppressions` prior to decrypting, scrubs `encryptedPayload` on send/discard/dead letter, and validates HMAC/timestamp/SHA256 digest and replay uniqueness on `/api/identity/mail/callbacks`.
* **Evidence boundary**: All mail sends used the local loopback/in memory `test_sink` transport; live AWS SES/SMTP sending and P2b `/registration/complete` account finalization remain pending.

## Post Review Verification

* `npm run typecheck`: 0 diagnostics.
* `npm --prefix frontend run lint && npm --prefix frontend run build:ui`: 0 ESLint errors, clean Vite production build.
* `npm run test:p2a-intents`: 3 passed, 0 failed.
* `npm run test:p2a-outbox`: 3 passed, 0 failed (covers tx rollback, lost lease recovery with monotonic fence bump, 3 retry limit, deadline drop, and signed callback replay/suppression).
* `npm run test:p2a-browser`: Playwright flow verified default off `/register` block, `/register` to `/register/verify` loopback mail sink flow, cooldown/countdown display, wrong code alert, valid code proof confirmation, and 0 accounts/sessions in MongoDB.
* `npm run test:unit`: 16 unit suites passed, 0 failed.
* `npm run test:local-consumer-e2e`: 11 flows passed, 0 failed.
* `npm run test:all-security`: 45 security suites passed, 0 failed.
* `npm run security:integration-check && npm run security:docs-check`: 0 violations, 0 errors.
