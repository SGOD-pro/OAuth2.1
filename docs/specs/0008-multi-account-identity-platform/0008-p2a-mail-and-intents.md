# 0008-P2a. Registration intents, OTP budgets, durable mail outbox, and verification proof

**Status:** Locally verified with local test sink (P2b account creation and real provider delivery remain pending)
**Date:** 2026-11-25

## 1. Purpose and scope boundary

Slice P2a delivers pre account email verification before any identity, credential, session, grant, membership, or OAuth token exists. It turns [PHASES.md](../../PHASES.md), [AUTHENTICATION_FLOWS.md](../../AUTHENTICATION_FLOWS.md), [MAIL_SERVICE.md](../../MAIL_SERVICE.md), [ABUSE_DEFENSE.md](../../ABUSE_DEFENSE.md), [CONFIGURATION.md](../../CONFIGURATION.md), and [USER_EXPERIENCE.md](../../USER_EXPERIENCE.md) into a bounded build slice.

**Strict P2a boundary:**
* P2a creates **zero** `user`, `account`, `session`, `oauthConsent`, `user_app_registrations`, `oauthAccessToken`, or `oauthRefreshToken` rows on `start`, `resend`, or failed/successful `verify`.
* P2b (`POST /api/identity/registration/complete`, transactional uniqueness on normalized email and username, engine bypass closure, `/register/profile`) remains deferred and keeps `IDENTITY_REGISTRATION_MODE=disabled` in production until both P2a and P2b pass acceptance.

## 2. Registration intents and browser binding

1. **Collection**: `registration_intents`. Key fields: `intentId` (128+ bit random handle), `emailLookup` (`HMAC(lookupKey, canonicalEmail)` using `IDENTITY_LOOKUP_KEY_REF`, never plaintext email as public ID or log field), `browserBindingHash`, `purpose` (`"registration"`), `termsVersion`, `oauthTransactionId` (optional), `invitationHandle` (optional), `status` (`pending` | `verified` | `exhausted` | `expired` | `consumed`), `generation` (integer >= 1), `otpVerifier` (`HMAC`), `otpExpiresAt`, `attemptCount`, `resendCount`, `lastSentAt`, `expiresAt`, `proofDigest`, `proofExpiresAt`.
2. **Browser binding**: `POST /api/identity/registration/start` and `/resend` establish/require an `HttpOnly`, `SameSite=Lax` (`Secure` in production) registration browser binding cookie and `Cache-Control: no-store`. A guessed `intentId` without a matching browser binding cookie is rejected.
3. **Generic admission response**: `start` and `resend` return generic HTTP `202` with opaque continuation state for new, already registered, and suppressed addresses alike. No endpoint leaks whether an email is registered or suppressed.
4. **State transitions and resend rules**:
   * Defaults from configuration contract: intent lifetime `IDENTITY_INTENT_TTL_SECONDS=1800` (30 minutes), code lifetime `IDENTITY_OTP_TTL_SECONDS=300` (5 minutes), cooldown `IDENTITY_MAIL_RESEND_SECONDS=60`.
   * Bounded `resend` transitions `pending -> pending` on the same `intentId` while `expiresAt` remains fixed: it increments `generation`, mints a new code verifier and resets `otpExpiresAt` bounded by `intent.expiresAt`, invalidates all prior code generations and any existing unconsumed proof, and **never** resets aggregate guess or send budgets.
   * Changing email starts a fresh budgeted intent rather than mutating `emailLookup` on an active intent.

## 3. OTP generations, verification, and attempt limits

1. **Generation & cryptography**: Generate uniform random 6 digit code via `crypto.randomInt(0, 1000000)` padded to 6 digits. Compute verifier strictly as `HMAC(otpVerifierKey, purpose || intentId || generation || emailLookup || code)` with unambiguous framing and dedicated secret key ref `IDENTITY_OTP_VERIFIER_KEY_REF` (separate from mail encryption key `IDENTITY_MAIL_PAYLOAD_KEY_REF`). Never log codes to stdout or error streams.
2. **Inline expiry & serialized attempt accounting**: `POST /api/identity/registration/verify` checks `now < intent.expiresAt` and `now < intent.otpExpiresAt` inline rather than waiting for background MongoDB TTL cleanup. Attempts serialize with atomic conditional updates (`findOneAndUpdate` / replica set transaction).
3. **Attempt budgets (`IDENTITY_OTP_MAX_ATTEMPTS=5`)**:
   * Max `5` failed attempts per generation (moving intent to `exhausted` / rejecting further tries for that generation) plus aggregate mailbox cap `10` failed verification guesses per `30 minutes` (`ABUSE_DEFENSE.md`).
   * **Malformed codes also consume the applicable attempt budget** before rejection. Constant time MAC comparison (`crypto.timingSafeEqual`) protects against timing leaks.
   * Expired, wrong generation, superseded, exhausted, or replayed codes fail cleanly with generic invalid/expired error JSON and return remaining attempts only to the bound browser owner.

## 4. Atomic send budgets and durable encrypted outbox

1. **Distributed quota enforcement**:
   * Domain separated HMAC target keys (`emailLookup`, trusted client IP/prefix via `getTrustedClientIp`, browser binding hash, deployment global daily counter `IDENTITY_GLOBAL_MAIL_DAILY_BUDGET`).
   * Mailbox limits (`ABUSE_DEFENSE.md`): cooldown `60s`, `3` sends per `15 minutes`, `10` sends per `day`; source IP `10/15 minutes`; browser `5/15 minutes`.
   * Fail closed when the budget store is unavailable: zero process local fallback and zero outbox writes/sends on store error. Preserve single allowance across Redis/Mongo failover by reserving critical send budgets atomically in the authoritative store alongside `mail_outbox` creation.
2. **Transactional intent + budget + outbox write**: `start` and `resend` atomically reserve send budgets, write/update `registration_intents`, and insert the `mail_outbox` record using a browser idempotency key so duplicate double clicks reuse one job rather than consuming extra sends.
3. **Encrypted outbox schema (`mail_outbox`)**: `jobId`, `operationId`, `templateVersion`, `purpose`, `emailLookup`, `encryptedPayload` (recipient email and 6 digit code encrypted with short lived `IDENTITY_MAIL_PAYLOAD_KEY_REF`, separate from verifier key and future P6 account DEKs), `intentId`, `generation`, `deadline` (`<= otpExpiresAt`), `status` (`queued` | `sending` | `sent` | `discarded` | `dead_letter`), `attemptCount`, `leaseOwner`, `fence`, `leaseExpiry`, `providerMessageId`.

## 5. Provider deadlines, leased worker, and suppression

1. **Transport abstraction**: `EmailSender.send(message, idempotencyKey, deadline)` supports loopback `test_sink` in local/test runs and AWS SES, approved SMTP, or signed webhook (`IDENTITY_MAIL_TRANSPORT`, `IDENTITY_MAIL_FROM`, `IDENTITY_MAIL_WEBHOOK_KEY_REF`) in production with versioned escaped text+HTML templates and fixed sender/subject.
2. **Leased worker & fencing**: Worker atomically claims due jobs (`leaseOwner`, monotonic `fence`, `leaseExpiry`). Before decrypting or sending, it verifies: job `deadline > now`, global daily ceiling not exceeded, `registration_intents.status === "pending"` with matching `generation`, and no active record in `mail_suppressions`. Stale workers cannot ack or retry after losing their fence.
3. **Deadlines & retries (`MAIL_SERVICE.md`)**:
   * Every provider call uses a **5 second** request timeout and honors job `deadline <= code.expiresAt`.
   * Bounded retries: up to **3** attempts with exponential backoff + jitter on transient/rate limit errors only while usable code lifetime remains; permanent validation or suppression errors do not retry.
   * On network timeout uncertainty, retry ONLY with the same `idempotencyKey` and current generation code; never mint a new OTP or refund send budget.
   * Scrub decrypted/encrypted OTP payload immediately upon send acceptance or discard of superseded generation jobs. Dead letters keep encrypted references + error category only.
4. **Suppression callbacks**: Authenticated bounce/complaint webhooks verify official SDK signature, timestamp, issuer, body digest, and event replay cache, persisting durable `mail_suppressions` silently without exposing suppression state publicly.

## 6. One-use verification proof (output to P2b)

* Upon atomic valid OTP verification (`status: "pending" -> "verified"`): mint a 256 bit CSPRNG verification proof stored in `registration_intents.proofDigest` (keyed digest), set `proofExpiresAt = min(now + 600_000ms, intent.expiresAt)`, and deliver the raw proof ONLY via an `HttpOnly`, `SameSite=Lax` (`Secure` in prod) registration proof cookie (`Cache-Control: no-store`). Never return the raw proof in JSON to browser JavaScript.
* Proof is bound strictly to `(intentId, emailLookup, browserBindingHash, purpose)` and stays usable by P2b `/api/identity/registration/complete` until consumed once or superseded by resend/expiry.

## 7. Proposed endpoints, UI surfaces, and config

* **API routes** (`Cache-Control: no-store`, CSRF protected, same origin): `POST /api/identity/registration/start`, `POST /api/identity/registration/resend`, `POST /api/identity/registration/verify`. Reject operator keys and raw provider errors (`{ error, code, requestId, retryAfterSeconds? }`).
* **Frontend pages** (deferred behind `IDENTITY_REGISTRATION_MODE` in P2a+P2b integration): `/register` (`Register.tsx`) and `/register/verify` (`VerifyEmail.tsx`), reconstructing state strictly from server backed browser bound intent without storing secrets or passwords in `localStorage`/URLs.
* **Typed config additions** (to wire during P2a implementation): `IDENTITY_REGISTRATION_MODE` (default `disabled`), `IDENTITY_OTP_TTL_SECONDS`, `IDENTITY_OTP_MAX_ATTEMPTS`, `IDENTITY_INTENT_TTL_SECONDS`, `IDENTITY_PROOF_TTL_SECONDS`, `IDENTITY_MAIL_RESEND_SECONDS`, `IDENTITY_OTP_VERIFIER_KEY_REF`, `IDENTITY_LOOKUP_KEY_REF`, `IDENTITY_MAIL_PAYLOAD_KEY_REF`, `IDENTITY_MAIL_TRANSPORT`, `IDENTITY_MAIL_FROM`, `IDENTITY_MAIL_QUEUE_REF`, `IDENTITY_GLOBAL_MAIL_DAILY_BUDGET`.

## 8. Mandatory test plan (zero accounts/sessions on failed AND successful OTP)

Before P2a exits, automated unit, security, worker, and local sink integration tests must assert baseline and post execution database counts (`user === 0`, `account === 0`, `session === 0`, `oauthConsent === 0`, `user_app_registrations === 0`, `oauthAccessToken === 0`, `oauthRefreshToken === 0`) across ALL cases below:

1. **Failed OTP verification scenarios (zero identities/sessions/proofs)**:
   * Wrong 6 digit code, malformed code (confirms attempt budget still decrements), wrong browser binding cookie, expired OTP inline (`otpExpiresAt <= now` even before TTL sweep), expired intent inline, superseded generation after resend, exhausted `5` attempt limit, aggregate `10/30min` mailbox guess limit, and concurrent verify replay after `exhausted`.
2. **Successful OTP verification scenario (proves verification WITHOUT account or session)**:
   * Valid 6 digit code returns verified continuation JSON (`{ verified: true }`) and sets `HttpOnly` registration proof cookie (`no-store`); payload contains zero raw proof string to JS; `registration_intents.status === "verified"` with `proofDigest` set; **database still has zero new `user`, `account`, `session`, `oauthConsent`, `user_app_registrations`, and token rows**.
   * Concurrent double submission of valid code produces at most one minted proof; resend after verify invalidates prior proof (`proofDigest` cleared); expired proof rejected without mutation.
3. **Budget, outbox, deadline, worker, and failure scenarios**:
   * Store outage on send budget reservation fails closed with `0` `registration_intents`, `0` `mail_outbox`, and `0` `test_sink` deliveries.
   * Mailbox (`60s` cooldown, `3/15m`, `10/day`), IP (`10/15m`), browser (`5/15m`), and global daily caps return generic bounded responses without resetting budgets across resend or changed browser handles.
   * Superseded generation outbox job is discarded unsent; expired `deadline` job is dropped before decrypt/send; stale `fence` worker cannot ack/retry; `5s` provider timeout retries up to 3 times within remaining lifetime reusing same `idempotencyKey` (zero new OTPs minted, zero extra budget consumed); bounce/complaint signed webhook suppresses future sends silently (`202` public response, `0` sends); forged callback signature/replay rejected.
