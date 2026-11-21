# Configuration: current runtime and planned V2 policy

**Authority:** Normative configuration reference. Updated 2026-11-22.
This docs branch is based on main `161ad99`; rows marked hardened are available on reviewed security PR #2, not automatically in this branch runtime. V2 settings are proposed names/contracts, not accepted environment variables until implemented.

## 1. Existing and hardened configuration

Read actual `backend/src/config/schema.ts`, `index.ts`, environment templates and deployment wiring together. Do not put secrets in frontend variables. Runtime `NODE_ENV` and client `isDev` are independent.

| Variable | Existing/hardened behavior | Operator rule |
|---|---|---|
| `NODE_ENV` | development/production/test required by schema | Explicit per deployment |
| `PORT` | Default 3000 | Node listener only |
| `MONGO_URI` | Required database connection | TLS/least privilege; V2 atomic workflows need replica set |
| `BETTER_AUTH_SECRET` | Required, >=32 characters | Dedicated engine secret, not all-purpose V2 key |
| `BETTER_AUTH_URL`, `FRONTEND_URL` | Canonical backend issuer/UI origin | Hardened production HTTPS/non-loopback validation; reference same-origin gateway |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Required strings in current schema | Backend upstream identity configuration; does not enable arbitrary auto-provisioning |
| `INTERNAL_GATEWAY_SECRET` | Hardened production required >=32 chars, backend supports bounded dual-secret rotation | Prefer random 32-byte secret; configure gateway and origin, never commit generated secret config |
| `TRUSTED_PROXY_CIDRS` | Required nonempty in production by app boot | Use actual trusted peers; never broad arbitrary internet trust |
| `ALLOW_DEV_CLIENTS_IN_PRODUCTION` | Default false | Explicit operator policy for development callbacks, not open/private/client-type choice |
| `AUTH_PUBLIC_SIGNUP_ENABLED` | Default true legacy signup control | V2 enabled only through proof-aware routing/bypass closure |
| `AUTH_EMAIL_VERIFICATION_ENABLED` | Default false | Hardened verification requires delivery transport; legacy flag alone does not implement pre-account OTP |
| `AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE` | Hardened `enforce_all` or `enforce_new` | Existing account migration only; never exempt new V2 accounts |
| `AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER` | Hardened explicit-zone ISO timestamp for enforce_new | Example `2026-06-01T00:00:00Z`; no local/ambiguous date |
| `EMAIL_DELIVERY_WEBHOOK_URL` | Hardened engine verification/reset transport, 5-second timeout and non-2xx rejection | HTTPS/non-loopback in production; V2 adds authenticated service boundary and durable queue |
| `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` | Preferred Redis REST settings | URL+token pair; do not infer raw TCP URL support from generic name |
| `UPSTASH_REDIS_API_KEY`, `REDIS_URL`, `REDIS_TOKEN` | Current compatibility aliases in hardened config | Reference Redis REST client behavior; isolate test credentials |
| `LAMBDA_BACKEND_URL` | Proxy generator setting, not backend Zod field | Hardened production build requires explicit approved origin URL |

Only run existing documented commands for the checked-out source. Changes to schema must update typed getters, templates, infra/worker wiring, startup validation and tests in the same implementation PR. Reject unknown security settings rather than assume a pasted V2 env file works.

## 2. Consumer settings

| Consumer | Required settings | Secret custody |
|---|---|---|
| Next.js/Express/FastAPI BFF | `AUTH_ISSUER`, `CLIENT_ID`, registered `AUTH_CALLBACK_URL`, `CLIENT_SECRET` for confidential client, strong `SESSION_SECRET` | Server-only secrets and shared session/transaction store |
| Browser SPA/mobile public client | Issuer, public client ID and exact callback; e.g. `VITE_AUTH_ISSUER`, `VITE_CLIENT_ID`, `VITE_AUTH_CALLBACK_URL` | No client secret; memory-based browser tokens, tested OIDC library |

No production localhost/client-ID fallback. The consumer never receives `MONGO_URI`, mail keys, browser-set handles, TOTP secrets or account data keys. Access policy does not determine whether it is public/confidential.

## 3. Proposed V2 configuration contract

These names are design proposals, intentionally not wired to runtime. Prefer a small typed server configuration object; if environment-backed, implement the names below with strict parsing. No boolean uses JavaScript truthiness for strings.

| Proposed key | Default/design | Validation/activation dependency |
|---|---|---|
| `IDENTITY_REGISTRATION_MODE` | `disabled` until P2 verified | Enum disabled/verified; production no unverified mode |
| `IDENTITY_MAX_BROWSER_ACCOUNTS` | 10 | Positive bounded integer and cookie/header budget test |
| `IDENTITY_SESSION_IDLE_SECONDS` / `ABSOLUTE_SECONDS` | 86400 / 2592000 | Idle <= absolute; server-clock enforcement |
| `IDENTITY_ADMIN_SESSION_IDLE_SECONDS` / `ABSOLUTE_SECONDS` | 1800 / 43200 | Mandatory TOTP; no legacy MFA-off flag |
| `IDENTITY_RECENT_AUTH_SECONDS` | 300 | Action receipt and MFA policy, explicit bound |
| `IDENTITY_CONTEXT_TTL_SECONDS` | 900 | Cannot exceed parent authority; purpose binding |
| `IDENTITY_OTP_TTL_SECONDS` / `MAX_ATTEMPTS` | 300 / 5 | Uniform six-digit code, aggregate attempt budget |
| `IDENTITY_INTENT_TTL_SECONDS` / `PROOF_TTL_SECONDS` | 1800 / 600 | Proof <= remaining intent lifetime |
| `IDENTITY_MAIL_RESEND_SECONDS` | 60 | Aggregate mailbox/IP/global send budgets cannot reset |
| `IDENTITY_OTP_VERIFIER_KEY_REF` | Required for verified signup | Separate secret manager version; dual-key rotation/intent expiry |
| `IDENTITY_LOOKUP_KEY_REF` | Required for protected email/username lookup | Domain-separated HMAC key, rotation uniqueness proof |
| `IDENTITY_MAIL_PAYLOAD_KEY_REF` | Required for pre-account mail jobs | Separate short-lived encryption purpose, queue cleanup |
| `IDENTITY_MAIL_TRANSPORT` | test_sink in local only; production explicit provider | Enum ses/approved_smtp/signed_webhook; provider dependency and test |
| `IDENTITY_MAIL_FROM` | No production default | Verified sender domain; fixed templates |
| `IDENTITY_MAIL_QUEUE_REF` | Required before signup enabled | Durable bounded queue/outbox; least-privilege worker |
| `IDENTITY_MAIL_WEBHOOK_KEY_REF` | Required if signed webhook selected | Authenticated timestamp/nonce/body signing; replay protection |
| `IDENTITY_GLOBAL_MAIL_DAILY_BUDGET` | No production default | Positive measured cap within provider/cost allowance |
| `IDENTITY_HASH_CONCURRENCY` / `WORKER_CONCURRENCY` | No production defaults | Measured per profile; fleet cap, not only process count |
| `IDENTITY_KEY_PROVIDER` | disabled until P6 | cloud_account_kms/self_host_vault capability profile |
| `IDENTITY_KEY_SERVICE_REF` | Required for encryption | Narrow service authorization and real erasure/restore evidence |
| `IDENTITY_DELETION_LEDGER_REF` | Required for deletion | Independently retained/replayed denial ledger; backup separation |
| `IDENTITY_RISK_MODE` | observe during validation | off/observe/step_up; no fingerprint-only allow/ban mode |
| `IDENTITY_FILTER_MODE` | disabled | Optional measured snapshot experiment, never auth authority |

Provider-specific credentials are secret references or scoped workload identity; never a giant env string containing account key material. Exact key-provider/SMTP/queue adapter variables must be documented when chosen. Tests validate invalid pairs, missing refs, wrong origin/scheme, invalid time/ranges and production activation dependencies.

## 4. Policies stored in data, not environment

| Policy | Owner/storage |
|---|---|
| `clientType`, `accessPolicy`, `isDev`, exact callbacks, requested/allowed scopes | Versioned client record, super-admin controlled trust flags |
| Username and verified contact | Account/lookup records; owner edit with proofs and uniqueness |
| `shareEmail`, `shareProfile`, optional activity/device preferences | Versioned owner privacy record; required security processing retained |
| TOTP enabled/verified, MFA timestamp, role/assignments | Authoritative server/engine state, never client boolean |
| Session/grant/account versions and deleting state | Durable monotonic records, not feature flags |
| Retention/budget tiers | Typed deployment policy with tested bounds; documented in DATA_LIFECYCLE and ABUSE_DEFENSE |

V2 cannot disable email verification or admin MFA through runtime compatibility flags. New settings separate rollout availability from security policy. In-flight proof/key versions are bounded and retired explicitly.

## 5. Development and production client rules

Production clients (`isDev=false`) use exact HTTPS callbacks; no wildcard, IP literal, loopback or regex. Development clients use exact registered loopback and permitted HTTPS callbacks. A production IdP can host development clients only under its explicit operator policy. A transition to production removes invalid callback/origin entries in the same atomic change; conflicting policy values fail.

All new identity routes remain first-party even when a registered consumer origin is allowed for protocol calls. Frontend environment gets only public issuer/client/UI flags. A frontend signup button cannot enable a disabled backend enrollment path.
