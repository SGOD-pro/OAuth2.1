# Implementation Phases

## Ground Rule

This runs in parallel with job applications, not before them. Total project clock: 3 weeks, part-time. A phase does not begin until the previous phase is verified against a concrete check.

## Phase 0: Triage

- Status: done. Evidence in `memory.md`.
- Deleted `backend/` (NestJS). `git grep @nestjs` returns nothing outside git history.
- Fixed `hono/src/lambda.ts`: `hono/lambda-edge` -> `hono/aws-lambda`.
- Set Lambda reserved concurrency via SAM template.
- Stood up DynamoDB table, on-demand and TTL, and rewired rate limiter and origin cache.
- `tsc --noEmit` passes with strict mode.
- No `process.env` reads outside the composition root.
- Note: Phase 0 used DynamoDB. Phase 1a migrates this to MongoDB TTL collections (ADR 006 update). This is not a re-do; it is a portability improvement that makes "deploy anywhere" true and removes AWS vendor lock-in.

## Phase 1: Portability, Security Hardening, MFA

Goal: the system is secure, portable, and MFA-protected. A stranger can deploy to any platform.

### 1a. MongoDB TTL migration

- Replaces DynamoDB.
- Create `rate_limits` and `origin_cache` collections in MongoDB with TTL indexes (`expireAfterSeconds`).
- Rewire `hono/src/middleware/rate-limit.ts` and `hono/src/cache/origin-cache.ts` from `hono/src/db/dynamo.ts` to use MongoDB TTL collections per `design.md`.
- Remove the DynamoDB table from `hono/template.yaml` and delete `hono/src/db/dynamo.ts`.
- Remove AWS SDK DynamoDB imports.
- Verify: two concurrent invocations, such as two parallel curl loops or `sam local` processes, enforce a consistent rate-limit count and see a consistent origin-allow decision after cache invalidation.
- Verify: the MongoDB TTL reaper deletes expired documents. Running `db.rate_limits.find()` after 70 seconds should return empty.

### 1b. Admin MFA

- Use TOTP via Better Auth `twoFactor` plugin.
- Enable the `twoFactor` plugin in Better Auth config (`hono/src/utils/auth.ts`).
- Add an "Enable 2FA" screen: QR code and manual key, confirm with a 6-digit code, show backup codes once.
- Add a login-time TOTP prompt: after email and password, if 2FA is enabled, show a 6-digit input.
- Add backup code fallback on login.
- Verify: the admin can enable 2FA, scan the QR with Google Authenticator, and log in with a 6-digit code.
- Verify: backup code works once and is consumed.
- Verify: login without a TOTP code is rejected.

### 1c. Security Scan Remediation

- `M10` (`make-admin.ts`): add explicit email confirmation prompt before writing. Log every promotion with timestamp and script runner identity. No break-glass ceremony.
- Client-secret hashing: inspect Better Auth `oauth-provider` source. Confirm `client_secret` is hashed at rest, not plaintext. If plaintext, add hashing before storage, hash on create, verify-only on token exchange.
- `L2` (`WAF`): document as accepted risk in `README`. Note CloudFront-WAF and API Gateway HTTP API as production upgrade paths. Do not build in this timebox.
- Verify: `make-admin.ts` prompts for email confirmation and logs the promotion.
- Verify: client secrets are not readable from the database in plaintext, query `oauthClient` collection.

### 1d. Multi-Platform Deploy Config

- Create entry point files for each target: `lambda.ts` exists, plus `vercel.ts`, `netlify.ts`, and `node-server.ts`. Each imports `app` from `app.ts` and exports the platform-specific handler.
- Write `.env.example` covering every variable in `envSchema` with one-line descriptions.
- Write platform-specific deploy notes in `README`: connection-pooling behavior, reserved concurrency (`Lambda`), min-instances (`Cloud Run`), known limitations (`Cloudflare Workers`).
- Verify: `app.ts` has zero platform-specific imports.
- Verify: each entry point file is under 20 lines.
- Verify: `tsc --noEmit` passes for all entry points.

### 1e. Config-Only Self-Host Verification

- Write a setup guide: clone -> fill `.env` -> run Better Auth CLI migration -> pick platform -> deploy.
- Gate: hand the repo and `README` to someone who has not touched this project. Have them attempt setup with no help. If they get stuck on an undocumented step, that step gets fixed before Phase 2. Self-review does not count.

## Phase 2: Ship and Document

Goal: the artifact is public and legible to someone evaluating it in an interview.

- Push the repo public. Confirm `projectrequirement.md` through `decision.md` are present and current; they are load-bearing for how a reviewer understands scope decisions.
- Write one public post, blog or LinkedIn, narrating the real engineering decisions:
- The lambda-edge/aws-lambda bug and why it mattered.
- Why in-memory rate limiting silently breaks under concurrent Lambda execution.
- Why MongoDB TTL collections replaced DynamoDB, portability without new infrastructure.
- Why TOTP via plugin beats email OTP, no mailer, no deliverability failure mode, backup codes.
- Why "deploy anywhere" is true now and wasn't before, Hono adapters plus single datastore.
- The data protection approach, hashing, not hand-rolled encryption, and why.
- Add the repo and post to resume and LinkedIn immediately. Do not wait for "more finished."
- Gate: Phase 2 is done when the public repo and public writeup exist and are linked from resume and LinkedIn. Nothing beyond this is in scope without a new, deliberate decision.

## Phase Gate Rule

- A phase may not begin until the previous one is verified against the concrete checks listed.
- If the 3-week clock runs out mid-phase, the project freezes at the last verified phase and ships in that state. A frozen-but-verified Phase 1 is a legitimate stopping point. An unverified Phase 2 is not. Do not claim "shipped" without the Phase 2 gate met.
