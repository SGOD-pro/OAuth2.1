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

## Phase 1: Portability and Security Hardening

Goal: the system is secure and portable. A stranger can deploy to any platform.

### 1a. MongoDB TTL migration

- Replaces DynamoDB.
- Create `rate_limits` and `origin_cache` collections in MongoDB with TTL indexes (`expireAfterSeconds`).
- Rewire `hono/src/middleware/rate-limit.ts` and `hono/src/cache/origin-cache.ts` from `hono/src/db/dynamo.ts` to use MongoDB TTL collections per `design.md`.
- Remove the DynamoDB table from `hono/template.yaml` and delete `hono/src/db/dynamo.ts`.
- Remove AWS SDK DynamoDB imports.
- Verify: two concurrent invocations, such as two parallel curl loops or `sam local` processes, enforce a consistent rate-limit count and see a consistent origin-allow decision after cache invalidation.
- Verify: the MongoDB TTL reaper deletes expired documents. Running `db.rate_limits.find()` after 70 seconds should return empty.

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

## Phase 2: Premium Frontend Redesign (Current Phase)

Goal: Redesign the existing React frontend to feel like a premium, enterprise-grade identity provider, using the Cohere design system and animated gradient aesthetics. The agent must read the existing frontend code first to preserve routing and API integration.

### 2a. Design System & Foundation Integration
- Integrate the Cohere design system (colors, typography, spacing, radii).
- Implement animated mesh gradient backgrounds (warm orange/pink/purple, deep blue/green) for public-facing auth pages.
- Ensure dark mode/light mode parity where applicable, prioritizing the premium "feel."

### 2b. Public Auth Pages (End-user facing)
- Login Page: Premium glassmorphism card over animated gradient. Email/password + Google OAuth.
- Register Page: Similar aesthetic, for end-users of registered client apps. Password strength indicator.
- Consent Screen: Clean, trustworthy UI showing app name, scopes, and authorize/deny buttons.
- OAuth Callback: Loading states with smooth transitions.

### 2c. Admin Panel (Self-hoster facing)
- Admin Dashboard: Stats cards (users, clients, logins) using Cohere component specs.
- Admin Logs Page: Read view of recent sign-ins, styled as a modern data table.
- Admin Client Management: CRUD UI for OAuth clients.

**Constraint:** Frontend route guards (AdminRoute.tsx) and API state management must remain intact. Only presentation and layout change.
**Gate:** Frontend compiles, all existing API integrations still function, visual review confirms premium gradient/Cohere aesthetic.

## Phase 3: Admin & Client App TOTP MFA Integration (Completed)

Goal: Secure admin accounts with standard TOTP MFA and verify the OIDC flow extends this to client apps.

### 3a. Backend Plugin Enablement (Done)
- Enable twoFactor plugin in Better Auth config (hono/src/utils/auth.ts).
- Ensure backend endpoints for TOTP setup, verification, and backup codes are exposed.

### 3b. Frontend MFA UI Fixes & Enforcement (Done)
- Fix the "Enable 2FA" loop: The setup must require typing a 6-digit code to finalize. The manual key/QR must be hidden permanently after successful setup.
- Fix login flow: Admin must be blocked from dashboard access until 6-digit code is verified.
- Backup code fallback must be functional.

### 3c. Client App MFA Verification (Done)
- Verify that if a user has TOTP enabled, logging into a registered OAuth client app via the centralized login screen forces the TOTP prompt before redirecting back to the client app.
- No new code needed for this—it is an inherent benefit of the OIDC centralized auth architecture. Document this behavior in the README.

**Gate:** Admin can enable 2FA (verifying a 6-digit code), log out, and cannot access the dashboard without a 6-digit code. Client app login inherits this MFA requirement automatically.

## Phase 4: Ship and Document (Current Phase)

Goal: The artifact is public and legible to someone evaluating it in an interview.

- Push the repo public. Confirm all markdown docs are present and current.
- Write one public post narrating the engineering decisions (lambda bug, Mongo TTL, UI/UX premium redesign, TOTP, deploy anywhere).
- Add the repo and post to resume/LinkedIn immediately.

**Gate:** Phase 4 is done when the public repo + public writeup exist and are linked from resume/LinkedIn.

## Phase Gate Rule

- A phase may not begin until the previous one is verified against the concrete checks listed.
- If the 3-week clock runs out mid-phase, the project freezes at the last verified phase and ships in that state.