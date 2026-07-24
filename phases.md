# Implementation Phases

## Ground Rule

This runs in parallel with job applications. Total project clock: 3 weeks, part-time.

## Phase 0: Triage

- Status: completed
- Deleted `backend/` (NestJS).
- Fixed `hono/src/lambda.ts` (`hono/aws-lambda`).
- Set Lambda reserved concurrency via SAM template.
- Stood up DynamoDB table, now being migrated to MongoDB TTL in Phase 1.
- `tsc --noEmit` passes.

## Phase 1: Portability, Security Hardening, MFA

### 1a. MongoDB TTL migration

- Replaces DynamoDB.
- Create `rate_limits` and `origin_cache` collections with TTL indexes.
- Rewire `rate-limit.ts` and `origin-cache.ts` to use MongoDB.
- Remove DynamoDB from SAM template.
- Verify concurrent invocations enforce rate limits and the TTL reaper deletes expired docs.

### 1b. Admin MFA

- Use TOTP via Better Auth `twoFactor` plugin.
- Enable the `twoFactor` plugin in Better Auth config.
- Add an "Enable 2FA" screen with QR code, manual key, 6-digit verification, and backup codes.
- Add a login-time TOTP prompt.
- Verify the admin can enable 2FA, scan QR with Google Authenticator, and log in with a 6-digit code.

### 1c. Security Scan Remediation

- `M10` (`make-admin.ts`): add explicit email confirmation prompt and log every promotion.
- Client-secret hashing: inspect Better Auth source. If plaintext, add hashing.
- `L2` (`WAF`): document as accepted risk and note the CloudFront-WAF upgrade path.

### 1d. Multi-Platform Deploy Config

- Create entry point files: `vercel.ts`, `netlify.ts`, `node-server.ts`.
- Write `.env.example`.
- Write platform-specific deploy notes in `README`.

### 1e. Config-Only Self-Host Verification

- Gate: hand the repo to someone unfamiliar. If they get stuck, fix the docs.

## Phase 2: Ship and Document

- Push the repo public.
- Ensure `projectrequirement.md` through `decision.md` are present.
- Write one public post narrating the engineering decisions: lambda bug, Mongo TTL, TOTP, deploy anywhere.
- Add the repo and post to resume and LinkedIn.
- Gate: public repo and public writeup exist and are linked.

## Phase Gate Rule

- If the 3-week clock runs out mid-phase, freeze at the last verified phase and ship in that state.
