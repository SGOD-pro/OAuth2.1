# SWYRA Auth -- Production Deployment Guide (DEPLOYMENT.md)

**Authority:** Authoritative Production Deployment & Operational Runbook  
**Target:** DevOps Engineers, Platform Administrators, and Site Reliability Engineers  

**V2 status (2026-11-19):** The multi-account identity platform is a planned
migration, not deployed functionality. Follow [PHASES.md](PHASES.md) and
[DATA_LIFECYCLE.md](DATA_LIFECYCLE.md). Current source findings are recorded in the
[baseline review](reviews/2026-11-19-identity-platform-baseline.md).

---

## 1. Deployment Topology Overview

SWYRA Auth operates across two complementary cloud infrastructures:

1. **Frontend & Edge Gateway (Vercel):**
   - Hosts the React SPA frontend (login, consent, account settings).
   - Serves as the public edge reverse-proxy. Rewrites `/api/*` to the AWS Lambda backend.
   - Injects the trusted perimeter header `x-gateway-secret` on rewritten requests.
2. **Backend Engine (AWS Lambda):**
   - High-performance Node.js 24 runtime executing the bundled Hono server (`dist/index.cjs`).
   - Connects to MongoDB Atlas for persistence and Upstash Redis for distributed rate limiting.

---

## 2. Infrastructure Deployment Steps

### 2.1 Backend Deployment (AWS Lambda via SAM)

#### Prerequisites
- AWS CLI configured with appropriate IAM permissions.
- AWS SAM CLI installed.
- Node.js 24+ and npm.

#### Build and Deploy
```bash
# 1. Navigate to backend directory
cd backend

# 2. Build the optimized single-file bundle
npm run build

# 3. Deploy via AWS SAM using samconfig.toml parameters
sam build
sam deploy --config-file samconfig.toml
```

#### Environment Variables on AWS Lambda
Ensure the Lambda environment variables are configured in AWS Systems Manager Parameter Store or Lambda environment:
- `NODE_ENV=production`
- `MONGO_URI=mongodb+srv://...`
- `BETTER_AUTH_SECRET=<min 32-character secret>`
- `BETTER_AUTH_URL=https://oauth21.vercel.app`
- `FRONTEND_URL=https://oauth21.vercel.app`
- `INTERNAL_GATEWAY_SECRET=<64-hex character secret>`
- `TRUSTED_PROXY_CIDRS=127.0.0.1/32,10.0.0.0/8`
- `ALLOW_DEV_CLIENTS_IN_PRODUCTION=false`
- `AUTH_PUBLIC_SIGNUP_ENABLED=true`

---

### 2.2 Frontend & Edge Gateway Deployment (Vercel)

#### Build Configuration
Before triggering deployment on Vercel, the edge rewrite rules must be populated with the active `INTERNAL_GATEWAY_SECRET` without committing the secret to version control.

```bash
# Prepare edge rewrite configuration from environment
node scripts/prepare-vercel-config.mjs

# Build frontend bundle
cd frontend
npm run build
```

#### Vercel Environment Variables
Configure the following in the Vercel Project Settings:
- `INTERNAL_GATEWAY_SECRET`: The exact 64-hex string configured on AWS Lambda.
- `VITE_PUBLIC_SIGNUP_ENABLED`: `true` (or `false` to disable public sign-up globally).

---

## 3. Secret Management & Rotation Protocols

### 3.1 Rotating `INTERNAL_GATEWAY_SECRET` & Remediation of Historical Secrets

> [!CAUTION]
> **Mandatory Production Rotation of Historical Secrets:**  
> Any secret values previously checked into Git history (including historical keys `139f62ef...` and `d5856917...`) MUST be treated as compromised. Operators MUST manually generate and configure fresh secrets in AWS Lambda and Vercel project settings. The repository now uses untracked `vercel.json` and `frontend/vercel.json` generated from tracked `*.template.json` files to guarantee secret-bearing deployment configuration is never tracked in Git.

The `INTERNAL_GATEWAY_SECRET` authenticates the edge proxy to the Lambda function. SWYRA Auth accepts strictly the `x-gateway-secret` header (legacy secondary headers like `x-internal-secret` are permanently removed).

**Zero-Downtime Secret Rotation Procedure:**

1. **Generate a fresh 64-character hex secret:**
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
2. **Dual-Secret Overlap on AWS Lambda:** Configure `INTERNAL_GATEWAY_SECRET` on AWS Lambda with both current and new secrets separated by a comma (`currentSecret,newSecret`). The backend evaluates each secret with timing-safe comparison on incoming `x-gateway-secret` headers.
3. **Update Vercel Edge:** Update `INTERNAL_GATEWAY_SECRET` in Vercel Project Settings with the new secret and trigger a deployment. The build script `scripts/prepare-vercel-config.mjs` injects the secret into an untracked `vercel.json` during the build.
4. **Finalize on AWS Lambda:** Once Vercel edge deployment completes, update AWS Lambda's `INTERNAL_GATEWAY_SECRET` to contain only `newSecret`.
5. **Update `backend/.env`:** Update the local environment file for testing.
6. **Verify Perimeter:** Execute `npm run test:direct-backend` to ensure the new secret is active and invalid/legacy headers are rejected (403).

### 3.2 Rotating Client Secrets

Confidential OAuth clients may rotate secrets without downtime:
1. Request a secret rotation via Super-Admin API: `POST /api/admin/clients/:clientId/rotate-secret`.
2. Update the consumer application's `CLIENT_SECRET` environment variable.
3. Restart the consumer application.

### 3.3 Identity Domain Role Migration Runbook

Before upgrading production to the mutually exclusive administrator model, execute the migration procedure:

1. **Create Database Backup:**
   ```bash
   mongodump --uri="$MONGO_URI" --out="backup_$(date +%Y%m%d_%H%M%S)"
   ```

2. **Run Read Only Audit Dry Run:**
   ```bash
   npm --prefix backend run migrate:roles
   ```
   Inspect the classification summary:
   - **Class A (`super-admin`):** Global administrators with explicit null scope.
   - **Class B (`app-admin`):** Application administrators with active client assignments.
   - **Class C (`user`):** Standard end users.
   - **Class D (Flagged):** Conflicting or ambiguous records. These are never automatically promoted.

3. **Resolve Class D Flagged Accounts:**
   If any accounts are flagged in Class D, operators must inspect records and resolve them before or after migration.

4. **Apply Migration:**
   ```bash
   npm --prefix backend run migrate:roles:apply
   ```
   The migration updates domain roles, deletes active session cookies for migrated users, and revokes refresh token families in `oauth_token_families`. Note that active RS256 access tokens remain valid until their expiration window completes (maximum fifteen minutes).

5. **Rollback Procedure (if required):**
   This legacy role-migration restore example must not restore deleted subjects,
   revoked credentials or erased account keys. V2 restores require quarantine and
   independent tombstone replay before traffic. Never run it as an automatic V2 rollback.
   ```bash
   mongorestore --uri="$MONGO_URI" backup_<timestamp>/
   ```

---

## 4. Production Pre-Flight Checklist

Before directing live user traffic to SWYRA Auth, verify:

- [ ] `NODE_ENV` is set to `production` on both Lambda and edge environments.
- [ ] `ALLOW_DEV_CLIENTS_IN_PRODUCTION` is set to `false`.
- [ ] `INTERNAL_GATEWAY_SECRET` is non-empty, high-entropy, and matches between Vercel and Lambda.
- [ ] `INTERNAL_GATEWAY_SECRET` is NOT hardcoded in git-tracked `vercel.json` or `samconfig.toml` files.
- [ ] `TRUSTED_PROXY_CIDRS` is configured with the proxy IP ranges.
- [ ] MongoDB connection uses TLS and connects to a replica set with transaction support.
- [ ] All required suites in `docs/security/security-suite-manifest.json` pass: `npm run test:all-security`. Record blocked/skipped checks explicitly.
- [ ] Documentation consistency linter passes: `npm run security:docs-check`.
- [ ] Integration contract linter passes: `npm run security:integration-check`.
- [ ] Discovery metadata at `/.well-known/openid-configuration` returns HTTPS URLs.
- [ ] Public JWKS endpoint at `/.well-known/jwks.json` returns active RSA public keys.

## 5. V2 release and migration runbook requirements

1. Pin the source commit and audit current client authentication methods, access
   flags, verification provenance, identities, role assignments and secret exposure.
   Rotate historically exposed secrets in actual deployments; git edits do not rotate them.
2. Close phase 0 findings before enabling new public enrollment/SSO behavior.
   Establish CI coverage for docs-only changes as well as runtime/security changes.
3. Apply additive client-policy schema and dual-read support. Dry-run ambiguous
   clients/duplicates; preserve current private clients and explicit app assignments.
4. Deploy verified enrollment with a real bounded mail queue, delivery provider,
   per-mailbox/IP/browser/global budgets and monitoring before enabling signup.
   Do not simply set AUTH_EMAIL_VERIFICATION_ENABLED and assume OTP is implemented.
5. Require administrative TOTP enrollment through restricted sessions. Test recovery,
   promotion, social callback and plugin admin paths before rolling out multiple accounts.
6. Prove multi-account tab isolation and logout semantics with real browser tests.
   Preserve old clients and expire/reverify legacy sessions safely during cutover.
7. Select account key infrastructure only after latency/cost/quotas, engine adapter,
   old-key recovery and provider destruction-delay tests. Inventory and migrate every
   plaintext copy with checkpointed verification before erasure is advertised.
8. Deploy durable deletion/tombstone jobs and key-cache invalidation before account
   deletion UI. Restore pre-deletion snapshots into quarantine and prove no resurrection.
9. Exercise real distributed Redis/Mongo failures, edge quotas, worker/mail backlogs,
   key-service outage and bounded load. Fingerprints are not the edge DDoS defense.
10. Complete license/provenance, dependency/SBOM audit, private vulnerability reporting,
    fresh-secret validation, self-host setup, documented limitations and independent
    review. Public repository visibility alone is not release readiness.

Roll out by bounded cohorts with recorded rollback thresholds and telemetry. Rollback
may disable a feature or restore compatible code; it must not restore deleted accounts,
keys, consumed proofs, old privileges, or revoked token families. Production data
migration and deployment are separate actions from this documentation change.
