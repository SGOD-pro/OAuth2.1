# SWYRA Auth -- Production Deployment Guide (DEPLOYMENT.md)

**Authority:** Authoritative Production Deployment & Operational Runbook  
**Target:** DevOps Engineers, Platform Administrators, and Site Reliability Engineers  

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

---

## 4. Production Pre-Flight Checklist

Before directing live user traffic to SWYRA Auth, verify:

- [ ] `NODE_ENV` is set to `production` on both Lambda and edge environments.
- [ ] `ALLOW_DEV_CLIENTS_IN_PRODUCTION` is set to `false`.
- [ ] `INTERNAL_GATEWAY_SECRET` is non-empty, high-entropy, and matches between Vercel and Lambda.
- [ ] `INTERNAL_GATEWAY_SECRET` is NOT hardcoded in git-tracked `vercel.json` or `samconfig.toml` files.
- [ ] `TRUSTED_PROXY_CIDRS` is configured with the proxy IP ranges.
- [ ] MongoDB connection uses TLS and connects to a replica set with transaction support.
- [ ] All 15 security test suites pass: `npm run test:all-security`.
- [ ] Documentation consistency linter passes: `npm run security:docs-check`.
- [ ] Integration contract linter passes: `npm run security:integration-check`.
- [ ] Discovery metadata at `/.well-known/openid-configuration` returns HTTPS URLs.
- [ ] Public JWKS endpoint at `/.well-known/jwks.json` returns active RSA public keys.
