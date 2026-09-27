# Configuration & Environment Specification
**Version:** 2.1.0  
**Status:** Authoritative Configuration Guide

This document provides a comprehensive reference for configuring the **SWYRA Auth** identity provider in development, testing, and production environments.

---

## 1. Production Security Prerequisites & Fail-Fast Secrets

When `NODE_ENV=production`, the application applies strict startup validation (`backend/src/config/schema.ts`). The server will fail immediately at boot if any required security key is missing, invalid, or shorter than 32 characters.

| Secret / Config Name | Required in Production | Min Length | Purpose |
|---|---|---|---|
| `BETTER_AUTH_SECRET` | **Yes** | 32 chars | Primary cryptographic master key for Better Auth user sessions, database field encryption, and cookie signing. |
| `APP_ADMIN_JWT_SECRET` | **Yes** | 32 chars | Dedicated HMAC-SHA256 signing secret for Per-Application Administrator JWTs (`token_use: "app_admin"` and `token_use: "app_admin_mfa_pending"`). Disallows derivation fallback in production. |
| `APP_ADMIN_TOTP_KEY` | **Yes** | 32 chars | Dedicated AES-256-GCM encryption key for securing App Admin TOTP secrets and backup codes at rest in MongoDB (`app_admins.totpSecret`). |
| `INTERNAL_GATEWAY_SECRET` | **Yes** | 32 chars | Shared secret protecting internal backend management and direct Lambda invocation endpoints against unauthorized external bypass. |
| `MONGO_URI` | **Yes** | - | Full MongoDB connection string (MongoDB 6+ or Atlas) with read/write credentials and database name. |
| `BETTER_AUTH_URL` | **Yes** | - | Canonical public URL of the auth backend API (e.g. `https://api.auth.yourdomain.com`). Must be HTTPS and non-loopback in production. |
| `FRONTEND_URL` | **Yes** | - | Canonical public origin of the frontend UI (e.g. `https://auth.yourdomain.com`). Must be HTTPS and non-loopback in production. Strictly origin without path. |
| `TRUSTED_PROXY_CIDRS` | Recommended | - | Comma-separated list of trusted upstream proxy / reverse proxy CIDRs (e.g. Cloudflare / ALB / API Gateway ranges) for client IP extraction. |
| `ALLOW_DEV_CLIENTS_IN_PRODUCTION` | Optional | - | Set to `'true'` to permit OAuth clients with `localhost` redirect URIs in production (defaults to `'false'`). |

> [!IMPORTANT]
> In `development` and `test` modes only, `APP_ADMIN_JWT_SECRET`, `APP_ADMIN_TOTP_KEY`, and `INTERNAL_GATEWAY_SECRET` have permissive fallbacks for zero-friction local setup. In `production`, all four secrets are **strictly mandatory**.

---

## 2. Complete Environment Variables Specification

### Backend Variables (`backend/.env`)

```ini
# Environment Mode
NODE_ENV=production
PORT=3000

# Database
MONGO_URI=mongodb+srv://<user>:<password>@cluster0.xyz.mongodb.net/oauthservice?retryWrites=true&w=majority

# Core Authentication & Secrets (>= 32 characters each)
BETTER_AUTH_SECRET=your_32_char_random_better_auth_secret_here
BETTER_AUTH_URL=https://api.auth.yourdomain.com
FRONTEND_URL=https://auth.yourdomain.com

# Dedicated App Admin Secrets (Required in production, >= 32 characters)
APP_ADMIN_JWT_SECRET=your_32_char_app_admin_jwt_secret_here
APP_ADMIN_TOTP_KEY=your_32_char_app_admin_totp_encryption_key

# Gateway Protection (Required in production, >= 32 characters)
INTERNAL_GATEWAY_SECRET=your_32_char_internal_gateway_secret_here

# Reverse Proxy & Network Boundary
TRUSTED_PROXY_CIDRS=10.0.0.0/8,172.16.0.0/12,127.0.0.1/32

# Production Development Overrides
ALLOW_DEV_CLIENTS_IN_PRODUCTION=false

# Public Registration & Verification Controls
AUTH_PUBLIC_SIGNUP_ENABLED=true
AUTH_EMAIL_VERIFICATION_ENABLED=false

# Distributed Rate Limiting & Cache (Optional - falls back to Mongo TTL)
UPSTASH_REDIS_REST_URL=https://<instance>.upstash.io
UPSTASH_REDIS_REST_TOKEN=your_upstash_rest_token_here

# Social Providers (Optional)
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### Frontend Gateway Variables (`frontend/.env`)

```ini
# Canonical Backend Service Endpoint
VITE_AUTH_URL=https://api.auth.yourdomain.com
```

### Consumer Application Variables (Client Side)

```ini
# Consumer Backend / BFF (Confidential Client)
AUTH_ISSUER=https://auth.yourdomain.com
JWKS_URL=https://auth.yourdomain.com/.well-known/jwks.json
CLIENT_ID=your_client_id_from_admin_console
CLIENT_SECRET=your_plaintext_client_secret
REDIRECT_URI=https://app.yourdomain.com/api/auth/callback

# Consumer Frontend SPA (Public Client - NO CLIENT_SECRET!)
VITE_AUTH_ISSUER=https://auth.yourdomain.com
VITE_CLIENT_ID=your_client_id_from_admin_console
VITE_REDIRECT_URI=https://app.yourdomain.com/auth/callback
```

---

## 3. Application Modes: Public vs. Private Applications

SWYRA Auth enforces strong tenant isolation between public and private OAuth 2.1 client applications:

### Public Applications (`isPublic: true`, default)
- Any authenticated user in the global `user` collection can authorize and consent to grant scopes to the application.
- Self-registration is allowed via `/api/auth/sign-up/email` when `AUTH_PUBLIC_SIGNUP_ENABLED=true`.
- Intended for SaaS clients, general portals, and open consumer applications.

### Private Applications (`isPublic: false`)
- Strict authorization boundary: Even if a user has an active global session with SWYRA Auth, they **cannot** authorize for a private application unless their membership is explicitly provisioned in `user_app_registrations` (`{ clientId, userId }`).
- Requests to `/api/auth/oauth2/authorize` for unauthorized accounts are immediately intercepted and rejected with `403 Forbidden` (`registration_disabled`).
- Direct self-registration via `/api/auth/sign-up/email` for private applications is strictly blocked.
- User membership is managed exclusively by Super Admins and Scoped Application Administrators via the Admin Console or Admin API (`/api/admin/clients/:clientId/users`).

---

## 4. Rate Limiting & Abuse Defense Configuration

SWYRA Auth implements multi-layered rate limiting with Upstash Redis and automatic MongoDB TTL collection fallback:

| Limit Tier | Window | Threshold | Key Strategy | Purpose |
|---|---|---|---|---|
| **App-Admin Authentication** | 60s | 5 req / IP | Client IP (`admin_auth:<ip>`) | Prevents brute-forcing App Admin credentials. |
| **App-Admin MFA Verification** | 60s | 5 req / IP | Client IP (`admin_mfa:<ip>`) | Throttles TOTP and backup code guessing attempts. |
| **Standard User Auth** | 60s | 20 req / IP | Client IP (`auth:<ip>`) | Throttles interactive user logins. |
| **Credential Stuffing Target** | 60s | 5 req / Email | Normalized Email (`cred_stuffing:<email>`) | Defends against botnets rotating across thousands of IPs against a single victim account. |
| **Admin Provisioning** | 60s | 5 req / IP | Client IP (`admin_provision:<ip>`) | Throttles application admin provisioning. |

---

## 5. Reverse Proxy & Network Boundary Guidelines

For AWS ALB, Cloudflare, Nginx, or API Gateway reverse proxies:
1. Ensure the reverse proxy strips external `X-Forwarded-For` headers from untrusted clients and sets a single trusted IP or appends the client IP to the chain.
2. Configure `TRUSTED_PROXY_CIDRS` to match your proxy's exact subnet or egress CIDR blocks.
3. If deployed on AWS Lambda behind an API Gateway or Function URL, the built-in trusted proxy resolver handles internal VPC and gateway hops securely.
