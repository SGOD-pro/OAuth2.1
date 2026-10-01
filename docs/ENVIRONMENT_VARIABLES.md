# Environment Variables Reference
**Version:** 2.1.0  
**Status:** Supporting Environment Schema Reference  
**Normative Reference:** For the single authoritative security architecture, perimeter gateway trust, and client mode lifecycle, refer strictly to [docs/SECURITY_CANONICAL.md](SECURITY_CANONICAL.md).

This document provides a complete reference for all environment variables used by the SWYRA Auth backend, frontend gateway, and consumer applications.

---

## 1. Backend Environment Variables (`backend/.env`)

These variables configure the Hono + Better Auth identity engine (`backend/src/config/schema.ts`).

| Variable | Required in Prod | Dev Default | Type | Description |
|---|---|---|---|---|
| `NODE_ENV` | **Yes** | `development` | String | Operating mode: `development`, `production`, or `test`. |
| `PORT` | No | `3000` | Number | Local HTTP port for standalone server (`src/node-server.ts`). |
| `MONGO_URI` | **Yes** | - | String | Full MongoDB connection string (including auth credentials and database name). |
| `BETTER_AUTH_SECRET` | **Yes** | - | String (min 32) | Primary cryptographic master key for session signatures, token encryption, and cookie signing. |
| `BETTER_AUTH_URL` | **Yes** | - | String (HTTPS in prod) | Canonical public URL of the auth backend API (e.g. `https://api.auth.yourdomain.com`). |
| `FRONTEND_URL` | **Yes** | - | String (HTTPS in prod) | Canonical public origin of the frontend UI (e.g. `https://auth.yourdomain.com`). Strictly origin, no path. |
| `APP_ADMIN_JWT_SECRET` | **Yes** | Derived in dev | String (min 32) | Dedicated HMAC-SHA256 signing secret for Per-Application Administrator JWTs. Must be explicitly set in production. |
| `APP_ADMIN_TOTP_KEY` | **Yes** | Derived in dev | String (min 32) | Dedicated AES-256-GCM encryption key for securing App Admin TOTP secrets and backup codes at rest in MongoDB. |
| `INTERNAL_GATEWAY_SECRET` | **Yes** | Derived in dev | String (min 32) | Shared secret required to invoke protected internal management routes and shield direct Lambda invocations. |
| `TRUSTED_PROXY_CIDRS` | Recommended | `""` | String | Comma-separated list of trusted upstream proxy CIDRs (e.g. Cloudflare / ALB / API Gateway) for client IP extraction. |
| `ALLOW_DEV_CLIENTS_IN_PRODUCTION` | No | `false` | Boolean | When set to `true`, permits creating brand-new OAuth clients with loopback URIs in production. Existing clients can be transitioned between development and production modes individually by authorized administrators. |
| `AUTH_PUBLIC_SIGNUP_ENABLED` | No | `true` | Boolean | Set to `false` to disable public self-registration globally. |
| `AUTH_EMAIL_VERIFICATION_ENABLED` | No | `false` | Boolean | Set to `true` to require mandatory email verification before login. |
| `UPSTASH_REDIS_REST_URL` | No | - | String | Upstash Redis REST endpoint for distributed rate limiting & token caching. |
| `UPSTASH_REDIS_REST_TOKEN` | No | - | String | Upstash Redis REST Bearer token. |
| `GOOGLE_CLIENT_ID` | Optional | - | String | Google OAuth 2.0 Web Client ID for social federation. |
| `GOOGLE_CLIENT_SECRET` | Optional | - | String | Google OAuth 2.0 Client Secret for social federation. |
| `UV_THREADPOOL_SIZE` | No | `16` | Number | libuv worker threadpool count for scrypt password hashing concurrency. |

> [!CAUTION]
> In production (`NODE_ENV=production`), `BETTER_AUTH_SECRET`, `APP_ADMIN_JWT_SECRET`, `APP_ADMIN_TOTP_KEY`, and `INTERNAL_GATEWAY_SECRET` must **each be at least 32 characters** long and completely distinct from each other.

---

## 2. Frontend Environment Variables (`frontend/.env`)

These variables configure the React Single-Page Application (Admin and Consent UI).

| Variable | Required | Type | Default | Description |
|---|---|---|---|---|
| `VITE_AUTH_URL` | **Yes** | String | `http://localhost:3000` | Public URL of the backend API used for API requests and discovery. |

---

## 3. Consumer Application Environment Variables

Consumer applications must configure environment variables according to their architecture:

### A. Confidential Client (Backend / BFF: Next.js, Express, FastAPI, Django)
These variables MUST be stored in server-only configuration. **NEVER expose `CLIENT_SECRET` to browser code.**

| Variable | Required | Type | Example | Description |
|---|---|---|---|---|
| `AUTH_ISSUER` | **Yes** | String | `https://oauth21.vercel.app` | Base origin of the SWYRA Auth Identity Provider. |
| `JWKS_URL` | **Yes** | String | `https://oauth21.vercel.app/.well-known/jwks.json` | Public RS256 key set endpoint for offline JWT verification. |
| `CLIENT_ID` | **Yes** | String | `qMoXkZwvWnZJRmFhpiTyzLMozZYrwvlF` | Unique OAuth 2.1 client identifier issued in Admin Console. |
| `CLIENT_SECRET` | **Yes** | String | `HQEFWhArRpYvjySBrzSbtBBlOpeZDpHY` | Plaintext client secret (never committed to public repos). |
| `REDIRECT_URI` | **Yes** | String | `https://app.example.com/api/auth/callback` | Whitelisted callback route registered for this client. |

### B. Public Client (Browser SPA: Vite, React, Vue)
Public clients cannot keep secrets. **They do NOT configure or use `CLIENT_SECRET`.**

| Variable | Required | Type | Example | Description |
|---|---|---|---|---|
| `VITE_AUTH_ISSUER` | **Yes** | String | `https://oauth21.vercel.app` | Base origin of the SWYRA Auth IdP. |
| `VITE_CLIENT_ID` | **Yes** | String | `qMoXkZwvWnZJRmFhpiTyzLMozZYrwvlF` | Unique OAuth 2.1 client identifier. |
| `VITE_REDIRECT_URI` | **Yes** | String | `http://localhost:5173/auth/callback` | Whitelisted browser callback route. |

> [!WARNING]
> **NEVER use `NEXT_PUBLIC_CLIENT_SECRET` or `VITE_CLIENT_SECRET`.**  
> Public clients use PKCE (`code_challenge` + `code_verifier`) and do not possess a client secret. Placing a client secret in frontend build bundles completely compromises application authentication.
