# Environment Variables Reference

This document provides a reference for all environment variables used by the SWYRA Auth backend and frontend applications.

---

## 1. Backend Environment Variables (`hono/.env`)

| Variable | Required | Type | Default | Description |
|---|---|---|---|---|
| `NODE_ENV` | **Yes** | String | `development` | Operating environment: `development`, `production`, or `test`. |
| `PORT` | No | Number | `3000` | HTTP port for standalone server (`src/node-server.ts`). |
| `MONGO_URI` | **Yes** | String | - | Full MongoDB connection string (including credentials and database name). |
| `BETTER_AUTH_SECRET` | **Yes** | String | - | Cryptographic secret key used to sign sessions and encrypt client secrets (min 32 chars). |
| `BETTER_AUTH_URL` | **Yes** | String | - | Public URL of the auth backend API (e.g., `https://api.auth.domain.com/api/auth`). |
| `FRONTEND_URL` | **Yes** | String | - | Public origin of the frontend UI (e.g., `https://auth.domain.com`). Strictly origin, no path. |
| `UPSTASH_REDIS_REST_URL` | No | String | - | Upstash Redis REST endpoint for distributed rate limiting & token caching. |
| `UPSTASH_REDIS_REST_TOKEN` | No | String | - | Upstash Redis REST Bearer token. |
| `GOOGLE_CLIENT_ID` | No | String | - | Google OAuth 2.0 Web Client ID for social login. |
| `GOOGLE_CLIENT_SECRET` | No | String | - | Google OAuth 2.0 Client Secret for social login. |
| `TRUSTED_PROXY_CIDRS` | No | String | `""` | Comma-separated list of trusted proxy CIDRs (e.g. Cloudflare / ALB) for client IP extraction. |
| `UV_THREADPOOL_SIZE` | No | Number | `16` | libuv worker threadpool count for scrypt hashing concurrency. |
| `AUTH_PUBLIC_SIGNUP_ENABLED` | No | Boolean | `false` in prod | Set to `true` to allow open public self-registration. |

---

## 2. Frontend Environment Variables (`frontend/.env`)

| Variable | Required | Type | Default | Description |
|---|---|---|---|---|
| `VITE_AUTH_URL` | **Yes** | String | `http://localhost:3000` (dev) | Public URL of the backend API used for API calls and discovery. |

---

## 3. Consumer Application Environment Variables

| Variable | Required | Type | Example | Description |
|---|---|---|---|---|
| `AUTH_ISSUER` | **Yes** | String | `https://auth.yourdomain.com` | Base origin of the SWYRA Auth Identity Provider. |
| `JWKS_URL` | **Yes** | String | `https://auth.yourdomain.com/.well-known/jwks.json` | Public RS256 key set endpoint for offline JWT verification. |
| `CLIENT_ID` | **Yes** | String | `qMoXkZwvWnZJRmFhpiTyzLMozZYrwvlF` | Unique OAuth 2.1 client identifier issued in Admin Console. |
| `CLIENT_SECRET` | Backend only | String | `HQEFWhArRpYvjySBrzSbtBBlOpeZDpHY` | Plaintext client secret (never committed to public repositories). |
| `REDIRECT_URI` | **Yes** | String | `https://app.example.com/api/auth/callback` | Whitelisted callback route registered for the application. |
