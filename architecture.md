# Architecture

## System Shape

- Frontend: React 19 + Vite + React Router v7, static build, deployable to any static host.
- API edge: Hono, deployed via platform-specific entry points using Hono's first-class runtime adapters (`hono/aws-lambda`, `hono/vercel`, `hono/netlify`, `hono/node-server` for Railway/Fly/Render/GCP Cloud Run/Azure Container Apps, `hono/cloudflare-workers`).
- Identity engine: Better Auth v1.6.x + `@better-auth/oauth-provider` + `twoFactor` plugin (TOTP, RFC 6238, backup codes).
- Primary datastore: MongoDB Atlas for persistent identity state (users, sessions, OAuth clients) and ephemeral cross-invocation state (rate-limit counters, CORS origin cache) via TTL-indexed collections. No second database required.
- Local dev: Docker Compose for API, frontend, and MongoDB.

## Why Each Component Exists

- `Hono`: compiles to platform-specific bundles via first-class adapters. One `app.ts`, multiple entry points (`lambda.ts`, `vercel.ts`, `node-server.ts`, etc.).
- Better Auth + plugins: implements OAuth 2.1/OIDC and TOTP-based MFA (RFC 6238, QR provisioning, backup codes) correctly, without hand-rolling cryptography. The `twoFactor` plugin allows standard apps like Google Authenticator and Microsoft Authenticator to generate 6-digit codes locally.
- MongoDB Atlas: the only database. Serves both persistent state and ephemeral state (rate-limit counters, origin cache) via native TTL indexes (`expireAfterSeconds`). Atlas encrypts at rest by default at the infrastructure level.
- MongoDB TTL collections: replace the previous DynamoDB dependency entirely, making the system deployable to any platform without AWS-specific state infrastructure.

## Multi-Platform Deploy Architecture

The app code in `hono/src/app.ts` is platform-agnostic. Each target gets its own thin entry point:

| Platform | Entry Point | Adapter | Notes |
| --- | --- | --- | --- |
| AWS Lambda | `hono/src/lambda.ts` | `hono/aws-lambda` | Set reserved concurrency to match Atlas tier |
| Vercel | `hono/src/vercel.ts` | `hono/vercel` | Serverless Functions, connection pooling varies |
| Netlify | `hono/src/netlify.ts` | `hono/netlify` | Same connection-pooling caveat as Vercel |
| Railway/Fly/Render | `hono/src/node-server.ts` | `hono/node-server` | Long-lived container, natural connection reuse |
| GCP Cloud Run | `hono/src/node-server.ts` | `hono/node-server` | Set min-instances > 0 for warm connection pool |
| Azure Container Apps | `hono/src/node-server.ts` | `hono/node-server` | Same as GCP Cloud Run |
| Cloudflare Workers | `hono/src/cloudflare.ts` | `hono/cloudflare-workers` | No MongoDB driver support, documented limitation |

## Data Protection Strategy

- Passwords: hashed one-way with bcrypt or argon2 via Better Auth.
- Client secrets: hashed for verification only, shown once at issuance.
- TOTP secrets: encrypted at rest by Better Auth's `twoFactor` plugin.
- JWT access tokens: RS256-signed, verified via the JWKS public key endpoint.
- Data in transit: TLS enforced, HSTS headers set.
- Data at rest: MongoDB Atlas encrypts at rest by default.
- No hand-rolled encryption: no symmetric-encryption layer over arbitrary fields.

## OIDC Consumer-DB Workflow

Standard OIDC flow, with no new feature or sync service:

1. User authenticates via the auth service.
2. Auth service issues an ID token (JWT) containing claims such as `sub` and `email`.
3. The consuming app decodes the token and creates or updates a local user row in its own DB, keyed on `sub`.
4. The consuming app verifies subsequent JWTs using the auth service's public key from JWKS.

## Runtime Boundaries

- Frontend must not query MongoDB directly.
- Admin authorization is enforced at the API boundary with Hono middleware.
- Admin login requires username/password plus a valid TOTP code when 2FA is enabled.
- Entry point files contain only adapter wiring, not business logic.

## Current Known Risks

- MongoDB Atlas connection limits vary by tier. Each deploy target's connection-pooling behavior must be documented, not solved uniformly in code.
- Cloudflare Workers does not support the MongoDB Node driver natively.
- Lambda Function URLs cannot have AWS WAF attached directly. This is an accepted risk.
