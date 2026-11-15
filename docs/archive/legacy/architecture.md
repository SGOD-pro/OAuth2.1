# Architecture

## System Shape
This project is a pre-written, self-hosted, centralized OAuth 2.1 / OIDC identity provider. It is designed to be cloned by a developer, configured with their own database and infrastructure, and deployed anywhere with zero always-on infrastructure costs.

- **Frontend (The Auth Server UI)**: React 19 + Vite + React Router v7. Built as a static bundle. It provides the login/signup pages, consent screens, and the admin dashboard. 
- **API Edge**: Hono. Deployed via platform-specific entry points using Hono's first-class runtime adapters. The core app logic in `hono/src/app.ts` is platform-agnostic.
- **Identity Engine**: Better Auth v1.x via npm. Implements OAuth 2.1/OIDC, session management, and TOTP MFA.
- **Primary Datastore**: MongoDB. The self-hoster provides a standard MongoDB connection string. MongoDB serves both persistent identity state (users, sessions, OAuth clients) AND ephemeral cross-invocation state (rate-limit counters, CORS origin cache) via TTL-indexed collections. No second database is required.
- **Local Dev**: Docker Compose (API + frontend + local MongoDB).

## Self-Hosting & Deployment Architecture (The Core Workflow)
The project is explicitly designed to be "config-only to stand up." A stranger can deploy this without reading the source code. The architecture supports two distinct frontend deployment scenarios, driven entirely by environment variables.

### Scenario A: Using the Provided React Frontend
The self-hoster wants the complete package (Admin Dashboard, Login UI, Consent Screens) out of the box.
1. **Clone & Install**: Clone the repo. Run `npm install` in root, `hono/`, and `frontend/`.
2. **Database Setup**: Create a MongoDB instance (e.g., MongoDB Atlas free tier). Grab the connection string.
3. **Backend Configuration**: Copy `hono/.env.example` to `hono/.env`. Fill in:
   - `MONGODB_URI` (Their database connection string)
   - `BETTER_AUTH_SECRET` (A randomly generated strong string for hashing/encryption)
   - `FRONTEND_URL` (The URL where the frontend will be hosted, e.g., `https://auth.myapp.com`)
   - `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` (Optional, for Google OAuth)
4. **Frontend Configuration**: Copy `frontend/.env.example` to `frontend/.env`. Fill in:
   - `VITE_API_URL` (The URL where the Hono backend will be hosted, e.g., `https://api.myapp.com`)
5. **Database Migration**: Run `npm run db:setup` in the `hono/` directory. This connects to MongoDB and creates the required collections (`user`, `session`, `oauthClient`, `rate_limits`, `origin_cache`) and applies the TTL indexes.
6. **Build & Deploy**:
   - **Frontend**: Run `npm run build` in `frontend/`. Deploy the `dist/` folder to a static host (Vercel, Netlify, S3+CloudFront).
   - **Backend**: Choose a platform. For example, if deploying to Railway, run `npm run build:node` (which executes `esbuild` targeting `node-server.ts`) and deploy the resulting `dist/index.js` bundle.
7. **Admin Promotion**: Register an account on the new auth server. Run the `make-admin.ts` script locally against the database to promote that account to `role: "admin"`.

### Scenario B: Building a Custom Frontend
The self-hoster only wants the API backend (the identity engine) and wants to build their own UI (e.g., in Next.js or Vue).
1. **Backend Setup**: Follow steps 1-3 and 5-7 from Scenario A. The `FRONTEND_URL` env var should point to wherever they plan to host their custom frontend.
2. **Custom Frontend Development**: The self-hoster builds their own UI. They must simply make HTTP requests to the Hono backend's endpoints (`/api/auth/*`, `/api/admin/*`, `/.well-known/*`). 
3. **CORS Handling**: The Hono backend dynamically allows CORS requests from any origin registered as an OAuth Client, plus the `FRONTEND_URL` specified in the backend `.env`. No code changes required in the backend to support the custom frontend.

## Multi-Platform Deploy Architecture (Backend)
The app code (`hono/src/app.ts`) is platform-agnostic. Each target gets its own thin entry point file. The self-hoster chooses which entry point to build based on their target platform:

| Platform | Entry Point | Adapter | Notes |
| --- | --- | --- | --- |
| AWS Lambda | `hono/src/lambda.ts` | `hono/aws-lambda` | Set reserved concurrency to match the user's DB tier connection limits. |
| Vercel | `hono/src/vercel.ts` | `hono/vercel` | Serverless Functions. Connection pooling varies per invocation. |
| Netlify | `hono/src/netlify.ts` | `hono/netlify` | Same connection-pooling caveat as Vercel. |
| Railway/Fly/Render | `hono/src/node-server.ts` | `hono/node-server` | Long-lived container, natural connection reuse. Simplest target. |
| GCP Cloud Run | `hono/src/node-server.ts` | `hono/node-server` | Set min-instances > 0 for warm connection pool. |
| Azure Container Apps | `hono/src/node-server.ts` | `hono/node-server` | Same as GCP Cloud Run. |
| Cloudflare Workers | `hono/src/cloudflare.ts` | `hono/cloudflare-workers` | No MongoDB Node driver support. Documented limitation. |

## Data Protection Strategy
- **Passwords**: Hashed one-way (bcrypt/argon2) via the Better Auth identity engine. If the DB leaks, plaintext passwords cannot be recovered.
- **Client secrets**: Hashed verify-only (same pattern as passwords). Shown once at issuance in the UI, never stored in plaintext, never displayed again.
- **TOTP secrets**: Encrypted at rest by the Better Auth Two-Factor plugin logic using the `BETTER_AUTH_SECRET` environment variable. If the DB leaks, TOTP secrets remain encrypted.
- **JWT access tokens**: RS256-signed, short-lived, verified via the JWKS public key endpoint (`/.well-known/jwks.json`). Consuming apps verify token integrity using the public key — no shared secret exposed.
- **Data in transit**: TLS enforced by the hosting platform, HSTS headers set by Hono middleware.
- **Data at rest**: MongoDB Atlas (or equivalent) encrypts at rest by default at the infrastructure level.
- **No hand-rolled encryption**: No symmetric-encryption layer over arbitrary fields. Hand-rolling crypto is an anti-corruption of the security model.

## OIDC Consumer-DB Workflow (Standard OIDC)
When a consuming application (an OAuth client registered against this auth server) authenticates a user, the data flow is standard OIDC. No sync service is built:
1. User is redirected to the auth service's login/signup page via the OAuth 2.1 authorize flow.
2. User authenticates (email/password, Google OAuth). If TOTP MFA is enabled, they must enter a 6-digit code before the flow can complete.
3. Auth service issues an authorization code → consuming app exchanges it for tokens (ID token + access token, RS256-signed JWT).
4. Consuming app decodes the ID token to read claims (`sub`, `email`, `role`, etc.).
5. Consuming app optionally calls `/api/auth/oauth2/userinfo` for additional claims.
6. Consuming app creates/updates a **local user row in its own database**, keyed on `sub`. The auth service does not push data to the consuming app.

## Runtime Boundaries
- The frontend (whether ours or a custom one) must not query MongoDB directly. All DB access goes through the Hono API.
- Admin authorization is enforced at the API boundary (Hono middleware), never only in the frontend route guard.
- Admin login requires username/password plus a valid TOTP code (when 2FA is enabled).
- Entry point files (`lambda.ts`, `vercel.ts`, etc.) contain only adapter wiring — no business logic, no middleware, no route definitions. All of that lives in `app.ts`.
- The Better Auth identity engine code must not be altered to add multi-tenant abstractions.

## Deployment Considerations for Self-Hosters
Because this is a pre-written service where the user brings their own infrastructure, the codebase is complete and secure. However, the deployer must be aware of the following platform-specific constraints when setting up their own DB and hosting:
- **Database Connection Limits**: The deployer chooses their own MongoDB tier (e.g., MongoDB Atlas). If they deploy the API to a highly concurrent serverless environment (like AWS Lambda or Vercel), they must ensure their chosen database tier can handle the connection pool size, or configure concurrency limits on their hosting platform accordingly.
- **Cloudflare Workers Limitation**: The deployer cannot run this specific pre-written auth service on Cloudflare Workers. The standard MongoDB Node.js driver requires Node.js or a compatible runtime, which Cloudflare Workers does not natively provide. Deployers must choose a Node-compatible host (Lambda, Railway, Vercel, etc.).
- **AWS Lambda Security (WAF)**: If the deployer chooses to host the API on AWS Lambda using a raw Function URL, AWS does not natively support attaching a Web Application Firewall (WAF) directly to it. To use a WAF, the deployer must place API Gateway or CloudFront in front of their Lambda function. This is a platform constraint, not a code issue.
