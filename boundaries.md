# Boundaries

## External Boundaries
- **Browser clients** may only interact with the deployed Frontend and the public API (`/api/auth/*`, `/.well-known/*`). 
- **Consuming applications** (registered OAuth clients) may only interact with the documented OIDC endpoints (`/api/auth/oauth2/*`). They do not have direct access to the Auth Server's database.
- **Consuming applications** store user data in their own databases, keyed on the `sub` claim from ID tokens. The auth service does not sync, push, or share data to consuming-app databases — standard OIDC token/userinfo claims are the entire mechanism.
- **Admin operations** are restricted to authenticated users with `role === "admin"`, enforced server-side via Hono middleware. 
- **Admin login** requires valid credentials (email/password) PLUS a valid TOTP 6-digit code (when 2FA is enabled). 
- **Self-hosters** interact with the system only through environment variables, the admin UI/API, and the provided database setup/migration scripts. They must never need to edit application code to achieve a standard deployment.

## Service Boundaries
- **Frontend**: Owns presentation and route orchestration only. It must never query MongoDB directly. Whether using our provided React app or a custom-built frontend, all data access goes through the Hono API.
- **Hono (API Edge)**: Owns HTTP policy: CORS, security headers, CSRF, rate limiting, admin role gating, and TOTP verification gates. It delegates all identity and crypto logic to the identity engine.
- **Identity Engine**: Better Auth v1.x via npm. Implements OAuth 2.1/OIDC, session management, and TOTP MFA.
- **MongoDB**: Owns ALL state — persistent (users, sessions, OAuth clients) AND ephemeral (rate-limit counters, origin cache via TTL collections). There is no second database (e.g., Redis, DynamoDB).
- **Platform Entry Points** (`lambda.ts`, `vercel.ts`, `node-server.ts`, etc.): Own only platform adapter wiring. They must not contain middleware, route definitions, or business logic. All of that lives in `app.ts`.

## Service Limits
- **Admin Endpoints**: Must reject requests without a valid session (`401`) or from non-admin users (`403`).
- **Admin Rate Limiting**: Strictly limited to authentication endpoints (`POST /api/auth/sign-in/email`, `POST /api/auth/two-factor/verify`) at 10 requests/minute/IP. Authenticated `/api/admin/*` GET routes (stats, logs, clients) are NOT rate-limited to allow smooth dashboard navigation.
- **Unsafe Redirect URIs**: Non-http(s) schemes, wildcards, and private-network hostnames (in production) must be rejected before persistence.
- **CORS**: Must only allow the configured `FRONTEND_URL` or an origin registered against a persisted OAuth client. 
- **Ephemeral State TTL**: Rate-limit and origin-cache documents in MongoDB must have TTL indexes set (`expireAfterSeconds`). They must never accumulate indefinitely. MongoDB's native TTL reaper handles expiry; no application-level cleanup code is permitted.

## Anti-Corruption Rules
- **The frontend admin route guard** (`AdminRoute.tsx`) must never be treated as the authorization decision point. It exists for UX (avoiding a flash of admin UI before redirect), not security. Server-side `requireAdmin` is the real gate.
- **No Multi-Tenancy**: SaaS/multi-tenant abstractions must not leak into this codebase. If a future SaaS is built, it is a separate repository consuming this project's OIDC surface as a client, not a fork that bolts tenancy onto this domain model.
- **No App-Specific DB Routing**: One deployment = one MongoDB database. All registered OAuth clients share this database for identity purposes. 
- **No Hand-Rolled Crypto**: No custom symmetric encryption layer over arbitrary database fields. No manual HMAC-SHA1 for TOTP. No custom JWT signing. All crypto is handled by the identity engine.
- **No DB Sync to Clients**: The auth service does not push data to consuming-app databases. Standard OIDC claims via tokens and `/userinfo` are the only mechanism.
- **No Direct `process.env` Reads**: All environment access goes through the composition root (`hono/src/config/index.ts`). Entry points and route handlers use the frozen `config` object.
- **App Admin Provisioning Limit**: When provisioning an admin for a client app, the user is created in the standard `user` collection with `role: "admin"`. Their `adminUserId` and `adminEmail` are saved on the `oauthClient` document for reference. This is a loose coupling, not a separate multi-tenant admin table.

## Data Ownership
- **The Auth Server** owns user/session/OAuth-client metadata — this is the only data model in the system.
- **The Frontend** may cache session state client-side (e.g., Zustand stores for dashboard data) but never computes authorization decisions from it.
- **Admin Stats and Logs** are read views over existing auth data (sessions, users), not a separate source-of-truth system. There is no dedicated audit-log collection.
- **Consuming Applications** own their own user data entirely. The auth service issues identity claims; what the consuming app stores with those claims is the consuming app's decision, in the consuming app's database.

## Deferred / Permanently Out of Boundary
- **Multi-tenancy, billing, self-serve tenant onboarding** — permanently out of boundary.
- **Data sync to consuming-app databases** — permanently out of boundary. Standard OIDC is the mechanism.
- **Cloudflare Workers support** — documented as a known limitation (no MongoDB Node driver support), not solved in this build.
- **Email OTP for admin MFA** — permanently out of boundary. TOTP via authenticator apps replaces it entirely.
- **Hand-rolled symmetric encryption layer** — permanently out of boundary. Hashing and infrastructure-level at-rest encryption are the correct approaches.
- **Framework-specific SDKs** — permanently out of boundary. OIDC conformance is the integration surface; any conformant OIDC client library works.
