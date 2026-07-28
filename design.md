# Design

## Design Principles
- Keep the auth service narrow: it is a passport office, not a product dashboard.
- Composition over framework magic — Hono middleware chain is linear and readable.
- Use existing audited libraries for security primitives. Identity Engine: Better Auth v1.x via npm. Implements OAuth 2.1/OIDC, session management, and TOTP MFA.
- Fix the smallest correct thing. No abstraction added that wasn't required to close a real gap.

## Domain Model
- **User**: authenticated principal, `user` collection, `role` field gates admin access.
- **Session**: sign-in state, `session` collection, doubles as the audit source for admin logs (no separate audit collection).
- **OAuth client**: `oauthClient` collection. Owns `redirectUris`, `allowedOrigins`, and hashed `clientSecret`. Schema is extended to include `adminUserId` and `adminEmail` for App Admin Provisioning.
- **Admin user**: a `User` with `role === "admin"`. Has a TOTP secret (provisioned via QR, stored encrypted).
- **RateLimitEntry**: ephemeral, `rate_limits` collection with TTL index. Infrastructure concern, not a business entity.
- **OriginCacheEntry**: ephemeral, `origin_cache` collection with TTL index. Middleware concern only.

## Patterns
- **DDD-lite**: users, sessions, and OAuth clients are separate concerns with clear ownership.
- **SOLID, pragmatically**: API handlers do one thing — parse/validate, delegate to the Better Auth identity engine or a direct Mongo query, return. No business rules the engine already owns.
- **Anti-corruption layer**: frontend route guard is UX only. Every admin route re-checks role server-side via `requireAdmin` middleware.
- **Composition root**: `hono/src/config/index.ts` is the single place env vars are parsed (via `envSchema`, zod) and frozen into a typed `config` object. No other file reads `process.env`.
- **Platform abstraction seam**: `hono/src/app.ts` contains all middleware, routes, and logic. Entry point files contain only adapter wiring. This is the only seam needed for multi-platform deploy.

## API Contracts
- `GET /` — health check, returns `{ message, status }`.
- `/.well-known/jwks.json` — JWKS public key endpoint. Consuming apps use this to verify JWTs.
- `/.well-known/openid-configuration` — OIDC discovery document.
- `/api/auth/*` — delegated entirely to the Better Auth identity engine. Includes:
  - OAuth 2.1/OIDC: authorize, token, revoke, introspect, userinfo, dynamic client registration, PKCE, consent, JWKS.
  - Email/password sign-in/sign-up, Google OAuth.
  - TOTP MFA: generate (QR), verify, disable, backup codes.
- `POST /api/admin/users` — Provision App Admin. Body: `{ email, password, name, clientId }`. Creates user with `role: "admin"`, updates `oauthClient` doc with `adminUserId`/`adminEmail`.
- `POST /api/admin/clients` — create OAuth client. `client_secret` returned once, hashed at rest.
- `GET /api/admin/clients` — list clients.
- `GET /api/admin/clients/:id` — fetch one client.
- `PATCH /api/admin/clients/:id` — partial update, URI validation, cache invalidation.
- `DELETE /api/admin/clients/:id` — delete, cache invalidation.
- `GET /api/admin/stats` — `{ totalUsers, totalClients, activeClients, recentLogins }`.
- `GET /api/admin/logs` — last 100 sessions, joined against `user` for email.
- Admin login flow: `POST /api/auth/sign-in/email` → if 2FA enabled, frontend intercepts `twoFactorRedirect` → `POST /api/auth/two-factor/verify` with TOTP code → session created.

## MongoDB TTL Collection Design (Replaces DynamoDB)
### rate_limits collection
Schema: `{ _id: "RATE#<ip>", count: number, createdAt: Date }`
Index: `{ createdAt: 1 }, expireAfterSeconds: 60` (1-minute window)
Logic:
1. `findOneAndUpdate({ _id: "RATE#<ip>" }, { $inc: { count: 1 }, $setOnInsert: { createdAt: new Date() } }, { upsert: true, returnDocument: 'after' })`
2. If `count > limit`, reject with 429.
3. MongoDB's TTL reaper automatically deletes documents 60 seconds after `createdAt`.

### origin_cache collection
Schema: `{ _id: "ORIGIN#<origin>", allowed: boolean, cachedAt: Date }`
Index: `{ cachedAt: 1 }, expireAfterSeconds: 300` (5-minute TTL)
Logic:
1. `findOne({ _id: "ORIGIN#<origin>" })` — if found, return `allowed`.
2. If not found, query `oauthClient` collection for matching origin.
3. `updateOne({ _id: "ORIGIN#<origin>" }, { $set: { allowed, cachedAt: new Date() } }, { upsert: true })`
4. On admin mutation (client create/update/delete): `deleteMany({})` or targeted deletion. Full invalidation is acceptable given small table size per deployment.

## OIDC Consumer-DB Workflow (Documented, not built)
Standard OIDC flow — no code to write, no sync service:
1. Consuming app redirects user to `/api/auth/oauth2/authorize?client_id=...&redirect_uri=...&...`
2. User authenticates on the auth service login page.
3. Auth service redirects back with authorization code.
4. Consuming app exchanges code for tokens at `/api/auth/oauth2/token`.
5. Consuming app decodes ID token (JWT) → reads `sub`, `email`, `role` claims.
6. Consuming app creates/updates a local user row in ITS OWN database, keyed on `sub`.
7. For subsequent requests, consuming app verifies JWTs using the public key at `/.well-known/jwks.json`.

## Centralized MFA Flow (TOTP via Better Auth Plugin)
- **Setup** (admin or user enables 2FA):
  1. User navigates to "Security" page and clicks "Enable 2FA".
  2. Better Auth engine generates a TOTP secret and returns a `totpURI`.
  3. Frontend renders QR code *locally* (using `qrcode.react`) — no external API calls.
  4. User scans with Google/Microsoft Authenticator.
  5. User enters a 6-digit code to confirm setup.
  6. Better Auth engine verifies code, encrypts secret with `BETTER_AUTH_SECRET`, saves to user document, generates backup codes.
  7. Backup codes shown once — user saves them.
- **Login** (user with 2FA enabled):
  1. User enters email + password → engine validates credentials.
  2. If valid and 2FA enabled → API returns `twoFactorRedirect: true`. No session granted.
  3. Frontend shows 6-digit TOTP prompt.
  4. User enters code → `POST /api/auth/two-factor/verify`.
  5. Success → session created. Backup code fallback supported.
- **Client App Inheritance**: Because OIDC login happens on the Auth Server, this MFA challenge automatically protects any registered client app the user is trying to log into.

## App Admin Provisioning Flow
- **Goal**: Allow the Auth Server admin to create an admin account specifically for a registered client app.
- **Flow**:
  1. Admin clicks "Provision App Admin" on the Client Detail page.
  2. Admin enters Name, Email, Password.
  3. Frontend calls `POST /api/admin/users` with `clientId`.
  4. Backend uses Better Auth engine `signUpEmail` to create user.
  5. Backend updates user document: `role: "admin"`.
  6. Backend updates `oauthClient` document: sets `adminUserId` and `adminEmail`.
  7. UI updates optimistically via Zustand store.
- **Usage**: The provisioned admin logs into the client app via OIDC. The client app receives a JWT containing `role: "admin"`, which the client app uses to grant admin panel access.

## Explicitly rejected in this design
- **Database adapter abstraction** — Better Auth engine provides this seam.
- **Dedicated audit-log collection** — sessions-as-proxy meets the requirement.
- **Email OTP for MFA** — TOTP is simpler, needs no mailer.
- **Hand-rolled symmetric encryption layer** — key-management complexity with no payoff.
- **Per-client DB routing** — rejected. One deployment = one MongoDB, shared by all OAuth clients.
- **Custom TOTP implementation** — Better Auth plugin handles it. No self-authored HMAC-SHA1.
- **External QR Code APIs** — rejected. QR codes must be generated locally in the browser to prevent secret leakage.
