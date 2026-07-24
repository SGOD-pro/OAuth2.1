# Design

## Design Principles

- Keep the auth service narrow: it is a passport office, not a product dashboard.
- Favor composition over framework magic. The Hono middleware chain is linear and readable.
- Use existing audited libraries for security primitives: Better Auth, MongoDB TTL, and Hono adapters.

## Domain Model

- `User`: authenticated principal; the `role` field gates admin access.
- `Session`: sign-in state; also the audit source for admin logs.
- `OAuth client`: application registered to use this auth server. `client_secret` is hashed at rest.
- `Admin user`: user with `role === "admin"`. Has a TOTP secret, provisioned via QR and stored encrypted.
- `RateLimitEntry` / `OriginCacheEntry`: ephemeral records stored in MongoDB TTL collections.

## Patterns

- DDD-lite: clear ownership for users, sessions, and OAuth clients.
- Anti-corruption layer: the frontend route guard is UX only. The server re-checks role.
- Composition root: `hono/src/config/index.ts` is the single place env vars are parsed.
- Platform abstraction seam: `hono/src/app.ts` contains all logic. Entry point files contain only adapter wiring.

## API Contracts

- `GET /` - health check.
- `/.well-known/jwks.json` - JWKS public key endpoint.
- `/.well-known/openid-configuration` - OIDC discovery document.
- `/api/auth/*` - delegated to Better Auth for OAuth 2.1/OIDC, email or Google sign-in, and TOTP MFA.
- `POST /api/admin/clients` - create OAuth client. `client_secret` is returned once and hashed at rest.
- `GET /api/admin/clients` - list clients.
- `GET /api/admin/clients/:id` - fetch one client.
- `PATCH /api/admin/clients/:id` - partial update.
- `DELETE /api/admin/clients/:id` - delete.
- `GET /api/admin/stats` - computed directly against MongoDB collections.
- `GET /api/admin/logs` - last 100 sessions, joined against user for email.
- Admin login flow: `POST /api/auth/sign-in/email` -> if 2FA is enabled, `POST /api/auth/two-factor/verify`.

## MongoDB TTL Collection Design

### `rate_limits` collection

- Schema: `{ _id: "RATE#<ip>", count: number, createdAt: Date }`
- Index: `{ createdAt: 1 }`
- Expiration: `expireAfterSeconds: 60`

### `origin_cache` collection

- Schema: `{ _id: "ORIGIN#<origin>", allowed: boolean, cachedAt: Date }`
- Index: `{ cachedAt: 1 }`
- Expiration: `expireAfterSeconds: 300`

## Admin MFA Flow

### Setup

Admin clicks "Enable 2FA". The backend generates a TOTP secret. The frontend renders a QR code. The admin scans it with Google Authenticator or Microsoft Authenticator, then enters a 6-digit code to confirm. Backup codes are shown once.

### Login

Admin enters email and password. If 2FA is enabled, the frontend shows a 6-digit TOTP prompt. The admin enters the code from the authenticator app. Better Auth verifies the code and creates the session.

### Multiple Deployments

Each deployment has its own admin account. The same authenticator app manages all of them, which is standard TOTP behavior.

## Explicitly Rejected in This Design

- Database adapter abstraction.
- Dedicated audit-log collection.
- Email OTP for admin MFA.
- Hand-rolled symmetric encryption layer.
- Per-client DB routing.
- Custom TOTP implementation.
