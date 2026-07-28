
# Project Requirements

## Positioning (read this before anything else)
This is a **pre-written, portfolio-grade, self-hosted OIDC/OAuth 2.1 provider**. It is not a startup, not an open-source community product, and not a SaaS. It exists to be a sharp, defensible engineering artifact for a job search. Scope decisions below are made against a **3-week clock**, not against "what would be ideal."

## Hard Constraints
- Total build time: 3 weeks, part-time. No phase may expand this.
- **Identity Engine**: Better Auth v1.x via npm. Implements OAuth 2.1/OIDC, session management, and TOTP MFA.
- **No database migration**: MongoDB stays. It serves both persistent state and ephemeral state (rate limits, origin cache via TTL collections).
- **Multi-platform deploy**: Must deploy correctly to AWS Lambda, Vercel, Netlify, Railway, Fly, Render, GCP Cloud Run, Azure Container Apps via Hono's per-runtime adapters.
- **Config-only self-hosting**: A stranger can clone the repo, supply env vars (`MONGODB_URI`, `BETTER_AUTH_SECRET`, `FRONTEND_URL`, etc.), run the migration script, and deploy. No code changes required for a standard deployment.
- **Admin security**: Admin endpoints must reject unauthenticated/non-admin callers. Admin login with 2FA enabled must reject requests without a valid TOTP code.
- **Client secrets**: Must be hashed at rest, shown once at issuance, never displayed again.
- **TOTP implementation**: Must use the Better Auth `twoFactor` plugin logic. No custom TOTP code. QR codes must be generated locally in the browser (no external APIs).
- **Rate limiting**: Must target authentication endpoints (`/api/auth/*`) to prevent brute-force attacks, leaving `/api/admin/*` GET routes unrestricted for smooth dashboard navigation.

## Functional Requirements
- Email/password sign-in and sign-up.
- Google OAuth sign-in.
- Full OAuth 2.1 / OIDC provider surface: authorize, token, revoke, introspect, userinfo, dynamic client registration, PKCE, consent, JWKS, end-session.
- JWT access tokens, RS256, served via JWKS. Consuming apps verify tokens using the public key.
- Admin role management (`admin` plugin, role stored on user).
- Admin CRUD for OAuth clients with redirect URI and allowed-origin validation before persistence.
- Admin TOTP MFA: enable via locally-generated QR code, verify at login, backup codes for recovery.
- App Admin Provisioning: Ability to create an admin account tied to a specific OAuth client, saving `adminUserId` and `adminEmail` on the `oauthClient` document.
- Admin stats and logs endpoints (read views over `session` and `user` collections).
- Dynamic CORS cached in MongoDB TTL collection.
- Platform entry point files for each deploy target, each < 20 lines, importing from shared `app.ts`.
- Frontend state management using Zustand with a 30-second TTL cache for admin dashboard data.

## OIDC Consumer-DB Workflow (Standard OIDC, not a custom feature)
- Consuming applications receive identity claims via ID tokens and `/userinfo`.
- Consuming apps store user data in their own databases, keyed on `sub`.
- No data sync, no pipeline, no shared database. The consuming app owns its user data after receiving claims.

## Data Protection Requirements
- Passwords: hashed one-way (bcrypt/argon2).
- Client secrets: hashed verify-only.
- TOTP secrets: encrypted at rest by Better Auth twoFactor plugin logic.
- Data in transit: TLS + HSTS.
- Data at rest: MongoDB Atlas encrypts at rest by default.
- No hand-rolled symmetric encryption layer over arbitrary database fields.

## Explicitly Out of Scope
- Multi-tenant SaaS control plane.
- Database adapter abstraction / multi-DB support.
- Custom-built cryptography, custom-built OIDC implementation, custom-built TOTP.
- Framework-specific SDKs — OIDC is the SDK.
- Email OTP for admin MFA — TOTP replaces it entirely.
- Data sync to consuming-app databases — standard OIDC claims are the mechanism.
- Cloudflare Workers support — documented limitation (no MongoDB driver support).
- Hand-rolled encryption layer — hashing + TLS + infrastructure at-rest encryption is the approach.
- NestJS backend — deleted, not migrated.
- External QR Code APIs — rejected to prevent TOTP secret leakage.

## Acceptance Criteria
- `hono/src/app.ts` is platform-agnostic. Entry point files contain only adapter wiring.
- Rate limiting and CORS caching survive concurrent execution environments via MongoDB TTL collections.
- Admin can enable TOTP 2FA, log in with a 6-digit code from Google Authenticator, and use backup codes.
- App Admin Provisioning successfully creates a user with `role: "admin"` and updates the `oauthClient` document.
- `make-admin.ts` prompts for explicit email confirmation and logs every promotion.
- Client secrets are hashed at rest (not plaintext) in the database.
- A person who is not the author can clone, configure via `.env`, pick a platform, and deploy without reading source code.
- E2E security tests pass: OIDC flow works, invalid redirects/secrets are rejected, MFA blocks OIDC authorization until verified.
- A public writeup exists describing the real bugs found and fixed.
