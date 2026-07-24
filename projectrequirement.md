# Project Requirements

## Positioning

This is a portfolio-grade, self-hosted OIDC/OAuth 2.1 provider, not a startup. Scope decisions are made against a 3-week clock.

## Hard Constraints

- Total build time: 3 weeks, part-time.
- No database migration. MongoDB stays.
- Must deploy correctly to AWS Lambda, Vercel, Netlify, Railway, Fly, Render, GCP, and Azure via Hono adapters.
- Must run near-zero-cost at idle on serverless targets.
- Must remain config-only to stand up, with no code changes for standard deployment.
- Admin endpoints must reject unauthenticated or non-admin callers.
- Admin login with 2FA enabled must reject requests without a valid TOTP code.
- Client secrets must be hashed at rest and shown once at issuance.
- TOTP implementation must use Better Auth's `twoFactor` plugin, with no custom TOTP code.

## Functional Requirements

- Email/password sign-in and sign-up.
- Google OAuth sign-in.
- Full OAuth 2.1 / OIDC provider surface: authorize, token, revoke, PKCE, consent, JWKS, and so on.
- JWT access tokens, RS256, served via JWKS.
- Admin CRUD for OAuth clients with URI validation.
- Admin TOTP MFA: enable via QR code, verify at login, and use backup codes for recovery. Uses Better Auth `twoFactor` plugin and is compatible with Google or Microsoft Authenticator.
- Admin stats and logs endpoints.
- Dynamic CORS cached in MongoDB TTL collection.
- Rate limiting enforced via MongoDB TTL collection.
- Platform entry point files for each deploy target.

## OIDC Consumer-DB Workflow

- Consuming applications receive identity claims via ID tokens and `/userinfo`.
- Consuming apps store user data in their own databases, keyed on `sub`.
- No data sync, no pipeline, no shared database.

## Data Protection Requirements

- Passwords: hashed one-way with bcrypt or argon2.
- Client secrets: hashed for verification only.
- TOTP secrets: encrypted at rest by the Better Auth plugin.
- Data in transit: TLS and HSTS.
- Data at rest: MongoDB Atlas encrypts at rest by default.
- No hand-rolled symmetric encryption layer.

## Explicitly Out of Scope

- Multi-tenant SaaS control plane.
- Database adapter abstraction or multi-DB support.
- Custom-built cryptography or TOTP.
- Framework-specific SDKs.
- Email OTP for admin MFA.
- Data sync to consuming-app databases.
- Cloudflare Workers support, because it is a documented limitation.
- NestJS backend.

## Acceptance Criteria

- `hono/src/app.ts` is platform-agnostic. Entry point files contain only adapter wiring.
- Rate limiting and CORS caching survive concurrent execution via MongoDB TTL collections.
- Admin can enable TOTP 2FA, log in with a 6-digit code from Google Authenticator, and use backup codes.
- `make-admin.ts` prompts for explicit email confirmation and logs every promotion.
- Client secrets are hashed at rest, not plaintext.
- A person who is not the author can clone, configure via `.env`, and deploy without reading source code.
- A public writeup exists describing the real bugs found and fixed.
