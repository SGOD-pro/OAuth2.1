# Boundaries

## External Boundaries

- Browser clients may only interact with the frontend and the public API (`/api/auth/*`, `/api/admin/*`).
- Consuming applications store user data in their own databases, keyed on the `sub` claim. The auth service does not sync data; standard OIDC token and userinfo claims are the entire mechanism.
- Admin operations are restricted to authenticated users with `role === "admin"`, enforced server-side.
- Admin login requires a valid TOTP code when 2FA is enabled, in addition to username and password.

## Service Boundaries

- Frontend owns presentation and route orchestration only.
- Hono owns HTTP policy: CORS, security headers, CSRF, rate limiting, admin role gating, and the TOTP gate.
- Better Auth owns identity: sessions, OAuth/OIDC, JWT/JWKS issuance, and TOTP MFA.
- MongoDB owns all state, persistent and ephemeral, via TTL collections. There is no second database.
- Platform entry point files own only adapter wiring.

## Service Limits

- Admin endpoints must reject requests without a valid session (`401`).
- Admin login with 2FA enabled must reject requests without a valid TOTP code (`401`).
- Unsafe redirect URIs must be rejected before persistence.
- Admin rate limit: 30 requests per minute per IP, enforced via MongoDB TTL collections.
- Rate-limit and origin-cache documents must have TTL indexes set.

## Anti-Corruption Rules

- The frontend admin route guard is UX only. Server `requireAdmin` is the real gate.
- SaaS and multi-tenant abstractions must not leak into this codebase.
- MongoDB TTL collection access must stay inside rate-limit and CORS-cache middleware.
- No hand-rolled symmetric encryption layer over arbitrary database fields.
- TOTP implementation must use Better Auth's `twoFactor` plugin exclusively. No custom TOTP code.

## Data Ownership

- The auth service owns user, session, and OAuth-client metadata.
- Admin stats and logs are read views over existing auth data.
- Consuming applications own their own user data entirely.

## Deferred or Permanently Out of Boundary

- Multi-tenancy, billing, and data sync to consuming-app databases.
- Framework-specific SDKs, because OIDC conformance is the integration surface.
- Cloudflare Workers support, because it is a documented limitation.
- Email OTP for admin MFA, because TOTP replaces it entirely.
