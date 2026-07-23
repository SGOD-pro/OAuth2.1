# Boundaries

## External Boundaries
- Browser clients may only interact with the frontend and the public API (`/api/auth/*`, `/api/admin/*`).
- OAuth client applications may only use the documented OIDC endpoints under `/api/auth/oauth2/*`.
- Admin operations are restricted to authenticated users with `role === "admin"`, enforced server-side.
- Self-hosters interact with the system only through environment variables and the admin UI/API — never
  through direct source edits for standard configuration. If a standard deployment requires editing
  application code, that is a scope failure against `projectrequirement.md`.

## Service Boundaries
- Frontend owns presentation and route orchestration only. Never queries Mongo/DynamoDB directly.
- Hono owns HTTP policy: CORS, security headers, CSRF, rate limiting, admin role gating, request logging.
- Better Auth owns identity: sessions, OAuth/OIDC mechanics, consent, JWT/JWKS issuance.
- MongoDB owns persistent identity state: users, sessions, OAuth clients.
- DynamoDB owns ephemeral cross-invocation state only: rate-limit counters, origin-allow cache. It must
  never become a second source of truth for anything MongoDB already owns.

## Service Limits
- Admin endpoints must reject requests without a valid session (`401`).
- Non-admin sessions must receive `403` on privileged routes.
- Unsafe redirect URIs (non-http(s) scheme, wildcard, private-network host in production) must be
  rejected before persistence.
- CORS must only allow the configured frontend origin or an origin registered against a persisted OAuth client.
- Admin rate limit: 30 requests/minute/IP, enforced correctly across concurrent Lambda execution
  environments via DynamoDB — an in-memory-only limiter does not satisfy this boundary, full stop.
- Lambda reserved concurrency must be set at deploy time to a value the target MongoDB Atlas tier's
  connection limit can sustain. This is a deployment-time boundary, documented in the setup guide, not
  enforced in code — self-hosters own their own Atlas tier choice.

## Anti-Corruption Rules
- The frontend admin route guard (`AdminRoute.tsx`) must never be treated as the authorization decision
  point. It exists for UX (avoiding a flash of admin UI before redirect), not security.
- SaaS/multi-tenant abstractions must not leak into this codebase. If a future SaaS is built, it is a
  separate repository consuming this project's OIDC surface as a client, not a fork that bolts tenancy
  onto this domain model.
- The deleted NestJS implementation must not be resurrected "for reference" inside this repo. If historical
  reference is needed, it lives in git history, not as dead code in the working tree.
- DynamoDB access must stay inside the rate-limit and CORS-cache middleware. Route handlers must not read
  or write DynamoDB directly — if a route needs cross-invocation state beyond these two cases, that is a
  signal to stop and re-scope, not to add a third ad-hoc table.

## Data Ownership
- The auth service owns user/session/OAuth-client metadata — full stop, this is the only data model in
  the system.
- The frontend may cache session state client-side but never computes authorization decisions from it.
- Admin stats and logs are read views over existing auth data (sessions, users), not a separate
  source-of-truth system — see `design.md` for the explicit rejection of a dedicated audit log.

## Deferred / Permanently Out of Boundary
- Multi-tenancy — not deferred-to-later, rejected for this project. See `project.md` non-goals.
- Billing and pricing — not applicable, this project has no monetization surface by design.
- Tenant-scoped audit logging — not applicable, there are no tenants.
- Any framework-specific SDK — OIDC conformance is the integration surface; framework SDKs are explicitly
  not built (`projectrequirement.md`).