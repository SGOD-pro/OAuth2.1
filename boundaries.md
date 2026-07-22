# Boundaries

## External Boundaries
- Browser clients may only interact with the frontend and the public API.
- OAuth client applications may only use the documented auth endpoints.
- Admin operations are restricted to authenticated users with the admin role.

## Service Boundaries
- Frontend owns presentation and route orchestration only.
- Hono owns HTTP policy, auth delegation, and admin APIs.
- Better Auth owns identity, sessions, consent, and token mechanics.
- MongoDB owns persistent identity and client state.

## Service Limits
- Admin endpoints must reject requests without a valid session.
- Non-admin sessions must receive `403` on privileged routes.
- Unsafe redirect URIs must be rejected before persistence.
- CORS must only allow the configured frontend origin or an origin registered by an OAuth client.
- Rate limits on auth and admin surfaces must stay conservative.

## Anti-Corruption Rules
- Do not let UI route guards become the authorization decision point.
- Do not let SaaS abstractions leak into the current auth-only core.
- Do not let the legacy NestJS implementation dictate new Hono API contracts.
- Do not hardcode tenant, billing, or pricing assumptions into auth primitives.

## Data Ownership
- The auth service owns user/session/client metadata.
- The frontend may cache session state, but not authoritatively compute authorization.
- Admin stats and logs are read views over auth data, not separate source-of-truth systems.

## Deferred Boundary Expansion
- Multi-tenancy is not part of the current boundary.
- Billing and pricing are not part of the current boundary.
- Tenant-scoped audit logging is not part of the current boundary.