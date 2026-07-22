# Project Requirements

## Hard Constraints
- The service must preserve OAuth 2.1 and OIDC flows for sign-in, consent, authorization code exchange, token issuance, revocation, introspection, and userinfo.
- The system must support Better Auth with Google OAuth, email/password auth, admin role management, and JWT access tokens signed with RS256/JWKS.
- The platform must keep frontend and API origins aligned through dynamic CORS derived from stored OAuth client origins.
- Admin operations must remain role-gated and CSRF-protected.
- The deployment target is AWS Lambda for the API, with S3 + CloudFront for the frontend, and Nginx only as a local or transitional edge layer.
- SaaS conversion work is deferred until the deployment and security baseline is verified.

## Functional Requirements
- Users must be able to sign in with email/password.
- Users must be able to sign in with Google.
- OAuth clients must be creatable, readable, updateable, and deletable from the admin surface.
- OAuth redirect URIs and allowed origins must be validated before persistence.
- Admin dashboards must expose service stats and sign-in logs.
- Auth flows must support consent and callback pages in the frontend.
- The Hono service must expose the API routes for auth and admin functions.

## Non-Functional Requirements
- Secrets must come from environment variables and be validated at startup.
- Security headers must be applied consistently.
- Request logging must remain available for operational tracing.
- CORS decisions must be cacheable and invalidatable when OAuth clients change.
- The codebase must remain maintainable under a staged migration from NestJS to Hono.

## Explicitly Deferred
- Multi-tenant SaaS support.
- Self-serve tenant registration.
- Billing integration.
- MAU pricing enforcement.
- Tenant-level audit logging beyond the current admin/session log surfaces.

## Acceptance Criteria
- Core auth routes work end to end in local and production-like environments.
- Admin routes reject unauthenticated and non-admin callers.
- Deployable artifacts can be built for the Lambda frontend/backend target.
- No SaaS-specific abstraction is introduced before the baseline deployment path is stable.