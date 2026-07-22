# Decision Records

## ADR 001: Use Better Auth as the identity core
- Status: Accepted
- Decision: Better Auth owns authentication, sessions, OAuth flows, and JWT issuance.
- Rationale: It reduces custom auth surface area and already supports the required flows.
- Consequences: Custom auth code must remain as thin adapters and policy checks around Better Auth.

## ADR 002: Migrate the API boundary to Hono
- Status: Accepted in progress
- Decision: Hono becomes the API edge for the auth service.
- Rationale: Hono is Lambda-friendly and keeps request handling explicit.
- Consequences: NestJS remains in the repo during transition, but new API work should target Hono.

## ADR 003: Keep MongoDB for the current implementation
- Status: Accepted for the current phase
- Decision: MongoDB remains the persistence layer until the baseline deployment is verified.
- Rationale: The current adapter and data model are already implemented on MongoDB.
- Consequences: Migration to DynamoDB is a future cost-optimization decision, not a prerequisite.

## ADR 004: Use dynamic CORS from stored OAuth client origins
- Status: Accepted
- Decision: Allow origins are derived from persisted OAuth client data with caching.
- Rationale: The registered client registry is the source of truth for allowed origins.
- Consequences: Admin client mutations must invalidate the origin cache.

## ADR 005: Enforce admin access server-side
- Status: Accepted
- Decision: Admin UI route guards are only UX; the API must enforce admin role checks.
- Rationale: Client-side checks are insufficient for security.
- Consequences: Admin handlers must require a validated session and role.

## ADR 006: Defer SaaS buildout
- Status: Accepted
- Decision: Multi-tenancy, billing, and self-serve registration are postponed.
- Rationale: The deployment/security foundation is not yet finished.
- Consequences: No SaaS-specific data model or pricing logic should be added yet.

## ADR 007: Prefer Lambda plus static hosting for production
- Status: Accepted
- Decision: Deploy the API on AWS Lambda and the frontend on S3 + CloudFront.
- Rationale: The target stack minimizes idle cost and fits the service shape.
- Consequences: Code and build artifacts must remain compatible with serverless deployment.