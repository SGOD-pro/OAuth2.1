# Session Memory

## Current State
- The repo contains a mixed migration state: NestJS legacy backend, Hono target API, and a React/Vite frontend.
- The current priority is deployment and security hardening before any SaaS expansion.
- Better Auth is the auth engine; the OAuth Provider plugin currently requires introspection-based handling for opaque provider tokens.

## Stable Facts To Carry Forward
- Admin access is server-side role gated.
- CORS is dynamic and tied to persisted OAuth client origins.
- CSRF protection applies to admin mutations.
- The production target is AWS Lambda for the API and S3 + CloudFront for the frontend.

## Deferred Topics
- Multi-tenant architecture.
- Billing integration.
- Self-serve tenant registration.
- MAU pricing enforcement.
- Tenant-scoped audit logging.

## Working Rules For Future Sessions
- Start from the nearest concrete file or runtime behavior.
- Prefer small verified changes over broad refactors.
- Keep documentation aligned to the code that actually ships.
- Do not widen the SaaS design before deployment verification is complete.