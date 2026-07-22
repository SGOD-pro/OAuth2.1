# Implementation Phases

## Phase 0: Verify the current baseline
- Confirm the Hono app boots locally.
- Confirm auth routes resolve correctly.
- Confirm admin login and role checks work.
- Confirm dynamic CORS works from persisted client origins.
- Verify the existing security headers and CSRF behavior.

## Phase 1: Complete Hono migration
- Move all active API behavior to Hono.
- Remove remaining dependency on NestJS for the runtime path.
- Keep the public auth and admin contracts stable.
- Verify parity with the legacy implementation where needed.

## Phase 2: Production deployment hardening
- Prepare AWS Lambda packaging for the API.
- Prepare S3 + CloudFront delivery for the frontend.
- Confirm environment validation and secret wiring.
- Confirm health checks and observability paths.

## Phase 3: Security closure
- Close the remaining security findings.
- Re-test redirect validation and origin restrictions.
- Re-check admin CSRF and role enforcement.
- Validate token handling behavior, including the Better Auth provider limitation workarounds.

## Phase 4: Cost-optimized infrastructure
- Evaluate lower-cost primitives where they do not reduce correctness.
- Only replace infrastructure after deployment stability is proven.
- Prefer incremental substitution over a full rewrite.

## Phase 5: SaaS layer buildout
- Add multi-tenancy.
- Add self-serve registration.
- Add billing.
- Add tenant-aware audit logging.
- Start MAU-based pricing enforcement only after the foundation is stable.

## Phase Gate Rule
- A phase may not begin until the previous one is verified.
- Verification must be based on a concrete test, build, deployment check, or security review result.