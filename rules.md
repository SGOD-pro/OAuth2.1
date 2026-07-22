# Rules

## Engineering Rules
- Keep changes minimal and scoped to one boundary at a time.
- Prefer existing primitives before introducing new abstractions.
- Preserve current auth flows unless a breaking change is explicitly planned and verified.
- Treat security regressions as blockers.
- Do not add SaaS features until the deployment and security baseline is proven.

## Coding Standards
- TypeScript throughout.
- Prefer explicit types at module boundaries.
- Keep route handlers small and delegating.
- Avoid hidden framework state when a plain function or module export will do.
- Keep logging structured enough to debug auth flows and admin mutations.

## Security Rules
- Validate env vars at startup.
- Apply security headers in the API edge.
- Validate redirect URIs before write operations.
- Enforce CSRF for admin mutations.
- Check the admin role server-side before privileged access.

## Linting and CI Expectations
- Frontend must pass ESLint.
- Backend and Hono TypeScript must stay buildable.
- Tests must cover critical auth and admin paths.
- Production deploy artifacts should be reproducible from source.

## Operational Rules
- Cache invalidation must be part of any OAuth client mutation path.
- Production secrets must never be committed.
- Local Docker Compose must stay usable for development and verification.