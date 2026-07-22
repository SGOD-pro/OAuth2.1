# Architecture

## System Shape
- Frontend: React 19 + Vite + React Router v7.
- API edge: Hono.
- Legacy backend: NestJS remains in the repository as the earlier implementation and adapter surface.
- Identity provider: Better Auth v1.6.10.
- Database: MongoDB Atlas for the current implementation.
- Deployment target: AWS Lambda for the Hono API, S3 + CloudFront for the frontend.
- Local composition: Docker Compose with API, frontend, and Nginx.

## Why Each Component Exists
- React/Vite is used because the UI is route-heavy, interactive, and already organized around lazy-loaded pages.
- Hono is used for the new API boundary because it compiles cleanly to Lambda, keeps middleware explicit, and fits the smaller auth service surface.
- Better Auth is the auth engine because it already owns the OAuth/OIDC lifecycle, session handling, and admin primitives.
- MongoDB is used because the current data model and Better Auth adapter are already built around it.
- Nginx is retained for local and transitional deployment because it can proxy API and frontend traffic and terminate TLS in one place.

## Data Flow
1. The browser reaches the React app.
2. The frontend talks to the API through `/api/auth` and `/api/admin`.
3. Hono enforces CORS, security headers, request logging, CSRF for admin mutations, and role checks.
4. Better Auth performs authentication, session, OAuth, consent, and token operations.
5. MongoDB stores users, sessions, OAuth clients, and related auth state.
6. Admin mutations invalidate the origin cache so CORS decisions reflect the latest client registry.

## Runtime Boundaries
- Frontend code must not directly query the database.
- Admin authorization must be enforced at the API boundary, not only in the UI.
- CORS allowlists must be derived from persisted OAuth client data rather than hardcoded frontend assumptions.
- The Lambda bundle must stay small and deterministic.

## Current Risks
- The repository still contains a NestJS backend, so the migration boundary must remain clear.
- Token behavior depends on Better Auth plugin limitations, so opaque-token and introspection handling remain relevant.
- The current deployment story is split between local Docker and AWS-targeted Lambda delivery.