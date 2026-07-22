# Design

## Design Principles
- Keep the auth service narrow: it is a passport office, not a product dashboard.
- Use explicit boundaries between browser UI, public auth routes, and privileged admin routes.
- Prefer composition over framework magic.
- Keep security controls close to the transport boundary.

## Domain Model
- User: authenticated principal.
- Session: sign-in state and audit source.
- OAuth client: an application registered to use the auth server.
- Admin user: a user with elevated privileges to manage OAuth clients and inspect service data.

## Patterns
- DDD: The auth system is modeled around users, sessions, and OAuth clients as separate concerns.
- SOLID: API handlers should have one responsibility and should delegate persistence and policy checks.
- Anti-corruption layer: frontend route guards and admin UI are not the source of truth for authorization.
- Composition root: configuration is built in dedicated modules and wired into the app entry points.

## API Contracts
- `GET /` returns a health response from Hono.
- `/api/auth/*` is delegated to Better Auth.
- `/api/admin/clients` supports list/create operations.
- `/api/admin/clients/:id` supports read/update/delete operations.
- `/api/admin/stats` returns service counters.
- `/api/admin/logs` returns recent sign-in activity.

## UI Contracts
- `/auth` is the main sign-in surface.
- `/consent` handles OAuth consent.
- `/callback` completes auth redirects.
- `/admin/login` is the admin entry point.
- `/admin`, `/admin/clients`, and `/admin/logs` require an admin session.

## Design Constraints
- Redirect URI validation must reject unsafe or private-network targets in production.
- CORS cache invalidation must happen on client mutation.
- CSRF protection must remain on admin routes that mutate server state.
- Role checks must happen before admin handlers execute.