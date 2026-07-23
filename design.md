# Design

## Design Principles
- Keep the auth service narrow: it is a passport office, not a product dashboard.
- Explicit boundaries between browser UI, public auth routes, and privileged admin routes.
- Composition over framework magic — Hono middleware chain is linear and readable, not a hidden DI graph.
- Security controls sit close to the transport boundary (CORS, CSRF, headers, rate limit all live in
  `hono/src/middleware/*` and are wired explicitly in `hono/src/app.ts`, not scattered per-route).
- Fix the smallest correct thing. No abstraction is added that wasn't required to close a real gap
  (see `decision.md` for the explicit rejection of a DB adapter abstraction layer in this build).

## Domain Model
- **User**: authenticated principal, Better Auth `user` collection, `role` field gates admin access.
- **Session**: sign-in state, also doubles as the audit source for the admin logs endpoint (no separate
  audit collection exists — this is a documented simplification, not an oversight; see `decision.md`).
- **OAuth client**: an application registered to use this auth server. Owns `redirectUris` and derived
  `allowedOrigins`, validated before persistence.
- **Admin user**: a `User` with `role === "admin"`. No separate admin entity.
- **RateLimitEntry / OriginCacheEntry**: new for this build. Live in DynamoDB, not in the domain layer —
  these are infrastructure concerns (cross-invocation state), not business entities, and must not leak
  into route handlers as anything other than a middleware concern.

## Patterns
- **DDD-lite**: users, sessions, and OAuth clients are modeled as separate concerns with clear ownership;
  no shared "everything" collection.
- **SOLID, pragmatically**: API handlers in `hono/src/routes/*` do one thing — parse/validate the request,
  delegate to Better Auth's `authProvider.api.*` or a direct Mongo query, return a response. They do not
  contain business rules Better Auth already owns (token issuance, session validation).
- **Anti-corruption layer**: the frontend route guard (`AdminRoute.tsx`) is UX only. It never becomes the
  authorization decision — every admin route re-checks role server-side via `requireAdmin` middleware,
  independent of what the frontend believes.
- **Composition root**: `hono/src/config/index.ts` is the single place environment variables are parsed
  (via `envSchema`, zod) and frozen into a typed `config` object. No other file reads `process.env` directly.

## API Contracts
- `GET /` — health check, returns `{ message, status }`.
- `/api/auth/*` — delegated entirely to Better Auth's handler (`authProvider.handler`). Not reimplemented.
- `POST /api/admin/clients` — create OAuth client. Body: `client_name`, `redirect_uris[]`,
  `allowed_origins[]`, `skip_consent`, `enable_end_session`. Validates every URI via `validateRedirectUri`
  before calling Better Auth. Invalidates the DynamoDB origin cache on success.
- `GET /api/admin/clients` — list all registered OAuth clients.
- `GET /api/admin/clients/:id` — fetch one client.
- `PATCH /api/admin/clients/:id` — partial update, same URI validation as create, same cache invalidation.
- `DELETE /api/admin/clients/:id` — delete, same cache invalidation.
- `GET /api/admin/stats` — `{ totalUsers, totalClients, activeClients, recentLogins }`, computed directly
  against MongoDB (`user`, `oauthClient`, `session` collections). `recentLogins` = sessions created in the
  last 24h, used as a proxy for sign-in events — there is no dedicated login-event log.
- `GET /api/admin/logs` — last 100 sessions, newest first, joined against `user` for email, shaped as
  `{ userId, userEmail, action: "sign_in", ipAddress, createdAt }`.

## New in this build: DynamoDB access pattern
- Table: single table, on-demand billing, TTL attribute enabled.
- Rate limit key: `RATE#<ip>` → `{ count, resetAt }`, TTL = `resetAt`.
- Origin cache key: `ORIGIN#<origin>` → `{ allowed: boolean }`, TTL = 5 minutes from write, matching the
  previous LRU TTL behavior.
- Cache invalidation on admin mutation: delete the specific `ORIGIN#*` items belonging to the mutated
  client's known origins if determinable, otherwise a bounded scan-and-delete by prefix is acceptable
  given expected table size (self-hosted, single-tenant, not a shared multi-tenant table) — full
  wholesale invalidation is an acceptable tradeoff here, not a hidden performance bug, because table size
  per deployment is small by construction.

## Explicitly rejected in this design
- A `DatabaseAdapter` abstraction to support Postgres/MySQL alongside Mongo — not needed, Mongo already
  works, and Better Auth's own adapter interface already provides this seam if a self-hoster wants to swap
  it later. Building an in-house abstraction on top of an abstraction that already exists is waste.
- A dedicated audit-log collection — the sessions-as-proxy approach already meets the stated requirement
  ("recent sign-in activity"); building a separate event-sourcing system for this is scope creep against
  the 3-week constraint.