# Architecture

## System Shape
- Frontend: React 19 + Vite + React Router v7, static build, deployable to S3 + CloudFront or any static host.
- API edge: Hono, deployed as a single AWS Lambda function behind API Gateway (HTTP API) or a Lambda Function URL.
- Identity engine: Better Auth v1.6.x + `@better-auth/oauth-provider`.
- Primary datastore: MongoDB Atlas (unchanged — see ADR in `decision.md` for why this is not being migrated).
- Ephemeral/cross-invocation state (rate limits, CORS origin cache): DynamoDB, on-demand billing, TTL-based expiry.
- Local dev: Docker Compose (API + frontend + optional Nginx).
- Legacy: NestJS backend — **deleted**, not retained, not migrated in parallel.

## Why Each Component Exists
- **Hono**: compiles cleanly to a single Lambda bundle via `hono/aws-lambda`, has no framework runtime
  overhead comparable to NestJS/Express, and keeps middleware (CORS, CSRF, rate limit, headers) explicit
  and readable in one file (`hono/src/app.ts`). This is the correct choice for a Lambda-first target;
  NestJS is not, and running both was the actual bug — not a migration in progress, dead weight.
- **Better Auth + oauth-provider plugin**: implements OAuth 2.1/OIDC (PKCE, consent, token exchange,
  refresh, introspection, revocation, JWKS, dynamic client registration) correctly, without hand-rolling
  cryptography. "Zero dependency" as literally stated in earlier scoping was rejected for exactly this
  reason — see `decision.md`. The real constraint honored here is zero *mandatory operational*
  dependency (no Redis, no message broker), not zero library dependency.
- **MongoDB Atlas**: already the working, tested persistence layer. Kept as-is under the "don't rewrite
  what works, fix the actual bug" principle. The real production risk was never "wrong database" — it was
  unbounded concurrent connections from Lambda, which is solved without touching the DB layer (see below).
- **Lambda reserved concurrency**: caps the maximum number of concurrent execution environments, which
  directly caps the maximum number of concurrent MongoDB connections opened against Atlas. This is a
  platform configuration, not a code change — the cheapest fix that fully addresses the connection-
  exhaustion risk that a Postgres/serverless-driver rewrite would have addressed at 10x the cost.
- **DynamoDB (on-demand)**: the only new component in this architecture, and it exists solely because
  in-memory `Map`/`LRUCache` state (the original rate limiter and origin cache) does not survive across
  Lambda's independent, concurrently-warm execution environments — this was a live correctness bug, not
  a scaling concern for later. DynamoDB's per-request pricing keeps idle cost at effectively zero, and its
  TTL feature replaces the LRU-with-ttl pattern the code already assumed.
- **S3 + CloudFront** (frontend): static hosting, no server to manage, pairs naturally with an API-only Lambda backend.
- **Docker Compose** (local only): lets a self-hoster or contributor run the full stack locally before
  touching AWS — this is what makes the project "config-only to run," not a production deployment target.

## Data Flow
1. Browser reaches the React app (S3/CloudFront or local Vite dev server).
2. Frontend calls `/api/auth/*` and `/api/admin/*` against the Lambda-backed API.
3. Hono middleware chain, in order: dynamic CORS (checked against Mongo-persisted OAuth client origins,
   cached in DynamoDB) → security headers → request logging → (admin routes only) CSRF → rate limit → role check.
4. Better Auth handles authentication, session, OAuth/OIDC, consent, and token operations against MongoDB.
5. Admin mutations (client create/update/delete) write to MongoDB, then invalidate the relevant DynamoDB
   cache entries so CORS decisions reflect the change on the **next** request, regardless of which Lambda
   execution environment serves it — closing the cross-container staleness gap in the original design.

## Runtime Boundaries
- Frontend must not query MongoDB or DynamoDB directly.
- Admin authorization is enforced at the API boundary (Hono middleware), never only in the frontend route guard.
- CORS allowlists are derived from persisted OAuth client data, never hardcoded.
- The Lambda bundle must stay a single artifact, built via `hono/aws-lambda`, with no Lambda@Edge code
  path — Lambda@Edge cannot read environment variables at all, which is incompatible with this project's
  fully env-driven config model (see `decision.md`).

## Current Known Risks (carried forward honestly, not hidden)
- MongoDB Atlas connection limits are managed by reserved concurrency, not eliminated. A self-hoster on a
  low Atlas tier who sets concurrency too high can still exhaust connections — this must be documented in
  the setup guide, not silently assumed away.
- DynamoDB introduces AWS-specific coupling. A self-hoster deploying to a non-AWS target (Cloudflare
  Workers, Fly.io, etc.) does not get this fix for free — out of scope for this build, documented as a
  known limitation, not solved speculatively.