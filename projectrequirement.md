# Project Requirements

## Positioning (read this before anything else)
This is a **portfolio-grade, self-hosted OIDC/OAuth 2.1 provider**, not a startup, not an open-source
community product, not a SaaS. It exists to be a sharp, defensible engineering artifact for a job search.
Scope decisions below are made against a **3-week clock**, not against "what would be ideal."

## Hard Constraints
- Total build time: 3 weeks, part-time, around thesis and job applications. No phase may expand this.
- No database migration. MongoDB stays. Rewriting persistence is out of scope — it is not a bug fix, it
  is unnecessary risk against the clock.
- No new mandatory runtime dependency (no Redis, no separate queue service, no second deployable). Every
  new piece of state must live in a managed AWS primitive already reachable from Lambda (DynamoDB).
- Must deploy correctly to real AWS Lambda (not Lambda@Edge) behind an HTTP API Gateway or Function URL.
- Must run near-zero-cost at idle (pay-per-request billing everywhere: Lambda, DynamoDB).
- Must remain config-only to stand up: a stranger clones the repo, supplies env vars (Mongo URI, Google
  OAuth credentials, Better Auth secret, frontend URL), deploys, and has a working OIDC provider. No
  code changes required for a standard deployment.
- Admin endpoints must reject unauthenticated and non-admin callers. Non-negotiable, not time-boxed away.
- CSRF protection must remain on all admin mutation routes.
- Redirect URI validation must reject unsafe/private-network targets in production.

## Functional Requirements
- Email/password sign-in and sign-up.
- Google OAuth sign-in.
- Full OAuth 2.1 / OIDC provider surface: authorize, token, revoke, introspect, userinfo, dynamic client
  registration, PKCE, consent.
- JWT access tokens, RS256, served via JWKS.
- Admin role management (`admin` plugin, role stored on user).
- Admin CRUD for OAuth clients (create/list/get/update/delete), with redirect URI and allowed-origin
  validation before persistence.
- Admin stats endpoint (user count, client count, active client count, logins in last 24h).
- Admin logs endpoint (recent sign-in activity, derived from sessions — no dedicated audit collection).
- Dynamic CORS: origins allowed only if registered against a persisted OAuth client, plus the configured
  frontend origin.
- Frontend: sign-in, sign-up, forgot/reset password, consent screen, OAuth callback handling, admin
  login + dashboard + client management + logs UI.

## Explicitly Out of Scope
- Multi-tenant SaaS control plane.
- Database adapter abstraction / multi-DB support (Postgres, MySQL, etc.).
- Billing, pricing, tenant-scoped audit logging.
- Custom-built cryptography, custom-built OIDC implementation ("0 dependency" as literally stated is
  rejected — see `decision.md` ADR on this).
- Framework-specific SDKs (Next.js, Django, etc.) — OIDC is the SDK; any conformant OIDC client library
  already works.
- NestJS backend — deleted, not migrated.

## Acceptance Criteria
- `hono/src/lambda.ts` uses `hono/aws-lambda`, deploys, and responds correctly behind API Gateway/Function URL.
- Rate limiting and CORS origin caching survive concurrent Lambda execution environments without
  correctness gaps (verified by more than one concurrent container serving consistent decisions).
- A person who is not the author can clone, configure via `.env`, and deploy without reading source code.
- NestJS backend directory no longer exists in the repository.
- A public writeup exists describing the real bugs found and fixed (see `phases.md` Phase 2).