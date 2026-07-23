# Session Memory

## Who this is for
Future sessions (Claude or the builder) picking this project back up. Read this before re-deriving
decisions that are already settled — re-litigating settled scope is the fastest way to blow the 3-week clock.

## Builder context (carry forward, do not re-ask)
- Final-year MSc CS student, KIIT, India. Needs to earn ASAP — job applications run in parallel with this
  project, not after it. Do not suggest sequencing that delays job applications.
- This project is a portfolio artifact for the job search, not a startup and not an open-source community
  product. It has no monetization path and none is being built.
- A separate SaaS ambition exists (originally an Instagram comment-auto-reply idea) and was correctly
  killed: Meta ships this natively, and a dozen funded competitors (ManyChat, Chatfuel, NapoleonCat, Spur,
  CreatorFlow, etc.) already occupy the commodity version of this idea at $9–49/month price points. No
  validated SaaS idea currently exists. If one emerges, it is a separate project, uses a hosted auth
  provider (Clerk/Supabase Auth/WorkOS), and does not depend on this repo.

## Settled decisions — do not re-litigate without a new, explicit reason
- Self-hosted, single-tenant-per-deployment model (not multi-tenant SaaS). Each deployer owns their own
  Mongo instance and secrets.
- MongoDB stays. No Postgres/serverless-driver migration in this build (ADR 004, ADR 007).
- NestJS backend deleted, not migrated in parallel (ADR 003).
- `hono/src/lambda.ts` must use `hono/aws-lambda`, never `hono/lambda-edge` (ADR 004) — this was a
  deploy-breaking bug, already identified, fix is mechanical.
- Rate limiting and CORS origin cache move from in-memory to a single on-demand DynamoDB table with TTL
  (ADR 006) — this was a live correctness bug under concurrent Lambda execution, not a future scaling item.
- Connection exhaustion against MongoDB Atlas is addressed via Lambda reserved concurrency, not a driver
  swap (ADR 005).
- "0 dependency" as literally stated is rejected; the real constraint is zero mandatory *operational*
  dependency (ADR 002).
- 3-week total timebox, part-time. Phase gates in `phases.md` are the source of truth for what's next.

## Stable facts about the existing system (verified against actual repo files, not assumed)
- Admin access is server-side role-gated (`role === "admin"` check in Hono middleware and in the legacy
  NestJS controller — the latter is being deleted).
- CORS is dynamic, derived from `oauthClient.redirectUris` matched by prefix against the request Origin.
- CSRF protection (`hono/src/middleware/csrf.ts`) applies to non-safe-method admin requests via a
  double-submit cookie/header pattern.
- Redirect URI validation already rejects non-http(s) schemes and wildcard characters; the private-network
  hostname check is production-only by design (dev needs localhost to work).
- Admin logs/stats are read views over `session` and `user` collections — there is no dedicated audit log,
  and building one is explicitly out of scope (ADR/design already reject this).
- Production target: AWS Lambda for the API (via `hono/aws-lambda` after the fix), S3 + CloudFront for the
  frontend, Docker Compose for local dev only.

## Working rules for future sessions
- Start from the nearest concrete file or runtime behavior, not from re-designing the architecture.
- Prefer the smallest verified change over a broad refactor — this is a hard rule, not a preference, given
  the timebox (see `AGENTS.md`, `rules.md`).
- Do not widen scope toward multi-tenancy, multi-DB support, or SaaS features under any framing — these
  are permanently out of boundary for this repo (`boundaries.md`).
- Update this file at the end of each work session with what was actually completed and verified against
  the Phase gates in `phases.md`, not with what was attempted or planned.

## Open items (update as resolved)
- Phase 0 not yet executed as of this writing — this document set (`projectrequirement.md` through
  `phases.md`) is the plan, not a completion record.
- IaC tool for deployment not yet chosen — Phase 0 says "whichever the builder already knows"; record the
  actual choice here once made, so future sessions don't re-debate SAM vs CDK vs Serverless Framework.