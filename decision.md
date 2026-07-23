# Decision Records

## ADR 001: Use Better Auth as the identity core
- Status: Accepted
- Decision: Better Auth owns authentication, sessions, OAuth flows, and JWT issuance.
- Rationale: Reduces custom auth surface area to near zero and already implements the required flows correctly.
- Consequences: Custom code stays a thin adapter/policy layer around Better Auth. No auth primitive is reimplemented.

## ADR 002: Reject "0 dependency" as literally stated
- Status: Accepted
- Decision: The project uses Better Auth, Hono, and the AWS SDK's DynamoDB client as real dependencies.
  "Zero dependency" is reinterpreted as "zero mandatory *operational* dependency" — no Redis, no message
  broker, no second always-on service to run.
- Rationale: Hand-rolling RS256 signing, PKCE, and OIDC discovery to satisfy a literal zero-dependency
  goal trades a solved, audited problem for a self-authored one. That is not lazy-efficient, it is reckless.
- Consequences: The public writeup for this project should not claim "zero dependencies" — it should claim
  "zero required infrastructure beyond Lambda/Mongo/DynamoDB," which is the true and defensible claim.

## ADR 003: Kill the NestJS backend outright, do not migrate it in parallel
- Status: Accepted (supersedes any prior "phase 1: migrate" framing)
- Decision: Delete `backend/` entirely rather than continuing a dual-implementation migration.
- Rationale: Two competing unfinished implementations of the same auth logic is not "in progress," it is
  a maintenance liability and a red flag in a portfolio review. `phases.md` already called for this; it
  had not been executed.
- Consequences: Any Better Auth CLI/config reference that lived only in `backend/auth.ts` must be ported
  to a `hono/`-side equivalent before deletion, not lost.

## ADR 004: Fix the Lambda adapter instead of the database
- Status: Accepted
- Decision: `hono/src/lambda.ts` moves from `hono/lambda-edge` to `hono/aws-lambda`. No database migration
  is performed in this build.
- Rationale: `hono/lambda-edge` targets Lambda@Edge/CloudFront Functions, which cannot read environment
  variables at all — a hard platform restriction incompatible with this project's fully env-driven config.
  This was a deploy-time crash, not a design preference, and is the highest-priority fix in the repo.
  A database rewrite was considered (Postgres via a serverless-HTTP driver) and rejected for this build:
  the actual production risk (unbounded concurrent Mongo connections from Lambda) is fully addressed by
  Lambda reserved concurrency, at a fraction of the cost and risk of a persistence-layer rewrite under a
  3-week clock. See ADR 005.
- Consequences: A future iteration may still evaluate Postgres if this project ever needs true elastic
  scale beyond what reserved concurrency comfortably serves — not before then.

## ADR 005: Bound MongoDB connections via Lambda reserved concurrency, not a driver swap
- Status: Accepted
- Decision: Set Lambda reserved concurrency to a value the target Atlas tier's connection limit supports,
  as a deployment-time configuration, documented in the setup guide.
- Rationale: This is the smallest correct fix for the actual failure mode (connection exhaustion under
  concurrent invocation), consistent with "does a native platform feature already cover it" — it does.
- Consequences: Self-hosters must choose an Atlas tier and a concurrency setting consistent with each
  other. This is documented, not automated, in this build.

## ADR 006: Move rate-limit and CORS-origin-cache state to DynamoDB
- Status: Accepted
- Decision: Replace the in-memory `Map` (admin rate limiter) and in-memory `LRUCache` (origin cache) with
  a single on-demand DynamoDB table, TTL-based expiry.
- Rationale: In-memory state does not survive across Lambda's independent concurrent execution
  environments. This was a live correctness bug (rate limits effectively unenforced under concurrency,
  origin-cache invalidation only reaching one container) at any real traffic level, not a future scaling
  concern. DynamoDB on-demand billing preserves the near-zero-idle-cost constraint.
- Consequences: One new AWS primitive is introduced. This is judged acceptable against ADR 002's
  "no mandatory operational dependency" rule because DynamoDB is managed, serverless, and billed
  per-request — it does not require the self-hoster to run or operate anything.

## ADR 007: No database adapter abstraction
- Status: Accepted
- Decision: MongoDB remains the only supported datastore in this build. No `DatabaseAdapter` interface is
  built on top of Better Auth's own existing adapter abstraction.
- Rationale: Better Auth already exposes adapter choice (Mongo, Postgres/MySQL/SQLite via Kysely, Prisma,
  Drizzle). Building a second abstraction on top of an existing one is pure waste against the 3-week clock
  and against YAGNI. A self-hoster who wants Postgres can swap the adapter directly in `hono/src/utils/auth.ts` themselves.
- Consequences: The public positioning ("bring your own DB") is honest about this: Mongo is supported
  out of the box; other Better Auth-supported databases are a documented, understood code change, not a
  first-class configured option.

## ADR 008: Scope as a portfolio artifact, not an open-source community product
- Status: Accepted
- Decision: No roadmap, no contribution guidelines beyond basics, no plugin system, no multi-tenant
  ambitions. The project is explicitly time-boxed to 3 weeks and positioned for a job search.
- Rationale: Competing with Keycloak/Zitadel/Ory/Supabase Auth on adoption with zero monetization and zero
  team is a losing, time-unbounded commitment for a final-year student who needs to earn ASAP. The
  differentiated, defensible angle (Lambda-native, pay-per-request, config-only) is achievable in the
  time-box; general feature-parity is not.
- Consequences: Effort in weeks 2–3 goes toward setup UX and a public writeup, not toward feature breadth.

## ADR 009: Defer any future SaaS to a separate project using a hosted auth provider
- Status: Accepted
- Decision: If a validated SaaS idea emerges later, it uses Clerk/Supabase Auth/WorkOS, not this project.
- Rationale: Auth is not differentiation for a revenue-seeking product; shipping speed and customer
  validation are. This project's existence is not contingent on a SaaS being built, and a SaaS's existence
  should not be contingent on this project being "good enough" to depend on.
- Consequences: This project and any future SaaS remain architecturally and organizationally independent.