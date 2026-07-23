# Build Prompt

You are executing a scoped, time-boxed engineering task on an existing repository. Before writing any
code, read these files in the repo root, in this order, and treat them as binding, not advisory:

`projectrequirement.md` → `project.md` → `architecture.md` → `design.md` → `boundaries.md` → `rules.md`
→ `decision.md` → `phases.md` → `memory.md`

## Non-negotiable framing

- This is a self-hosted, single-tenant-per-deployment OAuth 2.1 / OIDC provider (Hono + Better Auth +
MongoDB), deployed to a single AWS Lambda function. It is a portfolio artifact, not a startup, not a
SaaS, not an open-source community product with a roadmap. Do not add multi-tenancy, billing, plugin
systems, or a database adapter abstraction under any circumstance — these are explicitly rejected in
`decision.md` and `boundaries.md`.
- Total scope is time-boxed to 3 weeks, part-time. Work strictly in the order defined in `phases.md`.
Do not begin a phase until the prior phase's stated verification gate is actually met.
- Follow `AGENTS.md`'s "lazy senior developer" discipline: smallest correct diff, no unrequested
abstractions, reuse before rewrite, root-cause fixes at the shared function rather than per call site.

## Phase 0 — execute first, nothing else until this is verified

1. Delete the `backend/` directory (NestJS) entirely. Confirm no remaining references via `git grep`.
2. In `hono/src/lambda.ts`, replace the `hono/lambda-edge` import with `hono/aws-lambda`. This is a
deploy-breaking bug today (Lambda@Edge cannot read environment variables; this project's config is
fully env-driven) — fix it exactly, do not redesign the handler beyond this.
3. Configure Lambda reserved concurrency in the deployment IaC (choose SAM, CDK, or Serverless Framework —
pick whichever tool you already know; do not introduce a new one). Record the choice in `memory.md`.
4. Create a single on-demand DynamoDB table with a TTL attribute. Rewire
`hono/src/middleware/rate-limit.ts` and `hono/src/cache/origin-cache.ts` to read/write it instead of
the in-memory `Map`/`LRUCache`, per the key schema in `design.md` ("New in this build: DynamoDB access
pattern"). This fixes a real correctness bug: in-memory state does not survive across concurrent Lambda
execution environments.
5. Leave a runnable check behind for each fix per `rules.md` — at minimum, a script or documented manual
test proving (a) the Lambda handler reads env vars correctly, and (b) two concurrent simulated
invocations see a consistent rate-limit count and a consistent origin-cache decision after invalidation.
6. Do not touch MongoDB, do not add a database adapter abstraction, do not migrate to Postgres. This is a
deliberate, documented decision (ADR 004, ADR 005, ADR 007) — treat any temptation to "improve" the
persistence layer here as scope creep and stop.
7. Update `memory.md`'s "Open items" section with what was actually completed and verified.

## Phase 1 — only after Phase 0's gate is met

1. Write `.env.example` documenting every variable in the zod `envSchema`, one line each.
2. Write a setup section in the README: clone → configure `.env` → run the Better Auth CLI migration →
deploy via the IaC tool chosen in Phase 0. No step may require editing source code for a standard deployment.
3. Verification gate: have someone who has not touched this project attempt the setup unaided. Fix any
step they get stuck on before proceeding to Phase 2.

## Phase 2 — only after Phase 1's gate is met

1. Push the repository public with `projectrequirement.md` through `memory.md` intact and current.
2. Write one public post describing the three real engineering decisions made in Phase 0 (the Lambda
adapter bug, the in-memory-state-under-concurrency bug, choosing reserved concurrency over a database
rewrite). Prioritize this writeup over any further code polish — it is the higher-leverage deliverable
for the stated goal (job search artifact).
3. Add the repo and post to resume/LinkedIn on completion. Do not delay for a subjective "more finished" feeling.

## Constraints that apply throughout all phases

- No new mandatory operational dependency (no Redis, no message broker, no second always-on service).
- TypeScript strict mode stays on. No new `any` to silence a type error.
- All environment access goes through the existing composition root (`hono/src/config`). No direct
`process.env` reads elsewhere.
- Any change to a contract, boundary, or decision in the md files must update that file in the same change.
- If a requirement in this prompt appears to conflict with something discovered in the actual code, stop
and surface the conflict rather than silently choosing one side.