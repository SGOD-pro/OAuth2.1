# Implementation Phases

## Ground rule
This runs in **parallel** with job applications, not before them — applications start immediately,
independent of project status. Total project clock: **3 weeks**, part-time. A phase does not begin until
the previous phase is verified against a concrete check, not a feeling of "probably done."

## Phase 0: Triage (Week 1, first few hours of work)
Goal: stop the bleeding. Fix the defects that make the current repo actively broken or actively wrong,
touching as little as possible.
- Delete `backend/` (NestJS) entirely. Verify: `git grep` for NestJS imports returns nothing outside git history.
- Fix `hono/src/lambda.ts`: `hono/lambda-edge` → `hono/aws-lambda`. Verify: a real `sam local invoke` or
  deployed Lambda cold start succeeds and reads an env var correctly.
- Set Lambda reserved concurrency in the deploy config (SAM/CDK/Serverless Framework, whichever the
  builder already knows — do not learn a new IaC tool this month). Verify: the deployed function's
  concurrency limit is visible in the AWS console/CLI output.
- Stand up the single DynamoDB table (on-demand, TTL enabled) and rewire the admin rate limiter
  (`hono/src/middleware/rate-limit.ts`) and origin cache (`hono/src/cache/origin-cache.ts`) to use it per
  `design.md`. Verify: two separate concurrent invocations (simulate with two parallel curl loops or two
  separate `sam local` processes) enforce a consistent rate-limit count and see a consistent
  origin-allow decision after a cache invalidation.
- **Gate**: Phase 0 is not verified by "it compiles." It is verified by the four checks above actually
  passing, individually, with evidence (terminal output, screenshot, or a short note in `memory.md`).

## Phase 1: Config-only self-host (Week 2)
Goal: a stranger can deploy this without reading source code.
- Write a real `.env.example` covering every variable in `envSchema` with a one-line description each.
- Write a setup section in the README: clone → fill `.env` (Mongo URI, Google OAuth creds, Better Auth
  secret, frontend URL) → run the Better Auth CLI migration → deploy. No step requires editing source.
- One-command (or one-documented-sequence) deploy path using the IaC tool chosen in Phase 0.
- **Gate**: hand the repo + README to someone who has not touched this project (a classmate, a friend) and
  have them attempt the setup with no help. If they get stuck on an undocumented step, that step gets
  fixed before Phase 2 begins. This is the actual verification — self-review does not count.

## Phase 2: Ship and document (Week 3)
Goal: the artifact is public and legible to someone evaluating it in an interview.
- Push the repo public. Confirm `projectrequirement.md` through `decision.md` are present and current —
  they are load-bearing for how a reviewer understands the scope decisions, not decoration.
- Write one public post (blog or LinkedIn) narrating the real engineering decisions made under this scope:
  the `lambda-edge`/`aws-lambda` bug, why in-memory rate limiting silently breaks under Lambda concurrency,
  and why reserved concurrency was chosen over a database rewrite. This is prioritized above additional
  code polish — it is the higher-leverage use of remaining time.
- Add the repo and post to resume/LinkedIn immediately on completion. Do not wait for a "more finished"
  feeling — shipped-and-documented is the target state, not a subjective sense of completeness.
- **Gate**: the project is done when Phase 2's two artifacts (public repo, public writeup) exist and are
  linked from resume/LinkedIn. Nothing beyond this is in scope without a new, deliberate decision to extend.

## Phase Gate Rule
- A phase may not begin until the previous one is verified against the concrete check listed for it.
- If the 3-week clock runs out mid-phase (e.g., a job interview process starts), the project freezes at
  the last verified phase and ships in that state. A frozen-but-verified Phase 1 is a legitimate, honest
  stopping point. An unverified Phase 2 is not — do not claim "shipped" without the Phase 2 gate met.