# Build Prompt

You are executing a scoped, time-boxed engineering task on an existing repository. Before writing any
code, read these files in the repo root, in this order, and treat them as binding, not advisory:

`AGENT.md` → `projectrequirement.md` → `project.md` → `architecture.md` → `design.md` → `boundaries.md` → `rules.md` → `decision.md` → `phases.md` → `memory.md`

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


## Execution Rules
1. Zero Repo Scanning: Do not read the entire codebase to understand the project. The 10 files above are the absolute truth.
2. Zero Scope Creep: Apply the smallest correct diff. No unrequested abstractions. Reuse before rewrite. Root-cause fixes only.
3. Strict Phase Progression: Work strictly in the order defined in phases.md. Do not begin a phase until the prior phase's verification gate is met.
4. Respect Boundaries: boundaries.md defines what the system must NOT do. If my request violates a boundary, stop and call it out.
5. No Doc Drift: Any change to a contract, boundary, or decision must update the corresponding .md file in the exact same commit.
6. Update Memory: Update memory.md's state with exactly what was done in this session.
7. No Silent Overrides: If my request conflicts with the .md files or the code, STOP. Surface the conflict explicitly. Do not silently choose a side.
### Output Format
No fluff. No introductory pleasantries. Give me the code diff, the verification step, the .md updates, and state you are ready for the next task.

Awaiting my specific task. Execute context loading now.






create auth servers like that to test the application i amnyly config multiple appliction through
  admin dashboard, first you create the server files(separate on test folder init with npm(use tsconfig) and give backend the
  application urls for add in admin dashboard then run thee files once and check for different applciation it was handles or
  not.