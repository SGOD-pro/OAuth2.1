# Project Overview

## What this is
A self-hosted OAuth 2.1 / OIDC identity provider built on Hono + Better Auth + MongoDB, deployable to
AWS Lambda at near-zero idle cost. The person who deploys it owns their own database, their own secrets,
and their own infrastructure — there is no shared multi-tenant runtime and no vendor lock-in.

## What this is not
Not a startup. Not a SaaS. Not a funded product. Not competing head-on with Keycloak/Zitadel/Ory/Supabase
Auth on feature completeness — those are mature, team-maintained, container-first projects with years of
head start. Trying to out-feature them in 3 weeks is a losing move and isn't the goal.

## Why it exists (the real reason, stated honestly)
This is a portfolio artifact for a final-year MSc CS student job search. Its value is not measured in
GitHub stars or self-host adoption — it is measured in whether it survives a 45-minute technical interview
conversation and whether the accompanying writeup gets forwarded by a recruiter. Scope, documentation, and
the public writeup are chosen against that measure, not against "building a real company."

## The angle (why this project, not a generic clone)
Every mature self-hosted IdP in this space (Keycloak: JVM, Zitadel/Ory Kratos: long-running Go binaries)
is designed around always-on containers. None of them are built for the specific case of "an indie
developer who wants a real OIDC provider but doesn't want to pay for an always-on server before they have
users." This project is scoped narrowly to that gap: **Lambda-native, pay-per-request, config-only
deploy.** That narrowness is the differentiator, and it is also what makes 3 weeks realistic.

## Business value (as a portfolio artifact, not a company)
- Demonstrates real backend/platform engineering judgment: finding and fixing a hard Lambda deployment bug
  (`lambda-edge` vs `aws-lambda`), reasoning about state consistency across concurrent stateless execution
  environments (in-memory rate limiting/caching failure mode), and making a disciplined "don't rewrite
  what works" call under a deadline instead of chasing an idealized architecture.
- Demonstrates security literacy: CSRF on admin mutations, redirect URI validation, role-gated admin
  surface, dynamic CORS derived from persisted client data.
- Produces a citable, linkable artifact (repo + writeup) usable in resume, LinkedIn, and interviews.

## Non-goals
- Multi-tenancy, billing, self-serve tenant onboarding — deferred permanently, not "later." This project
  does not become a SaaS. If a SaaS is built, it is a separate, validated idea (see `memory.md`), and it
  uses a hosted auth provider (Clerk/Supabase Auth/WorkOS) rather than this project, because shipping
  speed for a revenue-seeking product beats owning the auth stack.