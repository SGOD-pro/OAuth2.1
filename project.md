# Project Overview

## What This Is

A self-hosted OAuth 2.1 / OIDC identity provider built on Hono + Better Auth + MongoDB, deployable to AWS Lambda, Vercel, Netlify, Railway, GCP Cloud Run, Azure Container Apps, or any Node-compatible host at near-zero idle cost. The person who deploys it owns their own database, their own secrets, and their own infrastructure. There is no shared multi-tenant runtime and no vendor lock-in. All ephemeral state, such as rate limiting and CORS caching, is handled via MongoDB TTL collections, meaning there is zero mandatory infrastructure beyond MongoDB itself.

## What This Is Not

- Not a startup.
- Not a SaaS.
- Not a funded product.
- Not a per-client DB routing system, because consuming apps store their own user data locally via standard OIDC claims.
- Not competing head-on with Keycloak, Zitadel, Ory, or Supabase Auth on feature completeness. Those are mature, team-maintained, container-first projects with years of head start. Trying to out-feature them in 3 weeks is a losing move and is not the goal.

## Why It Exists

This is a portfolio artifact for a final-year MSc CS student job search. Its value is not measured in GitHub stars or self-host adoption. It is measured in whether it survives a 45-minute technical interview conversation and whether the accompanying writeup gets forwarded by a recruiter. Scope, documentation, and the public writeup are chosen against that measure, not against "building a real company."

## The Angle

Every mature self-hosted IdP in this space, such as Keycloak, Zitadel, or Ory Kratos, is designed around always-on containers. None of them are built for the specific case of an indie developer who wants a real OIDC provider but does not want to pay for an always-on server before they have users. This project is scoped narrowly to that gap: platform-agnostic, pay-per-request capable, and config-only to deploy. By relying solely on MongoDB for both persistent and ephemeral state via TTL indexes and Hono's runtime adapters, the system can deploy to serverless or containerized environments without code changes. That narrowness is the differentiator, and it is also what makes 3 weeks realistic.

## Business Value

- Demonstrates real backend and platform engineering judgment: migrating ephemeral state from DynamoDB to MongoDB TTL collections to achieve true multi-platform portability without adding new infrastructure; reasoning about state consistency across concurrent stateless execution environments; and making a disciplined "don't rewrite what works" call under a deadline.
- Demonstrates security literacy: TOTP-based MFA using standard authenticator apps like Google Authenticator and Microsoft Authenticator via audited libraries; proper data protection with hashing credentials and infrastructure-level at-rest encryption instead of hand-rolled crypto; CSRF on admin mutations; and dynamic CORS derived from persisted client data.
- Produces a citable, linkable artifact, with repo and writeup, usable in resume, LinkedIn, and interviews.

## Non-Goals

- Multi-tenancy, billing, and self-serve tenant onboarding are deferred permanently, not "later." This project does not become a SaaS. If a SaaS is built, it is a separate, validated idea, and it uses a hosted auth provider such as Clerk, Supabase Auth, or WorkOS rather than this project, because shipping speed for a revenue-seeking product beats owning the auth stack.
- Per-client DB routing is rejected. Consuming applications own their user data via standard OIDC claims.
- Hand-rolled symmetric encryption is rejected. Hashing and infrastructure-level encryption are the correct approaches.
- Cloudflare Workers support is a documented limitation because the MongoDB driver is not supported there.
- Email OTP for admin MFA is replaced entirely by standard TOTP.
