
# Project Overview

## What this is
A pre-written, self-hosted OAuth 2.1 / OIDC identity provider built on Hono and MongoDB. It is designed to be cloned by a developer, configured with their own database, and deployed to AWS Lambda, Vercel, Netlify, Railway, or any Node-compatible host with near-zero idle cost. The person who deploys it owns their own database, their own secrets, and their own infrastructure — there is no shared multi-tenant runtime and no vendor lock-in. 

Crucially, this project uses the `better-auth` npm package at runtime. Identity Engine: Better Auth v1.x via npm. Implements OAuth 2.1/OIDC, session management, and TOTP MFA.

## What this is not
Not a startup. Not a SaaS. Not a multi-tenant control plane. Not a per-client DB routing system (consuming apps store their own user data locally via standard OIDC claims). Not competing head-on with Keycloak/Zitadel/Ory/Supabase Auth on feature completeness — those are mature, team-maintained, container-first projects with years of head start.

## Why it exists (the real reason, stated honestly)
This is a portfolio artifact for a final-year MSc CS student job search. Its value is not measured in GitHub stars or self-host adoption — it is measured in whether it survives a 45-minute technical interview conversation and whether the accompanying writeup gets forwarded by a recruiter. Scope, documentation, and the public writeup are chosen against that measure, not against "building a real company."

## The angle (why this project, not a generic clone)
Every mature self-hosted IdP in this space is designed around always-on containers. None of them are built for the specific case of "an indie developer who wants a real OIDC provider but doesn't want to pay for an always-on server before they have users." This project is scoped narrowly to that gap: **Platform-agnostic, pay-per-request capable, config-only deploy.** 

By relying solely on MongoDB (for both persistent and ephemeral state via TTL indexes), using Hono's runtime adapters for multi-platform deploy, and vendoring the identity engine, the system achieves true zero-vendor-lock-in without requiring the deployer to maintain a complex codebase.

## Business value (as a portfolio artifact, not a company)
- Demonstrates real backend/platform engineering judgment: migrating ephemeral state from DynamoDB to MongoDB TTL collections for portability; vendoring an identity engine to remove runtime dependencies; reasoning about state consistency across concurrent stateless execution environments.
- Demonstrates security literacy: TOTP-based MFA using local QR generation (no secret leakage); proper data protection (hashing credentials, infrastructure-level at-rest encryption); dynamic CORS; App Admin Provisioning via OIDC roles instead of multi-tenancy.
- Produces a citable, linkable artifact (repo + writeup) usable in resume, LinkedIn, and interviews.

## Non-goals
- Multi-tenancy, billing, self-serve tenant onboarding — deferred permanently. If a SaaS is built, it is a separate, validated idea and uses a hosted auth provider (Clerk/Supabase Auth/WorkOS).
- Per-client DB routing — rejected. Consuming applications own their user data via standard OIDC claims.
- Hand-rolled symmetric encryption — rejected. Hashing and infrastructure-level encryption are the correct approaches.
- Cloudflare Workers support — documented limitation (no MongoDB driver support).
- Email OTP for admin MFA — replaced entirely by standard TOTP.
- External QR Code APIs — rejected to prevent TOTP secret leakage.
