# Project Overview

This project is an auth-first SaaS foundation built around Better Auth, OAuth 2.1, and an admin-controlled client registry. The immediate value is a secure, deployable identity service that can issue tokens, manage OAuth clients, and provide the operational admin tooling needed to run the platform safely.

The current product boundary is intentionally narrow. It is not yet a multi-tenant SaaS platform; it is the authenticated core that must be stable before higher-level tenancy, billing, and self-serve onboarding are added.

Business value comes from three places:
- A reusable authentication and authorization core that can support multiple applications.
- An admin workflow for managing OAuth clients and observing access activity.
- A production deployment path that can be operated cheaply at low volume.

The near-term goal is to finish the Hono migration, harden the security posture, and deploy the system on AWS Lambda with a static frontend delivery path.