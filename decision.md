# Decision Records

## ADR 001: Use Better Auth as the identity core

- Status: Accepted
- Decision: Better Auth owns authentication, sessions, OAuth flows, JWT issuance, and TOTP MFA.

## ADR 002: Reject "0 dependency" as literally stated

- Status: Accepted
- Decision: "Zero dependency" is reinterpreted as "zero mandatory operational dependency" (`MongoDB` only).

## ADR 003: Kill the NestJS backend outright

- Status: Accepted
- Decision: Delete `backend/` entirely.

## ADR 004: Multi-platform deploy via Hono runtime adapters

- Status: Accepted
- Decision: Deployable to AWS Lambda, Vercel, Netlify, Railway, Fly, Render, GCP, and Azure via Hono adapters.
- Consequences: Per-target connection-pooling behavior must be documented.

## ADR 005: Platform-specific connection handling

- Status: Accepted
- Decision: MongoDB connection exhaustion is managed per deploy target. Stateless targets like Lambda need reserved concurrency; long-lived containers naturally reuse pools.

## ADR 006: MongoDB TTL collections replace DynamoDB

- Status: Accepted
- Decision: Rate-limit counters and CORS origin cache move to MongoDB collections with TTL indexes.
- Rationale: Makes "deploy anywhere" true, with no AWS-specific state infrastructure required.

## ADR 007: No database adapter abstraction

- Status: Accepted
- Decision: MongoDB remains the only supported datastore.

## ADR 008: Portfolio artifact, not open-source community product

- Status: Accepted
- Decision: Time-boxed to 3 weeks. No roadmap or multi-tenant ambitions.

## ADR 009: Defer any future SaaS to a separate project

- Status: Accepted
- Decision: Future SaaS uses Clerk or Supabase Auth, not this project.

## ADR 010: Client-data-in-consumer-DB satisfied by standard OIDC

- Status: Accepted
- Decision: No sync service is built. Consuming apps receive identity claims via OIDC tokens and store what they want in their own DBs.

## ADR 011: Admin MFA = Better Auth `twoFactor` plugin

- Status: Accepted
- Decision: Admin 2FA uses Better Auth's `twoFactor` plugin (`RFC 6238`). It replaces email OTP.
- Rationale: Standard authenticator apps generate codes locally from a shared secret provisioned via QR code. No mailer dependency, no deliverability failure mode.

## ADR 012: Data protection via hashing + TLS + infrastructure at-rest encryption

- Status: Accepted
- Decision: No hand-rolled symmetric encryption layer. Hashing for credentials, TLS for transit, MongoDB Atlas for at-rest encryption.

## ADR 013: Security scan remediation folded into phases

- Status: Accepted
- Decision: M10 fixed with logging and confirmation. H4b resolved by TOTP. L2 documented as accepted risk. Client-secret hashing verified.
