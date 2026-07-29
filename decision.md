# Decision Records

## ADR 001: Use Better Auth NPM Package
- Status: Accepted (Supersedes original "Use Better Auth as identity core")
- Decision: Identity Engine: Better Auth v1.x via npm. Implements OAuth 2.1/OIDC, session management, and TOTP MFA.
- Rationale: This achieves true "zero mandatory operational dependency" and gives the self-hoster complete ownership of the auth logic. They can audit and read the exact OIDC flow running on their server without digging into `node_modules`.
- Consequences: Self-hosters run `npm install better-auth`. Security updates are handled via standard npm version bumps.

## ADR 002: Reject "0 dependency" as literally stated
- Status: Accepted
- Decision: The project uses Hono, the MongoDB driver, and standard utility libraries as real dependencies. "Zero dependency" is reinterpreted as "zero mandatory operational dependency" — no Redis, no message broker, no second always-on database. 
- Rationale: Hand-rolling RS256 signing, PKCE, OIDC discovery, and TOTP to satisfy a literal zero-dependency goal trades solved, audited problems for self-authored ones.
- Consequences: The public writeup claims "zero required infrastructure beyond MongoDB," not "zero dependencies."

## ADR 003: Kill the NestJS backend outright
- Status: Accepted
- Decision: Delete `backend/` entirely rather than continuing a dual-implementation migration.
- Rationale: Two competing unfinished implementations is a maintenance liability, not progress.
- Consequences: Any Better Auth CLI/config that lived only in `backend/auth.ts` was ported to `hono/auth.ts` before deletion. NestJS is permanently out of boundary.

## ADR 004: Multi-platform deploy via Hono runtime adapters
- Status: Accepted
- Decision: The API is deployable to AWS Lambda, Vercel, Netlify, Railway, Fly, Render, GCP Cloud Run, Azure Container Apps via Hono's first-class per-runtime adapters. One `app.ts`, multiple thin entry point files.
- Rationale: The project's value proposition includes "deploy anywhere." This is made true by using adapters Hono already ships, not by writing platform abstractions. The app logic is platform-agnostic; only the entry point changes.
- Consequences: Per-target connection-pooling behavior must be documented in the setup guide. Cloudflare Workers is a documented limitation (no MongoDB driver).

## ADR 005: Platform-specific connection handling
- Status: Accepted
- Decision: MongoDB connection exhaustion is managed per-deploy-target, documented in the setup guide:
  - Lambda/Vercel/Netlify: Configure reserved concurrency or platform equivalents to cap concurrent execution environments.
  - Railway/Fly/Render/Cloud Run/Azure: Long-lived containers naturally reuse a connection pool.
- Rationale: Different runtime models have different connection behaviors. A uniform code-level fix doesn't exist; the correct answer is per-target documentation, not speculative code.
- Consequences: Self-hosters must read the platform-specific notes for their target.

## ADR 006: MongoDB TTL collections replace DynamoDB
- Status: Accepted
- Decision: Rate-limit counters and CORS origin cache move from DynamoDB to two MongoDB collections with native TTL indexes (`expireAfterSeconds`). 
- Rationale: DynamoDB was the only AWS-specific piece of state in the system. Removing it makes "deploy anywhere" true — the only required infrastructure is MongoDB, which the self-hoster already configures. MongoDB's TTL index maps directly onto the same expiry pattern DynamoDB provided.
- Consequences: Two new collections (`rate_limits`, `origin_cache`) with TTL indexes. Documents expire automatically via MongoDB's native TTL reaper — no cleanup code.

## ADR 007: No database adapter abstraction
- Status: Accepted
- Decision: MongoDB remains the only supported datastore. No `DatabaseAdapter` interface is built.
- Rationale: The Better Auth identity engine already exposes adapter choice internally. Building a second abstraction on top is waste.
- Consequences: Mongo is supported out of the box; other databases are a documented code change, not a first-class configured option.

## ADR 008: Portfolio artifact, not open-source community product
- Status: Accepted
- Decision: No roadmap, no contribution guidelines beyond basics, no plugin system, no multi-tenant ambitions. Time-boxed to 3 weeks.
- Rationale: Competing with Keycloak/Zitadel/Ory/Supabase Auth on adoption is a losing commitment for a final-year student who needs to earn ASAP.
- Consequences: Effort goes toward setup UX, security hardening, and a public writeup, not feature breadth.

## ADR 009: Defer any future SaaS to a separate project
- Status: Accepted
- Decision: If a validated SaaS idea emerges later, it uses Clerk/Supabase Auth/WorkOS, not this project.
- Consequences: This project and any future SaaS remain architecturally independent.

## ADR 010: Client-data-in-consumer-DB satisfied by standard OIDC
- Status: Accepted
- Decision: No new feature, sync service, or data pipeline is built. Consuming applications receive identity claims via standard OIDC ID tokens and `/userinfo`, and store whatever they want in their own databases, keyed on `sub`.
- Rationale: This is exactly how Google/Microsoft/OAuth works. The identity provider issues claims; the consuming app decides what to store locally. Building a sync service would be reinventing what OIDC already does.
- Consequences: Documented as a workflow in `architecture.md`. Consuming apps verify request JWTs using the auth service's JWKS public key.

## ADR 011: MFA = Better Auth TOTP Plugin (RFC 6238)
- Status: Accepted
- Decision: Admin and user 2FA uses the Better Auth `twoFactor` plugin logic — TOTP (RFC 6238), backup codes. Replaces email OTP entirely.
- Rationale: TOTP needs no mailer (eliminates the email-provider dependency entirely). Standard authenticator apps (Google/Microsoft Authenticator) generate codes locally from a shared secret provisioned once via QR code — no network round-trip, no spam-folder failure mode. Backup codes come free.
- Consequences: Admin login flow = username/password → TOTP 6-digit code (when 2FA enabled). Because OIDC is centralized, this MFA automatically protects registered client apps when their users log in.

## ADR 012: Data protection via hashing + TLS + infrastructure at-rest encryption
- Status: Accepted
- Decision: No hand-rolled symmetric encryption layer. Data protection is:
  - Passwords: hashed one-way (bcrypt/argon2).
  - Client secrets: hashed verify-only, shown once at issuance.
  - TOTP secrets: encrypted at rest by the Better Auth twoFactor plugin using `BETTER_AUTH_SECRET`.
  - JWTs: RS256-signed, verified via JWKS public key.
  - Transit: TLS + HSTS.
  - At rest: MongoDB Atlas encrypts at rest by default (infrastructure level).
- Rationale: "Encrypt the whole DB with strong encryption" is vague enough to be dangerous. Hashing for credentials, TLS for transit, and infrastructure-level at-rest encryption is the correct, standard approach.
- Consequences: If a specific field genuinely needs encryption-in-use later, that's a scoped decision made then, not a blanket policy now.

## ADR 013: Security scan remediation folded into phases
- Status: Accepted
- Decision: Security scan findings addressed as follows:
  - M10 (admin promotion via DB script): fixed to log every promotion with actor/timestamp and require explicit email confirmation before writing. 
  - H4b (admin MFA): resolved by ADR 011 (TOTP). 
  - L2 (Lambda Function URL, no WAF): documented as accepted risk with the CloudFront-WAF path noted as the production upgrade. 
  - Client-secret hashing: verified the Better Auth identity engine hashes `client_secret` at rest.
- Rationale: Each finding is triaged by actual exploitability, not by the scan's severity label. The fixes are proportional to the threat and the timebox.
- Consequences: These are tracked as Phase 1c gate items, verified and closed.

## ADR 014: App Admin Provisioning via OIDC Roles
- Status: Accepted
- Decision: To provide administrators for registered client apps, the Auth Server admin uses a "Provision App Admin" feature. This creates a standard user in the Auth Server DB with `role: "admin"` and saves their `adminUserId`/`adminEmail` on the specific `oauthClient` document for reference.
- Rationale: Client apps do not configure their own admins. When the provisioned admin logs into the client app via OIDC, the `admin` role is included in their JWT token. The client app reads this claim to grant admin panel access. This avoids multi-tenancy while solving the client app admin requirement.
- Consequences: The `oauthClient` schema is extended to include `adminUserId` and `adminEmail`. Client apps must check the `role` claim in the JWT to authorize their own admin panels.

## ADR 015: App Admin Provisioning is Informational Only
- Status: Accepted
- Decision: The 'Provision App Admin' feature saves the user's ID and email on the `oauthClient` document for reference only. It does not create a per-client scoped role.
- Rationale: Introducing per-client scoped admin roles would constitute multi-tenancy, which is permanently out of boundary. Client apps receive a standard JWT containing the global `role` claim; they are responsible for their own internal authorization based on that claim.