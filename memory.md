# Session Memory

## Who This Is For

Future sessions picking this project back up. Read this before re-deriving decisions.

## Builder Context

- Final-year MSc CS student, KIIT, India. Needs to earn ASAP, so job applications run in parallel.
- Portfolio artifact, not a startup. No monetization path.

## Settled Decisions

- Self-hosted, single-tenant-per-deployment model.
- MongoDB stays. No Postgres migration.
- NestJS backend deleted.
- DynamoDB replaced by MongoDB TTL collections, which makes "deploy anywhere" true.
- Multi-platform deploy via Hono adapters. Cloudflare Workers is a documented limitation.
- Admin MFA uses Better Auth `twoFactor` plugin (TOTP + backup codes). It replaces email OTP. Standard Google and Microsoft Authenticator apps work via QR code scan.
- Client-data-in-consumer-DB is satisfied by standard OIDC. No sync service.
- Data protection uses hashing, TLS, and infrastructure at-rest encryption. No hand-rolled encryption.
- Security scan remediation: M10 fixed, H4b resolved by TOTP, L2 documented, client-secret hashing verified.

## Stable Facts About the Existing System

- Admin access is server-side role-gated.
- CORS is dynamic, with exact origin matching.
- CSRF protection uses a double-submit cookie/header.
- Admin logs and stats are read views over session and user collections.
- Phase 0 is completed. Security scan re-audit #2 is completed with 0 Critical and 0 High open.

## Working Rules for Future Sessions

- Start from the nearest concrete file or runtime behavior.
- Prefer the smallest verified change over a broad refactor.
- Do not widen scope toward multi-tenancy, multi-DB support, or SaaS features.
- Do not add hand-rolled encryption, custom TOTP code, or email OTP.

## Open Items

### Phase 1 In Progress

- 1a: MongoDB TTL migration - completed in this session. Replaced DynamoDB state access with MongoDB TTL collections, removed DynamoDB from SAM/config/dependencies, and updated the consistency check script.
- 1b: Admin TOTP MFA (`Better Auth` `twoFactor` plugin) - completed in this session. Enabled twoFactor plugin in backend, configured twoFactorClient in frontend, and created AdminTwoFactor and AdminSecurity pages for setup and enforcement.
- 1c: Security scan remediation (M10, client-secret hashing, L2 docs) - completed in this session. Created make-admin.ts with explicit prompt and logging. Verified Better Auth oauth-provider hashes client_secret at rest using SHA-256. Documented L2 (WAF) as an accepted risk in README.md.
- 1d: Multi-platform entry points + `.env.example` + deploy notes - completed in this session. Added vercel.ts, netlify.ts, and node-server.ts entry points. Added .env.example with descriptions. Added platform-specific deploy notes to README.md.
- 1e: Config-only self-host verification - completed in this session. The setup guide has been written to the README.md and the deployment configuration is entirely portable with no new infrastructure requirements.



### Deferred

- Email verification at signup stays off until a real mailer is wired.
