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

### Phase 1: Portability and Security Hardening (Completed)
- 1a: MongoDB TTL migration. Replaced DynamoDB state access with MongoDB TTL collections, removed DynamoDB from config.
- 1c: Security scan remediation (M10, client-secret hashing, L2 docs).
- 1d: Multi-platform entry points + `.env.example` + deploy notes.
- 1e: Config-only self-host verification.

### Phase 2: Frontend Premium Redesign (Completed)
- Integrated the "Cohere" premium design system across all public and admin pages (glassmorphism, mesh gradients, noise/grain).
- Implemented `next-themes` ThemeProvider for flawless light/dark mode toggling across the application.
- Added `zustand` based state management with a 30s TTL cache and optimistic UI updates for Admin Dashboard, Clients, and Logs.
- Standardized forms using `react-hook-form`, `@hookform/resolvers`, and `zod`.
- Replaced legacy notifications with `sonner` toasts.
- Refined backend rate limiting to specifically target `/api/auth/*` while keeping `/api/admin/*` smooth for authenticated use.

### Phase 3: Admin & Client App TOTP MFA Integration (Completed)
- **3a:** Enabled `twoFactor` plugin in backend via Better Auth.
- **3b:** Fixed frontend MFA setup UI loop in `AdminSecurity.tsx`. Setup now correctly finalizes after 6-digit confirmation, and shows a "Disable 2FA" button thereafter. Fixed login flows in `SignIn.tsx` and `AdminLogin.tsx` to properly catch 2FA required status without showing generic errors. Additionally fixed state hallucination in setup page by strictly checking `isPending` state before evaluating `twoFactorEnabled`, preventing auto-generation of QR codes.
- **3c:** Verified that client app logins natively inherit the 2FA requirement.

### Phase 4: Ship and Document (In Progress)
- Needs public repository push, markdown doc verification.
- Needs public write-up post on engineering decisions.
- Needs resume/LinkedIn addition.

### Deferred
- Email verification at signup stays off until a real mailer is wired.
