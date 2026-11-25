# AI Agent Guidance & Integration Protocol (AGENTS.md)

Welcome, AI coding agent (e.g., Google Antigravity, Claude Code, GitHub Copilot, Cursor, Devin).

This repository contains **SWYRA Auth**, a centralized **OAuth / OpenID Connect (OIDC)** identity provider.
Production readiness and conformance must be established with evidence, not inferred from this description.

## V2 planning boundary (2026-11-22)

Read [docs/README.md](docs/README.md), [docs/PHASES.md](docs/PHASES.md),
[docs/IMPLEMENTATION_MAP.md](docs/IMPLEMENTATION_MAP.md), and
[0008](docs/specs/0008-multi-account-identity-platform/index.md) before V2 changes.
V2 user-facing flows remain planned. P0 isolated adapters/tests are
[locally verified](docs/specs/0008-multi-account-identity-platform/p0-evidence.md). Slices P1a, P1b, and P1c (client policy classification, audit, canonical policy resolution,
open app bypass, private token access, introspection gating, admin client policy UI and API,
and transactional credential transition and commit fences) are locally verified. Slices P2a and P2b (registration intents, OTP budgets, encrypted mail outbox, leased worker with local test sink, authenticated callbacks, transactional verified account completion, `/register/profile`, and verified mode provisioning bypass closure behind default disabled mode) are
[locally verified](docs/specs/0008-multi-account-identity-platform/verify.md)
with live mail provider delivery and P3 through P9 remaining pending. The first P3 slice
(browser session registry, opaque account handles, request local session adapter, single
account sign out and removal, and ordinary login / verified registration session wiring)
is also [locally verified](docs/specs/0008-multi-account-identity-platform/verify.md), with
chooser UI, OAuth transaction selection, and dashboard contexts pending for the next P3 slice.
Security PR #2 is integrated into main at `828acc5`;
preserve its eligibility/MFA hardening rather than rebuilding it as the next feature.
After P0 acceptance, follow bounded P1-P9 slices, preserving private/admin isolation, stable subjects
and protocol endpoints. New identity pages/APIs require a full-stack slice; a UI-only
task still follows frontend restrictions. Do not mark future endpoints/configuration
as implemented or future tests as passed. Account key deletion never replaces durable
revocation, independent restore safety or residual cleanup.

---

## ⚠️ Mandatory Precedence & Normative Contract

Before writing, modifying, or reviewing any integration code for consumer applications, you **MUST** read and adhere to the authoritative contracts:

👉 **[docs/INTEGRATION.md](docs/INTEGRATION.md)** (Normative Consumer Integration Specification & Concrete Recipes)  
👉 **[docs/SECURITY.md](docs/SECURITY.md)** (Normative Security Architecture & Trust Model)  
👉 **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** (System Design & Multi-Tenant Isolation Topology)  
👉 **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** (Complete Environment & Configuration Reference)  
👉 **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** (Production Deployment Runbook & Secret Rotation)  
👉 **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)** (Machine-Readable OAuth Errors & Diagnostic Procedures)  

---

## ⚡ The 10 Golden Rules for AI Agents

1. **NEVER create another authentication system when the centralized IdP is already configured.**  
   Consumer applications never install duplicate auth frameworks (Better Auth, NextAuth, Auth.js, Passport, Supabase, Lucia).
2. **NEVER connect a consumer directly to the IdP's MongoDB for normal authentication.**  
   Consumer applications never receive `MONGO_URI`. All communication is over standard HTTP OAuth 2.1 endpoints.
3. **NEVER copy password/session/token tables from the IdP.**  
   Credentials, session tokens, and refresh token family trees belong exclusively to the IdP.
4. **NEVER expose CLIENT_SECRET to browser code.**  
   Confidential clients keep secrets server-side; public clients (SPAs, mobile apps) do not use secrets.
5. **NEVER put confidential secrets in public environment variables or client storage.**  
   Never put secrets in `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `localStorage`, `sessionStorage`, or frontend source.
6. **NEVER create a localhost production fallback.**  
   Expressions like `AUTH_CALLBACK_URL || "http://localhost:3000/callback"` or `CLIENT_ID || "dev-client"` are strictly forbidden. Missing configuration must fail closed.
7. **NEVER treat NODE_ENV=production as "all OAuth clients are production".**  
   The IdP server runtime environment (`NODE_ENV`) is distinct from the client mode (`isDev`). A production IdP hosts both production and development clients.
8. **NEVER treat isDev as isPublic.**  
   `isDev` governs loopback URI permissions. Legacy `isPublic` describes open/private user access and does not prove OAuth client authentication type. V2 separates `clientType`, `accessPolicy`, and `isDev`.
9. **NEVER treat authentication as application authorization.**  
   OAuth authentication identifies "Who is this user?" via `sub`. The consumer application owns its own business roles and permissions.
10. **NEVER bypass the IdP's redirect URI / PKCE / state validation.**  
    OAuth 2.1 mandates PKCE (`S256`) and cryptographically random `state` on all flows.

---

## 🧭 Fast Endpoint Directory

Base URL: `${AUTH_ISSUER}` (e.g. `https://oauth21.vercel.app`)

| Protocol Action | Method | Exact Endpoint | Notes |
|---|---|---|---|
| OpenID Discovery | `GET` | `/.well-known/openid-configuration` | Returns issuer metadata & RFC endpoints |
| JWKS Public Keys | `GET` | `/.well-known/jwks.json` | RS256 public keys for offline verification |
| OAuth Authorization | `GET` | `/api/auth/oauth2/authorize` | Browser redirect with PKCE & state |
| Token Exchange / Refresh | `POST` | `/api/auth/oauth2/token` | `grant_type=authorization_code` or `refresh_token` |
| User Profile Info | `GET` | `/api/auth/oauth2/userinfo` | Header `Authorization: Bearer <access_token>` |
| Token Revocation | `POST` | `/api/auth/oauth2/revoke` | Revokes token family or active token |
| Token Introspection | `POST` | `/api/auth/oauth2/introspect` | Confidential client token verification |

---

## 🌳 Current Runtime Application Configurations

All applications authenticate users via the **centralized OAuth 2.1 Authorization Code Flow with PKCE (`S256`)**:

1. **A. Public Application (`isPublic: true`)**:
   - Open to all platform users. Sign-up enabled at IdP. First login records membership in `user_app_registrations`.
2. **B. Private Application (`isPublic: false`)**:
   - Enterprise tenant. Unauthenticated users are redirected to centralized IdP login with sign-up disabled.
   - Upon authentication, IdP verifies explicit membership in `user_app_registrations`.
   - Assigned &rarr; Authorization Code; Unassigned &rarr; `302 error=access_denied`.
   - **Zero Password Relay:** Consumer applications NEVER collect, proxy, or relay passwords.
3. **C. Public Application + Custom App Admin**:
   - Standard OAuth login. App Admins receive `role: "admin"` and `scoped_client_id: "<clientId>"`.
4. **D. Private Application + Custom App Admin**:
   - Standard OAuth login. App Admin must be explicitly provisioned for the private client, with matching `scoped_client_id`.

---

## 🔒 18 Security Review Questions for Agents

Before completing any integration task, verify:
1. Is the client public or confidential?
2. Is this client development or production?
3. Is the callback URI exactly registered in the IdP?
4. Is the production callback HTTPS?
5. Is localhost used only for explicitly configured development?
6. Is `CLIENT_SECRET` strictly server-side?
7. Is PKCE `S256` enabled on all authorization code flows?
8. Is `state` generated randomly and verified upon callback?
9. Is `iss` validated against `AUTH_ISSUER`?
10. Is `aud` validated against `CLIENT_ID`?
11. Is the JWT cryptographically verified against the IdP JWKS?
12. Is `returnTo` constrained to safe relative paths?
13. Is local application logout distinguished from IdP logout?
14. Is application authorization enforced independently of authentication?
15. Is IdP MongoDB completely untouched?
16. Can authentication fail open on any code path?
17. Is there an environment bypass that could activate in production?
18. Are production and development configurations strictly isolated?

---

## 📋 Integration Recipes Index

For the normative framework contracts and reviewed fixture requirements, refer directly to [docs/INTEGRATION.md](docs/INTEGRATION.md#6-concrete-framework-integration-recipes):

- **Next.js 14+ (App Router) BFF**: Route handlers for PKCE login, callback, and HttpOnly session cookie storage.
- **Pure React SPA (Vite / CRA)**: In-browser PKCE S256 generation, redirect, token exchange without secrets.
- **React SPA + Python FastAPI**: PyJWKClient offline JWT verification with RS256 algorithm pinning and audience validation.
- **React SPA + Express / Node.js**: `jose` offline JWT verification middleware.

---

## ✅ Integration Verification Checklist

Before declaring your integration task complete, verify every item:
- [ ] No `MONGO_URI` or direct DB access in consumer codebase.
- [ ] No duplicate auth frameworks installed in consumer dependencies.
- [ ] Authorization redirect uses `/api/auth/oauth2/authorize` (NOT `/auth`).
- [ ] PKCE `code_challenge` (`S256`) and `state` are supplied and validated.
- [ ] `client_secret` is strictly server-side and never exposed to browser bundles.
- [ ] No localhost fallback literals in configuration (`|| "http://localhost..."`).
- [ ] RS256 JWTs are validated offline via `/.well-known/jwks.json`.
- [ ] `aud` and `iss` claims in JWT match consumer `CLIENT_ID` and `AUTH_ISSUER`.
- [ ] Consumer application builds cleanly and tests pass.
- [ ] Linter gate passes: `npm run security:integration-check`.

## Required V2 review invariants

- No account/credential creation before a verified one-use mailbox proof is consumed.
- One person may hold multiple distinct verified-email accounts. Immutable user IDs,
  not email prefixes, chosen usernames or fingerprints, identify authorization subjects.
- Chooser selection binds account/session to a specific OAuth transaction across tabs.
- Separate accounts can coexist; their roles, sessions, expiry and logout never merge.
- Both admin roles require TOTP and recent MFA on backend and plugin paths.
- Open-app ordinary membership gates are removed only in the policy migration slice.
  Private memberships, consent, registered clients and app-admin assignments remain.
- Ordinary admin API/search/export/log projections omit full emails. Token claims
  respect granted scopes; local-part labels remain personal data.
- Account key destruction does not replace immediate revocation or residual cleanup.
  Do not claim erasure if old backups can recover keys or plaintext.
- Fingerprints and Bloom filters never decide authentication, uniqueness or access.
- Record source inspection, mocked probes, integration tests and blocked checks separately.

---

## 🛠️ Core Engineering Rules

### 1. Think before coding
- State material assumptions before implementation.
- Ask when missing information changes correctness, security or scope.
- Explain meaningful tradeoffs and suggest a simpler solution when appropriate.
- Never silently invent requirements or claim unverified behavior.
- Resolve routine choices using existing project conventions without unnecessary questions.

### 2. Simplicity first
- Implement only the requested behavior.
- Prefer existing components and platform capabilities.
- Do not add speculative abstractions, configuration, dependencies or features.
- Do not introduce factories, interfaces, wrappers or DI containers for a single trivial use.
- Choose the smallest design that meets the actual requirements.

### 3. Surgical changes
- Every changed line must trace to the requested task.
- Match existing style and preserve unrelated behavior.
- Avoid unrelated refactoring, formatting and cleanup.
- Remove code/imports made unused by your changes.
- Report unrelated dead code without deleting it.
- Preserve security controls and existing test assertions.

### 4. Goal-driven execution
- Define observable success criteria before implementation.
- For multi-step work, give a short plan with a verification check per step.
- For bug fixes, reproduce the failure with a focused regression test when practical.
- Test meaningful behavior and security boundaries, not implementation details.
- Run relevant checks and inspect the final diff.
- Report actual results, including failed, skipped or blocked checks.
- Never claim tests passed unless they were executed successfully.

### 5. Comments explain why
- Comments explain intent, constraints, tradeoffs or non-obvious security decisions.
- Do not narrate code that is already clear.
- Remove redundant comments in code you change.
- Preserve useful protocol references and security invariants.

### 6. Error ownership
- Handle and translate errors once at the owning boundary:
  HTTP handler, CLI entrypoint or background-job runner.
- Internal functions normally propagate errors with safe, useful context.
- Do not catch merely to log and rethrow at every layer.
- Never swallow failures or return success-shaped defaults.
- Local handling is allowed for required cleanup, transaction rollback,
  bounded recovery or a documented domain outcome.
- Cleanup must preserve the original failure.
- Never expose credentials, tokens, PII or internal stack traces publicly.

### 7. File size and responsibilities
- Keep new source files under 300 lines.
- When modifying an existing source file, keep it under 300 lines
  or document a narrowly scoped exception.
- Do not split large unrelated legacy files during a small fix.
- Split by cohesive responsibility before a file grows too large.
- Avoid artificial fragmentation, circular dependencies and generic
  helpers/utils dumping grounds.
- Never compress code or remove useful explanations to meet the limit.
- Generated files, lockfiles and reference documentation are exempt.

### 8. Encapsulation and dependency injection
- Group related state and behavior into cohesive modules or objects.
- Use classes when they clarify state, lifecycle or invariants.
- Keep simple stateless operations as functions.
- Pass external dependencies explicitly, such as storage, mail,
  key services, clocks and randomness, where substitution or testing helps.
- Prefer constructor/function injection over hidden mutable globals.
- Do not introduce a DI framework without a concrete need.
- Use small shared error/async-job wrappers only when multiple real
  call sites share the same boundary policy.
- Wrappers must preserve errors, cancellation, deadlines and transaction context.

### 9. Security takes precedence
- Simplicity never justifies removing validation, ownership checks,
  MFA, rate limits, revocation fences or transaction guarantees.
- Fail closed at sensitive boundaries.
- Do not weaken tests or bypass checks to obtain a green result.
