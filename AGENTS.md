# AI Agent Guidance & Integration Protocol (AGENTS.md)

Welcome, AI coding agent (e.g., Google Antigravity, Claude Code, GitHub Copilot, Cursor, Devin).

This repository contains **SWYRA Auth**, a production-grade, multi-tenant **OAuth 2.1 and OpenID Connect (OIDC)** Identity Provider.

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
   `isDev` governs loopback URI permissions; `isPublic` governs whether the client possesses a secret or has open tenant access. They are independent dimensions.
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

## 🌳 Supported Application Configurations

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

For complete, copy-pasteable, verified code examples, refer directly to [docs/INTEGRATION.md](docs/INTEGRATION.md#6-concrete-framework-integration-recipes):

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
