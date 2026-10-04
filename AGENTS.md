# AI Agent Guidance & Integration Protocol (AGENTS.md)

Welcome, AI coding agent (e.g., Google Antigravity, Claude Code, GitHub Copilot, Cursor, Devin).

This repository contains **SWYRA Auth**, a production-grade, multi-tenant **OAuth 2.1 and OpenID Connect (OIDC)** Identity Provider.

---

## ⚠️ Mandatory Precedence & Normative Contract

Before writing, modifying, or reviewing any integration code for consumer applications, you **MUST** read and adhere to the authoritative contracts:

👉 **[docs/AI_AGENT_INTEGRATION_CONTRACT.md](file:///home/swyra/projects/OAuth2.1/docs/AI_AGENT_INTEGRATION_CONTRACT.md)** (Normative Integration Specification)  
👉 **[docs/security/integration-policy.json](file:///home/swyra/projects/OAuth2.1/docs/security/integration-policy.json)** (Machine-Readable Integration Policy)  
👉 **[docs/SECURITY_CANONICAL.md](file:///home/swyra/projects/OAuth2.1/docs/SECURITY_CANONICAL.md)** (Normative Security Architecture & Trust Model)

---

## ⚡ The 10 Golden Rules for AI Agents

1. **NEVER create another authentication system when the centralized IdP is already configured.**  
   Consumer applications never install duplicate auth frameworks (Better Auth, NextAuth, Auth.js, Passport, Supabase, Lucia).
2. **NEVER connect a consumer directly to the IdP's MongoDB for normal authentication.**  
   Consumer applications never receive `MONGO_URI`. All communication is over standard HTTP OAuth 2.1 or App-Admin REST endpoints.
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
| OpenID Discovery | `GET` | `/.well-known/openid-configuration` | Returns issuer metadata |
| JWKS Public Keys | `GET` | `/.well-known/jwks.json` | RS256 public keys for offline verification |
| OAuth Authorization | `GET` | `/api/auth/oauth2/authorize` | Browser redirect with PKCE & state |
| Token Exchange / Refresh | `POST` | `/api/auth/oauth2/token` | `grant_type=authorization_code` or `refresh_token` |
| User Profile Info | `GET` | `/api/auth/oauth2/userinfo` | Header `Authorization: Bearer <access_token>` |
| Token Revocation | `POST` | `/api/auth/oauth2/revoke` | Revokes token family or active token |
| App Admin Login | `POST` | `/api/auth/app-admin/login` | `{ client_id, client_secret, email, password }` |
| App Admin Verify | `POST` | `/api/auth/app-admin/verify` | Header `Authorization: Bearer <admin_token>` |
| App Admin Logout | `POST` | `/api/auth/app-admin/logout` | Revokes admin token JTI |

---

## 🌳 Client Type Decision Tree

1. **Confidential vs Public**:
   - Server backend (Next.js BFF, Express, FastAPI, Django): **Confidential Client** (holds `client_secret` server-side).
   - Browser SPA (React, Vue, Vite), mobile app: **Public Client** (PKCE S256 only, NO `client_secret`).
2. **Development vs Production**:
   - Local testing against IdP: **Development Client** (`isDev: true`, loopback `http://localhost:*` permitted).
   - Deployed live workload: **Production Client** (`isDev: false`, strict HTTPS only, no localhost).
3. **Application Access Mode**:
   - `isPublic: true`: Open to all registered platform users.
   - `isPublic: false`: Restricted enterprise tenant (only explicitly provisioned users may log in).
     - *Strategy 1 (Centralized OAuth 2.1)*: Standard OAuth 2.1 Code Flow + PKCE. Users pre-assigned via `POST /api/admin/clients/:clientId/users`. Unassigned users receive 403 `access_denied`.
     - *Strategy 2 (In-App Credential Relay)*: White-labeled login form in consumer app; backend relays `{ client_id, client_secret, email, password }` to `/api/auth/app-admin/login`.
     - Full specification: [docs/AI_AGENT_INTEGRATION_CONTRACT.md § 28](docs/AI_AGENT_INTEGRATION_CONTRACT.md#28-private-application-architecture--dual-strategy-integration-guide-ispublic-false).

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

For complete, copy-pasteable, verified code examples, refer directly to [docs/AI_AGENT_INTEGRATION_CONTRACT.md](file:///home/swyra/projects/OAuth2.1/docs/AI_AGENT_INTEGRATION_CONTRACT.md#27-concrete-framework-integration-recipes):

- **Next.js 14+ (App Router) BFF**: Route handlers for PKCE login, callback, and HttpOnly session cookie storage.
- **Pure React SPA (Vite / CRA)**: In-browser PKCE S256 generation, redirect, token exchange without secrets.
- **React SPA + Python FastAPI**: PyJWKClient offline JWT verification with RS256 algorithm pinning and audience validation.
- **React SPA + Express / Node.js**: `jose` offline JWT verification middleware.
- **Per-Application Admin Portal**: Relaying staff credentials to SWYRA Auth and verifying session tokens.

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
- [ ] `aud` or `client_id` claim in JWT matches consumer `CLIENT_ID`.
- [ ] Consumer application builds cleanly and tests pass.
- [ ] Linter gate passes: `npm run security:integration-check`.
