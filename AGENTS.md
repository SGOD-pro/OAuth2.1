# AI Agent Guidance & Integration Protocol (AGENTS.md)

Welcome, AI coding agent (e.g., Google Antigravity, Claude Code, GitHub Copilot, Cursor, Devin).

This repository contains **SWYRA Auth**, a production-grade, multi-tenant **OAuth 2.1 and OpenID Connect (OIDC)** Identity Provider.

---

## ⚠️ Mandatory Precedence & Normative Contract

Before writing, modifying, or reviewing any integration code for consumer applications, you **MUST** read and adhere to the authoritative contracts:

👉 **[docs/SECURITY_CANONICAL.md](file:///home/swyra/projects/OAuth2.1/docs/SECURITY_CANONICAL.md)** (Normative Security Architecture & Trust Model)  
👉 **[docs/AI_AGENT_INTEGRATION_CONTRACT.md](file:///home/swyra/projects/OAuth2.1/docs/AI_AGENT_INTEGRATION_CONTRACT.md)** (Normative Integration Specification)

---

## ⚡ The 7 Non-Negotiable Agent Rules

1. **NEVER connect to or query the SWYRA Auth MongoDB database.**  
   Consumer applications never touch `MONGO_URI`. All communication is over standard HTTP OAuth 2.1 or App-Admin REST endpoints.
2. **NEVER install duplicate authentication engines in consumer apps.**  
   Do NOT install Better Auth, NextAuth / Auth.js, Passport.js, Supabase Auth, or Lucia inside the consumer repository. Use lightweight OAuth or JWT validation libraries (`jose`, `pyjwt`, `requests`, `fetch`).
3. **NEVER redirect authorization requests to `/auth`.**  
   The OAuth 2.1 authorization endpoint is **`/api/auth/oauth2/authorize`**. The path `/auth` is an internal IdP frontend Single-Page Application route.
4. **NEVER expose `client_secret` to client-side code.**  
   Do not prefix secrets with `NEXT_PUBLIC_`, `VITE_`, or commit them to public repos. Public clients (SPAs) do NOT use secrets; confidential clients (Node, Python, Go backends) keep secrets in server-only environment variables.
5. **ALWAYS use PKCE (`code_challenge` + `code_verifier`) and `state`.**  
   OAuth 2.1 mandates PKCE for all authorization flows. Always pass `code_challenge_method=S256` and cryptographically random `state`.
6. **ALWAYS validate Access Tokens offline using the JWKS endpoint.**  
   Backend APIs and resource servers must verify RS256 JWTs offline against `${AUTH_ISSUER}/.well-known/jwks.json`. Always verify `iss`, `aud` (matching consumer `CLIENT_ID`), and `exp`.
7. **Maintain clean separation of concerns.**  
   Do not rewrite the consumer app's database schema or business tables. Reference the user solely by their permanent subject identifier (`sub` claim) from the token.

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

## 📋 Integration Recipes Index

For complete, copy-pasteable, verified code examples, refer directly to [docs/AI_AGENT_INTEGRATION_CONTRACT.md](file:///home/swyra/projects/OAuth2.1/docs/AI_AGENT_INTEGRATION_CONTRACT.md#8-concrete-integration-recipes):

- **Next.js 14+ (App Router) BFF**: Route handlers for PKCE login, callback, and HttpOnly session cookie storage.
- **Pure React SPA (Vite / CRA)**: In-browser PKCE S256 generation, redirect, token exchange without secrets.
- **React SPA + Python FastAPI**: PyJWKClient offline JWT verification with RS256 algorithm pinning and audience validation.
- **React SPA + Express / Node.js**: `jose` offline JWT verification middleware.
- **Per-Application Admin Portal**: Relaying staff credentials to SWYRA Auth and verifying session tokens.

---

## ✅ Phase 20 Verification Checklist

Before declaring your integration task complete, verify every item:
- [ ] No `MONGO_URI` or direct DB access in consumer codebase.
- [ ] No duplicate auth frameworks installed in consumer dependencies.
- [ ] Authorization redirect uses `/api/auth/oauth2/authorize` (NOT `/auth`).
- [ ] PKCE `code_challenge` (`S256`) and `state` are supplied and validated.
- [ ] `client_secret` is strictly server-side and never exposed to browser bundles.
- [ ] RS256 JWTs are validated offline via `/.well-known/jwks.json`.
- [ ] `aud` or `client_id` claim in JWT matches consumer `CLIENT_ID`.
- [ ] Consumer application builds cleanly and tests pass.
