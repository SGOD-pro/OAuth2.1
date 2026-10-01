# SWYRA Auth Canonical Security Architecture & Specification (SECURITY_CANONICAL.md)

> **Document Status**: NORMATIVE / AUTHORITATIVE  
> **Classification**: Single Source of Truth for SWYRA Auth Identity Provider Architecture  
> **Last Reconciled**: 2026-10-02  
> **Master Gate**: `npm run test:all-security` (14 Blocking Suites)  
> **Consistency Gate**: `npm run security:docs-check`

---

## 1. Ground Truth & Precedence Hierarchy

Every security claim in this repository is governed strictly by the following normative hierarchy of truth:

1. **Runtime Security-Critical Code** (`backend/src/`): The authoritative enforcement point for all authentication, authorization, token operations, and perimeter gateways.
2. **Executable Security Test Suites** (`backend/tests/security/`): The executable proof of security invariants. If documentation disagrees with test assertions, documentation MUST be reconciled to reflect verified reality.
3. **Deployment Configuration & Schemas** (`backend/src/config/`, CloudFormation, environment definitions): The physical boundary rules.
4. **Canonical Security Specification** (`docs/SECURITY_CANONICAL.md`): This document. The single authoritative textual standard for architecture, threat models, and authorization semantics.
5. **Supporting Documentation** (`README.md`, `ARCHITECTURE.md`, `ADMIN_GUIDE.md`, `CONFIGURATION.md`, `ENVIRONMENT_VARIABLES.md`, `INTEGRATION_GUIDE.md`, `AGENTS.md`): Derived explanatory documents referencing this canonical model.
6. **Historical Audit & Investigation Artifacts** (`docs/SECURITY_REVIEW.md`, `docs/SECURITY_INVESTIGATIONS.md`, `docs/SECURITY_REMEDIATION_PLAN.md`): Labeled `HISTORICAL / NON-NORMATIVE`. They document point-in-time investigations and must never contradict this canonical specification.

---

## 2. Canonical Terminology Model

To eliminate architectural drift, all components must be described using these exact canonical terms:

| Term | Definition & Security Invariants |
|---|---|
| **Identity Provider (IdP)** | The centralized multi-tenant authentication and token issuance engine. Runs strictly in `NODE_ENV=production`. Enforces strict HTTPS, cookie security, CSRF protection, and rate limiting. |
| **Production Client (`isDev=false`)** | An OAuth 2.1 client registered for live user-facing workloads. **Strict Rule**: Requires public FQDNs with HTTPS. NEVER permits `localhost`, `127.0.0.1`, `[::1]`, or private IP ranges. |
| **Development Client (`isDev=true`)** | An OAuth 2.1 client registered on the production IdP specifically for local consumer software development. **Strict Rule**: Strictly restricted to local loopback addresses (`http://localhost:*`, `http://127.0.0.1:*`, `http://[::1]:*`). Strictly rejects private RFC1918 IPs (`10.x`, `192.168.x`, `172.16.x`), link-local (`169.254.x`), external domains, and spoofed hostnames (`localhost.evil.com`). |
| **Public Client (`isPublic=true`)** | Single-Page Applications (SPA), mobile apps, or native clients. Does NOT hold or transmit a `client_secret`. Strictly mandated to use OAuth 2.1 Authorization Code Flow with PKCE (`S256`) and cryptographically random `state`. |
| **Confidential Client (`isPublic=false`)** | Server-side backend services (Node.js, FastAPI, Go, Java). Holds a high-entropy `client_secret`. Authenticates during token exchange via HTTP Basic Auth or secure POST body over TLS. |
| **Super Admin** | Platform operator account having `user.role === "admin"` and `user.scopedClientId == null`. Has global administrative authority: client creation, client deletion, global user management, and platform audit log access. |
| **Scoped Admin** | Delegated client administrator account having `user.role === "admin"` and `user.scopedClientId !== null`. Restricted strictly to managing non-privileged configuration of their own assigned application. Cannot create/delete apps, cannot manage other tenants, and cannot access platform logs or stats. |
| **App Admin** | Delegated application staff credentials stored in the `app_admins` collection. Authenticates via `/api/auth/app-admin/login` to obtain a scoped, JTI-tracked administrative JWT. Strictly denied access to platform `/api/admin/*` routes. |

---

## 3. Perimeter & Conjunctive Gateway Trust Boundary

SWYRA Auth runs on serverless compute (AWS Lambda / Vercel Serverless) where direct URLs may be accessible. To prevent perimeter bypass:

```
[ INTERNET ]
     |
     v
[ API GATEWAY / REVERSE PROXY / WAF ]
     |  Injects: x-gateway-secret: <INTERNAL_GATEWAY_SECRET>
     v
[ SWYRA AUTH BACKEND ]
     |
     +---> Management Perimeter: requireGatewayTrust
     |       1. Gateway Secret Verified? (timing-safe equal) ---> NO  --> 403 Forbidden
     |       2. Admin Session Active? --------------------------> NO  --> 401 Unauthorized
     |       3. User Role === 'admin'? -------------------------> NO  --> 403 Forbidden
     |       4. Scoped/Super Admin Authorization Checks --------> NO  --> 403 Forbidden
     |       5. Authorized Mutation & Audit Log
     |
     +---> Public Protocol Surface (/oauth2/authorize, /token, /userinfo, /.well-known/*)
             Intentionally public protocol surface; exempted from gateway secret;
             protected by TLS, PKCE, CORS, and per-IP rate limiting.
```

### Conjunctive Trust Invariants
The trust boundary for management endpoints is **conjunctive** (`GATEWAY AND SESSION AND ROLE`), never substitutive:
1. **GATEWAY-1**: Direct Lambda URL + Valid Admin Session + No Gateway Secret $\rightarrow$ **HTTP 403 Forbidden**.
2. **GATEWAY-2**: Direct Lambda URL + Valid Gateway Secret + No Admin Session $\rightarrow$ **HTTP 401 Unauthorized**.
3. **GATEWAY-3**: Valid Gateway Secret + Valid Super Admin Session $\rightarrow$ **HTTP 200 OK**.
4. **GATEWAY-4**: Forged Gateway Secret + Any Session $\rightarrow$ **HTTP 403 Forbidden**.
5. **GATEWAY-5**: Valid Gateway Secret + Scoped Admin Session targeting other client $\rightarrow$ **HTTP 403 Forbidden**.

---

## 4. Canonical Management Authorization Lifecycle

All management mutations follow this exact 10-step pipeline:

```
 1. Resolve request context & client IP
 2. Verify gateway secret header (x-gateway-secret / x-internal-secret)
 3. Authenticate session via HttpOnly cookie
 4. Verify user platform role (role === "admin")
 5. Determine administrative scope (isSuperAdmin vs requireScopedAdmin)
 6. Enforce temporary password change requirements (mustChangePassword)
 7. Resolve target application identity (resolveOAuthClient)
 8. Enforce tenant isolation boundary (canonicalTargetId === scopedClientId)
 9. Validate configuration payload against mode policy (isDev loopback vs prod HTTPS)
10. Atomic database mutation + audit log entry (recordAdminAudit)
```

---

## 5. Client Mode Policy & Transition Rules

The production IdP accommodates both production and local development consumer applications under strict security controls:

### Development Clients (`isDev=true`)
- Can only be created or modified by an authenticated Super-Admin.
- Permitted redirect URIs & origins:
  - `http://localhost:*`
  - `http://127.0.0.1:*`
  - `http://[::1]:*`
- Strictly rejected:
  - Non-loopback IPs (e.g. `10.0.0.1`, `192.168.1.1`, `172.16.0.1`)
  - Link-local addresses (`169.254.x.x`)
  - Spoofed hostnames (`http://localhost.evil.com`, `http://127.0.0.1.evil.com`)
  - Remote public domains (`https://external.example.com`)
  - Wildcard domains or paths

### Production Clients (`isDev=false`)
- Permitted redirect URIs & origins:
  - Valid public FQDNs with `https://`
- Strictly rejected:
  - Any loopback address (`localhost`, `127.0.0.1`, `[::1]`)
  - Plaintext `http://` (RFC 8252 exceptions apply only to native dev loopback)
  - Wildcard hostnames or scheme wildcards

### Mode Transitions
- **Dev $\rightarrow$ Prod Transition**: Requires Super-Admin authorization and **MUST remove all localhost/loopback URIs and origins**. Transition attempts containing remaining localhost entries are rejected with HTTP 400.
- **Prod $\rightarrow$ Dev Transition**: Restricted to Super-Admins; all URIs must conform to strict loopback constraints.
- **Field Independence**: Changes to `isDev` do not mutate `isPublic` or `application_type`. Public and confidential classifications remain strictly independent.

---

## 6. Refresh Token Family Security & CAS Rotation

SWYRA Auth implements RFC 6749 and OAuth 2.1 draft specifications for refresh token rotation:

1. **Token Family Pinning**: Every refresh token belongs to a cryptographically unique `familyId` bound strictly to a `clientId` and `userId`.
2. **Fail-Closed Client Ownership**: When a token refresh request arrives:
   ```typescript
   if (existingFamily && (!existingFamily.clientId || existingFamily.clientId !== canonicalClientId)) {
       return 400 invalid_grant;
   }
   ```
   A family missing client ownership metadata immediately fails closed; cross-client callers cannot rotate or inspect other clients' families.
3. **Atomic Compare-and-Swap (CAS)**:
   Rotation claims are executed atomically in MongoDB:
   ```typescript
   db.collection("oauth_token_families").updateOne(
       {
           _id: doc._id,
           activeTokenHash: incomingHash,
           status: "active",
           clientId: canonicalClientId
       },
       {
           $push: { consumedTokenHashes: incomingHash },
           $set: { activeTokenHash: newHash, updatedAt: new Date() }
       }
   );
   ```
4. **Deterministic Replay Grace Window (2000ms)**:
   - Request presenting previously consumed token within $0 \le t < 2000\text{ ms}$ of legitimate rotation: Treated as a benign in-flight concurrent network race. Loser request is rejected as consumed; active winner family remains intact.
   - Request presenting previously consumed token at $t \ge 2000\text{ ms}$: Treated as token theft replay attack. **Immediate cascade revocation** of entire token family, purging all access and refresh tokens for that subject.

---

## 7. The 7 Non-Negotiable Rules for Consumer Applications

Consumer applications integrating with SWYRA Auth MUST adhere to these rules:

1. **NEVER connect to or query the SWYRA Auth MongoDB database.** All interaction occurs via standard OAuth 2.1 / OIDC or App-Admin HTTP endpoints.
2. **NEVER install duplicate authentication engines in consumer apps.** Do NOT install Better Auth, NextAuth/Auth.js, Passport, or Supabase Auth in consumer apps. Use lightweight JWT/JWKS verification (`jose`, `pyjwt`).
3. **NEVER redirect authorization requests to `/auth`.** The OAuth 2.1 authorization endpoint is `/api/auth/oauth2/authorize`.
4. **NEVER expose `client_secret` to client-side code.** Public clients (SPAs) do not have secrets. Confidential backends keep secrets in server-only environment variables.
5. **ALWAYS use PKCE (`code_challenge` + `code_verifier`) and `state`.** OAuth 2.1 mandates PKCE for all authorization flows.
6. **ALWAYS validate Access Tokens offline using the JWKS endpoint.** Resource servers verify RS256 JWTs against `${AUTH_ISSUER}/.well-known/jwks.json`, checking `iss`, `aud`, and `exp`.
7. **Maintain clean separation of concerns.** Reference users solely by their permanent subject identifier (`sub` claim).

---

## 8. Master Security Gate & Verification Matrix

The repository executes 14 blocking security test suites via `npm run test:all-security`:

| # | Suite Name | Primary Focus |
|---|---|---|
| 1 | `test-client-mode-transition` | Client mode transitions, dev loopback rules, prod HTTPS requirements |
| 2 | `cross-client-refresh-matrix` | Refresh token isolation, CAS atomicity, replay detection |
| 3 | `full-production-adversarial-suite` | Adversarial penetration vectors and production environment validation |
| 4 | `final-adversarial-gate` | Master 28-point gate: isolation, scoped admin restrictions, CSRF |
| 5 | `direct-backend-access-suite` | Gateway boundary (GATEWAY-1 to 5), direct Lambda isolation, curl access |
| 6 | `session-hijacking-suite` | Session theft, password rotation invalidation, deactivation |
| 7 | `oauth-transaction-suite` | Multi-tab transaction isolation, state CAS, code single-use |
| 8 | `credential-compromise-suite` | Blast radius containment for leaked user/admin credentials |
| 9 | `cross-tenant-matrix` | Multi-tenant database partitioning and cross-app isolation |
| 10 | `production-vs-development-suite` | Strict production vs dev loopback redirect validation |
| 11 | `deployed-consumer-suite` | Live IdP validation and deployed consumer app integration |
| 12 | `aws-dashboard-integration-suite` | AWS Dashboard consumer client authorization code and token flows |
| 13 | `test-app-management-auth` | Strict admin session requirements for app create/update/delete |
| 14 | `e2e-oidc-interop` | OpenID Connect discovery, RS256 token signing, and JWKS verification |

---

## 9. Automated Documentation Consistency Gate

Any modifications to code, routes, test suites, or documentation are validated using:

```bash
npm run security:docs-check
```

This gate enforces that:
- All required canonical documents and manifests exist.
- `package.json` test scripts match `docs/security/security-suite-manifest.json`.
- `test:all-security` includes all blocking suites.
- Terminology across all markdown files adheres to this canonical standard.
- Environment variables in documentation match `src/config/schema.ts`.
- Route descriptions match `docs/security/security-route-manifest.json`.
