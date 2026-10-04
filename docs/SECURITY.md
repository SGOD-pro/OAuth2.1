# SWYRA Auth -- Normative Security Architecture & Trust Model (SECURITY.md)

**Status:** NORMATIVE / AUTHORITATIVE SECURITY SPECIFICATION  
**Precedence:** This document defines the non-negotiable security requirements and trust boundaries of SWYRA Auth. In the event of any conflict between this document and consumer application implementations, this document takes absolute precedence.  

---

## 1. Security Philosophy & The Fail-Closed Foundation

Security in SWYRA Auth is designed around three governing axioms:

1. **Fail-Closed by Design:** Any missing credential, unconfigured setting, ambiguous state, or unexpected protocol parameter MUST result in immediate request rejection or server termination.
2. **Zero Consumer Trust:** Consumer applications are external entities. They never receive direct access to IdP user credentials, session tables, or the database.
3. **Defense-in-Depth:** Every authorization decision is verified across multiple layers: network perimeter, gateway trust header, Hono router, Better-Auth core, and MongoDB transactional checks.

---

## 2. Threat Model & Trust Boundaries

```
[ UNTRUSTED ZONE: Browser / Mobile Client / Public Internet ]
                           │
       Boundary 1: TLS 1.3 / Exact HTTPS Redirect URIs
                           ▼
[ DMZ / EDGE: Vercel Reverse Proxy & Edge Router ]
                           │
       Boundary 2: Internal Gateway Secret (x-gateway-secret)
                           ▼
[ TRUSTED CORE: AWS Lambda Function (Hono Router) ]
                           │
       Boundary 3: MongoDB Encrypted Driver & Replica Set
                           ▼
[ PERSISTENCE: MongoDB Atlas Data Store ]
```

### Trust Boundary Definitions
- **Boundary 1 (Edge Perimeter):** Validates TLS certificates, enforces HSTS, drops malformed HTTP frames, and rewrites edge traffic.
- **Boundary 2 (Gateway Trust Perimeter):** Ensures that requests entering the Lambda management surfaces originate exclusively from the authorized API Gateway / reverse proxy via `x-gateway-secret`. Direct internet calls to Lambda URLs fail closed (403 `forbidden`).
- **Boundary 3 (Storage Isolation):** User credentials, session tokens, and refresh token families are stored exclusively within the IdP database. Consumer applications never receive database credentials.

---

## 3. Normative Security Invariants (P0 Guarantees)

### 3.1 Zero Credential Exposure
- Consumer applications MUST NEVER collect, render input forms for, handle, proxy, transmit, or store IdP user passwords.
- The previous credential-relay pattern (`/api/auth/app-admin/login`) is strictly deprecated and forbidden for consumer authentication.
- All user authentication terminates at the centralized IdP login interface (`/auth`).

### 3.2 Mandatory PKCE S256 & Endpoint Integrity
- All browser authorization code flows target the canonical endpoint `/api/auth/oauth2/authorize` (never internal UI routes).
- Every authorization request to `/api/auth/oauth2/authorize` MUST include `code_challenge` and `code_challenge_method=S256`.
- Plain PKCE (`code_challenge_method=plain`) is strictly rejected at the OAuth boundary.
- During token exchange, the consumer must supply the exact `code_verifier`. Replay of codes or incorrect verifiers fails immediately (400 `invalid_grant`).

### 3.3 Strict Redirect URI Exact Matching
- Redirect URIs are matched using strict, full string equality against registered entries.
- Wildcards (`*`), path traversals (`/..`), regex patterns, and query string injections are strictly forbidden.
- Localhost URIs (`http://localhost:*`, `http://127.0.0.1:*`) are permitted **ONLY** when `isDev: true`. Production clients (`isDev: false`) fail closed if a loopback URI is supplied.

### 3.4 Cryptographic State Parameter
- Every authorization request MUST include a cryptographically random `state` parameter generated with at least 128 bits of entropy.
- The consumer application MUST verify that the `state` received in the callback matches the `state` initiated in the session.

### 3.5 Token Family Rotation & Replay Protection
- Refresh tokens rotate atomically on every exchange.
- Replaying a previously consumed refresh token triggers immediate **Cascade Revocation**, revoking the entire token family and invalidating all active access tokens for that user/client combination.
- Token families are strictly scoped to the `clientId` that created them. Cross-client token exchange or introspection attempts fail closed.

### 3.6 Offline Cryptographic Verification & Algorithm Pinning
- Consumer applications verify JWT signatures offline against the IdP's JWKS (`/.well-known/jwks.json`).
- Consumer JWT verifiers MUST pin the signing algorithm strictly to `RS256`. Algorithms `none`, `HS256`, or unpinned configurations are strictly forbidden.
- The consumer MUST validate that `iss === AUTH_ISSUER` and `aud === CLIENT_ID`.

---

## 4. Multi-Tenant Private Application Security

When `isPublic = false`, the application is an enterprise tenant:
1. **No Public Self-Registration:** Unauthenticated users hitting `/oauth2/authorize` are directed to IdP login with `is_public=false`, which hides and disables the Sign-Up tab. Direct sign-up API calls return 403 `registration_disabled`.
2. **Pre-Authorization Requirement:** Authentication alone does not grant access. The IdP verifies that the authenticated user ID is explicitly present in `user_app_registrations` for that `clientId`.
3. **Instant Eviction on De-Provisioning:** If a user is removed from `user_app_registrations`, their existing refresh token family is immediately revoked, and subsequent refresh requests return 401 `invalid_grant`.

---

## 5. Administrative Authorization Separation

- **Super Administrator (`role: "admin"`, `scopedClientId: null`):** Authorized to manage global platform resources, register new clients, and provision administrators.
- **Application Administrator (`role: "admin"`, `scopedClientId: "<clientId>"`):** Authorized to manage only their designated client. Scoped administrators cannot:
  - Modify or view other clients (Cross-Tenant Access Forbidden).
  - Mutate security boundary flags (`isDev`, `isPublic`).
  - Delete their application or any other application.
  - Access Super-Admin endpoints.

---

## 6. Automated Security Validation Suite

SWYRA Auth maintains an automated continuous security test gate consisting of 15 blocking test suites:

| Suite Name | Test Script | Verified Security Properties |
|---|---|---|
| **Client Mode Transition** | `npm run test:client-mode-transition` | Atomic dev/prod transitions, loopback URI lockdown, flag immutability |
| **Cross-Client Refresh Matrix** | `npm run test:cross-client-refresh` | Token family CAS concurrency, cross-client substitution defenses, grace windows |
| **Adversarial Master Gate** | `npm run test:full-adversarial` | Comprehensive penetration matrix against token replay and code theft |
| **Final Adversarial Gate** | `npm run test:security-gate` | Rigorous privilege injection, CSRF evasion, and scope-tampering tests |
| **Direct Backend Access** | `npm run test:direct-backend` | Gateway perimeter enforcement (`x-gateway-secret`), direct URL blocking |
| **Session Hijacking** | `npm run test:session-hijack` | Multi-tab isolation, cookie tampering, cross-origin state poisoning |
| **OAuth Transaction** | `npm run test:oauth-tx` | Code substitution, multi-tab transaction isolation, verifier binding |
| **Credential Compromise** | `npm run test:credential-comp` | Password invalidation, JWT revocation, token family revocation |
| **Cross-Tenant Matrix** | `npm run test:cross-tenant` | Isolation between tenants A, B, and C under adversarial load |
| **Prod vs Dev** | `npm run test:prod-vs-dev` | Strict environment flag enforcement and loopback boundary rules |
| **Deployed Consumer** | `npm run test:deployed-consumer` | Live HTTPS verification, fail-closed callback checks against live IdP |
| **AWS Dashboard Integration** | `npm run test:aws-dashboard` | Real-world consumer app integration and role-claim validation |
| **App Management Auth** | `npm run test:app-mgmt-auth` | Scoped vs Super Admin authorization decisions and audit logging |
| **E2E OIDC Interop** | `npm run test:oidc-interop` | Full OIDC compliance, PKCE S256, JOSE remote JWKS verification |
| **Private App OAuth** | `npm run test:private-oauth` | Private tenant login flow, registration disabled, assignment enforcement |

Execute all security suites:
```bash
npm run test:all-security
```
