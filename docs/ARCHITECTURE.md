# SWYRA Auth -- System Architecture (ARCHITECTURE.md)

**Authority:** Normative Technical Architecture & System Design Specification  
**Scope:** SWYRA Auth Core IdP, Security Boundaries, and Multi-Tenant Topology  

---

## 1. System Topology & Infrastructure Layout

SWYRA Auth is structured as a resilient, multi-tier cloud-native identity service:

```
[ User Browser / Consumer Application ]
                 │
                 ▼ HTTPS
┌─────────────────────────────────────────────────────────┐
│              Vercel Edge & Reverse Proxy                │
│  - Static Asset Delivery (React SPA frontend)           │
│  - Edge Rewrites (/api/* -> AWS Lambda Function URL)   │
│  - Gateway Trust Header Injection (x-gateway-secret)    │
└────────────────────────┬────────────────────────────────┘
                         │ HTTPS + x-gateway-secret
                         ▼
┌─────────────────────────────────────────────────────────┐
│               AWS Lambda (Node.js 24)                   │
│  - Hono Framework HTTP Router                           │
│  - Gateway Trust Perimeter Middleware                   │
│  - Better-Auth Core + OAuth 2.1 / OIDC Plugin Engine    │
│  - RS256 JWT Token Minting & JWKS Engine                │
│  - Token Family CAS Rotation Engine                     │
└──────────────┬───────────────────────────┬──────────────┘
               │                           │
               ▼ MongoDB Driver            ▼ HTTP REST
┌─────────────────────────────┐  ┌────────────────────────┐
│      MongoDB Atlas          │  │     Upstash Redis      │
│  - Replica Set              │  │  - Sliding Window      │
│  - user & oauthClient docs  │  │    Rate Limiters       │
│  - user_app_registrations   │  │  - Origin Caching      │
│  - oauth_token_families     │  │                        │
└─────────────────────────────┘  └────────────────────────┘
```

---

## 2. Centralized Authentication Boundary

### The Single IdP Model
All consumer applications—regardless of their ownership, framework, or internal authorization model—rely on SWYRA Auth as the authoritative Identity Provider.

1. **Credentials Terminate at IdP:** User email and password pairs are submitted exclusively to the IdP login interface (`/auth`).
2. **Stateless Authorization Tokens:** Consumer backends receive standard OpenID Connect tokens (`id_token`, `access_token`, `refresh_token`).
3. **No Credential Relay:** Consumer applications never collect or transmit user credentials. The previous architecture of relaying credentials through `/api/auth/app-admin/login` has been retired.

---

## 3. Tenancy Model: Public vs Private Applications

SWYRA Auth implements multi-tenant isolation via the `isPublic` property on the `oauthClient` record:

```
                          OAuth /authorize Request
                                     │
                                     ▼
                        Is user authenticated at IdP?
                                     │
                         ┌───────────┴───────────┐
                        NO                       YES
                         │                        │
                         ▼                        ▼
                Redirect to IdP Login       Is client isPublic?
               (Sign-Up disabled if               │
                client.isPublic=false)   ┌────────┴────────┐
                         │              YES                NO
                         ▼               │                 │
                User authenticates       │                 ▼
                         │               │       Is user in user_app_registrations?
                         └───────────────┘                 │
                                                   ┌───────┴───────┐
                                                  YES              NO
                                                   │               │
                                                   ▼               ▼
                                            Issue Code       302 access_denied
```

### 3.1 Public Applications (`isPublic: true`)
- Open to all authenticated users of the SWYRA platform.
- When an authenticated user authorizes a public application, the IdP automatically records membership in `user_app_registrations` and issues the authorization code.
- Public self-registration is enabled on the IdP login page for public clients.

### 3.2 Private Applications (`isPublic: false`)
- Access is restricted exclusively to pre-authorized organizational users.
- An unauthenticated user hitting `/api/auth/oauth2/authorize` is redirected to the IdP login page (`/auth?is_public=false`), where the **Sign-Up tab is hidden and disabled**.
- Upon authenticating with their IdP account, the OAuth boundary queries `user_app_registrations`:
  - If registered (or user possesses app-admin bypass): OAuth authorization code is issued.
  - If NOT registered: Authorization is immediately denied with HTTP 302 to the consumer callback: `error=access_denied&error_description=Access restricted: Your account is not authorized for this private application`.
- Self-registration API (`POST /api/auth/sign-up/email?client_id=...`) strictly returns HTTP 403 `registration_disabled`.

---

## 4. Administrative Role Hierarchy

SWYRA Auth enforces explicit separation between platform level and application level administrators:

```mermaid
classDiagram
    class User {
        +String id
        +String email
        +String role
        +String scopedClientId
    }

    class GlobalSuperAdmin {
        +role = "super-admin"
        +scopedClientId = null
        +Can create/delete clients
        +Can provision global users
        +Can manage platform config
        +CANNOT enter consumer admin portals
    }

    class ApplicationAdmin {
        +role = "app-admin"
        +scopedClientId = "client-123"
        +Can update own client-123
        +Can view client-123 users
        +CANNOT manage client-456
        +CANNOT access super admin APIs
        +CANNOT access MAuth dashboard
    }

    class EndUser {
        +role = "user"
        +scopedClientId = null
        +Can authenticate to authorized apps
    }

    User <|-- GlobalSuperAdmin
    User <|-- ApplicationAdmin
    User <|-- EndUser
```

### Administrative Claims in Tokens
When an administrator completes the OAuth 2.1 flow for an application:
1. An explicitly assigned application admin receives their scope in the RS256 JWT ID token and UserInfo endpoint:
```json
{
  "sub": "6ac2611c1878f531c3f91a05",
  "email": "admin@tenant.com",
  "role": "admin",
  "scoped_client_id": "client-123"
}
```
2. A super admin signing in to a consumer application receives standard user claims (`role: "user"`, `scoped_client_id: null`) to prevent consumer admin portal access using platform credentials.

---

## 5. Token Lifecycle & Family Revocation Engine

SWYRA Auth implements RFC 6749 Section 10.4 and RFC 6819 refresh token rotation with an atomic Compare-and-Swap (CAS) state machine:

```
[ Active Refresh Token R0 ]
          │
          │ POST /oauth2/token (grant_type=refresh_token)
          ▼
   CAS State Machine:
   - Validates client ownership
   - Marks R0 as consumed
   - Issues new Access Token A1 + new Refresh Token R1
          │
          ├─────────────────────────────────────────────────┐
          ▼                                                 ▼
[ Legitimate Client holds R1 ]                    [ Attacker replays R0 ]
          │                                                 │
          ▼                                                 ▼
Normal subsequent rotation                      REPLAY THEFT DETECTED:
                                                - CAS detects consumed R0
                                                - Cascade Revocation triggers
                                                - Family marked status: "revoked"
                                                - Active tokens A1, R1 purged
                                                - Returns 401 invalid_grant
```

### Invariants:
1. **Per-Client Scoping:** A token family is permanently bound to the `clientId` that created it. Replaying or presenting a token family across client boundaries is rejected (400 `invalid_grant`).
2. **Grace Window:** A strict 2000ms grace window accommodates concurrent in-flight network retries without false-positive family revocation.
3. **Private Tenant Eviction:** When a user is removed from a private application, subsequent refresh token exchanges fail immediately (401 `invalid_grant`), and all active access tokens for that client are invalidated.

---

## 6. Cryptographic Infrastructure (JWKS & PKI)

- **Algorithm:** Strictly `RS256` (RSA Signature with SHA-256). Algorithms `HS256`, `none`, or unpinned algorithms are rejected.
- **Key Storage:** RSA 2048-bit keypairs generated and stored securely in MongoDB collection `oauthKey`.
- **Public Metadata:** JWKS keys published at `/.well-known/jwks.json` and OpenID Discovery at `/.well-known/openid-configuration`.
- **Consumer Offline Verification:** Consumer applications never make per-request network calls to verify tokens. They cache JWKS keys and perform cryptographic verification locally.

---

## 7. Portal Isolation and Session Context Separation

SWYRA Auth cleanly separates the central identity provider console from consumer application sessions:

1. **Independent Consumer App Sessions:**
   Consumer applications run on separate domain origins (such as `app.example.com` or local ports). Each consumer application establishes its own local session cookies or tokens using the OAuth 2.1 code exchange. Logging out of or switching accounts on the central identity provider does not clear unrelated consumer application cookies.
2. **Single Active Identity Provider Context:**
   The central management console on `${AUTH_ISSUER}` maintains exactly one active identity context per browser origin. If a user signed in to a consumer application navigates to `/admin/login`, the interface detects the consumer identity and presents a frictionless account switching banner.
3. **Explicit Account Switching Without Loops:**
   Clicking the account switch action invalidates the current identity provider session and clears form state without redirect loops, allowing the platform Global Super Administrator to sign in cleanly.
4. **Mutually Exclusive Role Boundary:**
   `swyra@auth2.1.com` is the sole platform Global Super Administrator. Application administrators can only manage their explicitly assigned applications through application portal routes, and standard end users possess zero administrative access.

---

## 8. Offline Token Verification and Revocation Latency

1. **Short Lifespan Tokens:**
   Access tokens are signed RS256 JWTs with a maximum lifespan of 15 minutes (900 seconds).
2. **Offline Verification Window:**
   Consumer resource servers verify tokens locally against the cached public key set at `/.well-known/jwks.json`. If you revoke or demote an administrator, downstream resource servers will accept the cryptographically valid token until its 15 minute lifespan expires.
3. **Real Time Mitigation:**
   When high security workflows require immediate revocation, resource servers must query the real time introspection endpoint at `/api/auth/oauth2/introspect`. Central identity provider administrative endpoints query database state and token revocation timestamps on every request, enforcing zero delay revocation.
