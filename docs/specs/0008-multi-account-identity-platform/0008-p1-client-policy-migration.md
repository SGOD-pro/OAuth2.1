# 0008-P1. Client policy migration and open access without membership

**Status:** In Progress (Slice P1a verified; Slices P1b and P1c pending)
**Date:** 2026-11-22

## Summary

This specification defines the migration of OAuth client configurations to independent dimensions for OAuth V2. It separates the initial work into slice P1a, focused on classification and a read only inventory, followed by later enforcement and user interface slices. Slice P1a preserves existing runtime behavior while establishing clean mapping rules from legacy flags to independent client authentication types and access policies. Conflicting, partial, invalid, or uncertain client records are flagged for administrative review without guessing or mutating database documents. Later slices enforce PKCE S256 for public clients, client bound refresh token rotation, strict development environment validation with native loopback port exceptions, and the elimination of ambient membership writes for open applications.

## Context

Legacy SWYRA Auth used a single boolean field named `isPublic` to govern two orthogonal properties. First, it determined client authentication capability, meaning whether an OAuth client is a public client such as a single page browser application or a confidential client that can protect a client secret. Second, it determined user access policy, meaning whether an application is open to any authenticated user or private to an enterprise tenant requiring assigned membership.

This coupling creates security and operational gaps. An open consumer application might run on a server and require confidential client authentication with a client secret. Conversely, an enterprise tenant application might run as a public mobile application or single page application while requiring strict private membership. Furthermore, development mode was tied to `isDev`, but legacy systems sometimes conflated development settings with public client status.

To address these limitations safely, the migration is structured into distinct, reviewable increments. Slice P1a introduces the independent dimension model, mapping rules, and a read only inventory scanner while leaving runtime authorization behavior completely untouched. Slice P1b activates runtime enforcement and the open access membership gate once legacy records are audited. Slice P1c provides updated administrative interface controls.

Existing administrative trust boundaries must remain intact throughout this migration. Platform super admins alone may view full client inventories and alter client policy dimensions. Furthermore, platform super admins must remain strictly excluded from accessing private consumer applications, even if an explicit membership row exists in the database.

## Requirements

**User stories:**
- As a platform administrator, I want to classify OAuth clients by their actual authentication capability (`public` or `confidential`) and access policy (`open` or `private`) independently so that client security matches application architecture.
- As a platform operator, I want to run a read only audit script in slice P1a that flags ambiguous or uncertain legacy client records so that I can remediate them before changing runtime access rules.
- As an end user, I want to sign in to open applications without being forced into an ambient membership record in `user_app_registrations`.
- As an enterprise tenant owner, I want private applications to strictly enforce active membership across authorization, code exchange, token refresh, and online validation so that revoked users are denied immediately.
- As a security auditor, I want platform super admins excluded from private consumer applications so that administrative credentials never leak into tenant scopes.

**Acceptance criteria for Slice P1a (Classification and Read Only Inventory):**
- **AC-P1A-01 (Traceable to umbrella 0008 AC-05):** The policy resolver classifies every combination of `clientType`, `accessPolicy`, and `isDev` deterministically.
- **AC-P1A-02 (Traceable to umbrella 0008 AC-05):** The read only inventory script inspects all clients in `oauthClient` and reports counts and lists for migrated, compatible open public, compatible private confidential, compatible open confidential, compatible private public, and ambiguous records with zero database writes.
- **AC-P1A-03 (Traceable to umbrella 0008 AC-05):** Legacy mapping rules map `isPublic: true` to `accessPolicy: "open"` and `isPublic: false` to `accessPolicy: "private"`. Client authentication type is derived from verified registration metadata, specifically the presence of a valid client secret and token endpoint authentication method.
- **AC-P1A-04 (Traceable to umbrella 0008 AC-05):** Conflicting, partial, invalid, or uncertain records, including missing redirect URIs, invalid URL schemes, URI fragments, wildcard domains, or conflicting boolean fields, are classified as ambiguous and flagged for administrative review without guessing.
- **AC-P1A-05:** Runtime behavior in Slice P1a remains completely unchanged. Existing authorization code flows, consent checks, token exchanges, and membership writes continue executing their established logic.

**Acceptance criteria for Later Slices (Enforcement and UI):**
- **AC-P1B-01 (Traceable to umbrella 0008 AC-06):** When open application membership bypass is enabled by configuration (`OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=true`), eligible authenticated users authorize and consent to open applications without inserting records into `user_app_registrations`.
- **AC-P1B-02 (Traceable to umbrella 0008 AC-06):** Ambient membership writes for open applications are removed from password login (`/sign-in/email`), signup (`/sign-up/email`), social login callbacks, and multi factor authentication continuation when the open access gate is active.
- **AC-P1B-03 (Traceable to umbrella 0008 AC-05):** Better Auth and custom runtime wrappers enforce client authentication types. Public clients must omit client secrets and supply PKCE S256 code challenges on authorization and code verifiers on token exchange. Confidential clients must authenticate using valid credentials and enforce PKCE S256 code verifiers on authorization code flows per OAuth 2.1 Section 4.1.1.
- **AC-P1B-04:** Public clients executing token refresh (`grant_type=refresh_token`) use client bound refresh token rotation without requiring a PKCE verifier per RFC 6749 Section 6. Replayed refresh tokens trigger immediate family revocation (`status: "revoked"`).
- **AC-P1B-05:** Native clients (`application_type: "native"`) and development mode clients (`isDev: true`) allow ephemeral variable ports on loopback IP literals (`127.0.0.1`, `[::1]`) per RFC 8252 Section 7.3, while `localhost` is supported for developer tool compatibility per RFC 8252 Section 8.3. Non native production clients strictly forbid loopback URIs and strictly require exact HTTPS redirect URIs.
- **AC-P1B-06:** Platform super admin accounts are strictly excluded from private consumer applications across all authorization checks, even if a record exists in `user_app_registrations` or `app_admins`.
- **AC-P1B-07 (Traceable to umbrella 0008 AC-14):** Existing consumer protocol endpoints (`/api/auth/oauth2/*`) and offline RS256 token verification against JWKS remain fully compatible. Zero direct database access is granted to consumers.
- **AC-P1B-08:** Token introspection strictly requires confidential client authentication, verifies calling client policy, verifies user account eligibility, and validates active private application membership when the token audience is private. Revoked private access returns `{ active: false }`.
- **AC-P1C-01:** Frontend administrative modals (`RegisterAppModal.tsx`, `EditAppModal.tsx`) provide explicit independent selectors for Client Type (`Public`, `Confidential`) and Access Policy (`Open`, `Private`).
- **AC-P1C-02:** Client listing (`GET /api/admin/clients`) remains restricted to super admins only. Client policy updates require verified super admin authority.

## Options considered

### Option 1: Direct in place database rewrite

Run a migration script that updates all documents in `oauthClient` immediately, guessing missing fields from heuristics.

**Pros:**
- Rapidly populates new schema fields in one step.

**Cons:**
- High risk of misclassifying enterprise clients and exposing private tenant data.
- Mutates live database records without human verification.
- Breaks backward compatibility if older backend instances are running during rolling deployment.

### Option 2: Phased migration with read only audit inventory and runtime fallback (Chosen)

Divide the work into P1a (classification and read only audit), P1b (runtime enforcement and open access gate), and P1c (administrative user interface). Legacy records remain unchanged in P1a. In P1b, a feature flag gates the removal of membership writes. Ambiguous records fail closed until explicitly updated by a super admin.

**Pros:**
- Completely safe and non destructive.
- Zero guessing on ambiguous or uncertain records.
- Enables thorough operator review before any runtime behavior changes.
- Safe instant rollback by toggling the open access configuration switch.

**Cons:**
- Requires maintaining fallback compatibility logic during the transition window.
- Requires manual administrative review for ambiguous records.

### Option 3: Dual client registry collections

Create a separate MongoDB collection for V2 clients and maintain the legacy collection in parallel.

**Pros:**
- Complete isolation between legacy and modern client models.

**Cons:**
- Heavy code duplication across authentication and administrative routes.
- Dual maintenance of caches, indexes, and credentials.
- Confusing operational model for client management.

## Decision

**Chosen option**: Option 2: Phased migration with read only audit inventory and runtime fallback.

We divide the client policy migration into three focused phases:
1. **Slice P1a (Current task):** Define independent client dimensions, deterministic mapping rules, runtime compatibility resolver, and a read only audit script (`backend/scripts/audit-client-policies.ts`). Runtime behavior is preserved.
2. **Slice P1b (Next backend slice):** Introduce the open access configuration gate (`OPEN_APP_MEMBERSHIP_BYPASS_ENABLED`), remove ambient membership writes in login and signup flows, enforce PKCE S256 on public clients, enforce client bound refresh rotation, and enforce strict super admin exclusion from private apps.
3. **Slice P1c (Frontend slice):** Update administrative client registration and editing modals to manage independent dimensions.

**Implementation skills**: None.

## Rationale

Option 2 strictly follows the core engineering principles in root AGENTS.md. It avoids speculative guessing, preserves private tenant security boundaries, and prevents downtime. Operating slice P1a as a read only audit tool provides platform operators with complete visibility into legacy client configurations before changing runtime access rules.

Option 1 was rejected because automatic guessing creates severe security hazards if a private client is mistakenly classified as open. Option 3 was rejected because maintaining two client registries adds unnecessary complexity and violates the rule of simplicity.

## Feature design

### Data model sketch

The MongoDB collection `oauthClient` receives additive, optional fields. Legacy fields remain intact for backward compatibility:

```typescript
export interface OAuthClientPolicyFields {
  // V2 explicit independent dimensions
  clientType?: "public" | "confidential";
  accessPolicy?: "open" | "private";
  isDev?: boolean;

  // Migration provenance metadata
  policyVersion?: number;
  policyMigratedAt?: Date;
  policyMigratedBy?: string;

  // Legacy fields (retained for backward compatibility)
  isPublic?: boolean;
  is_public?: boolean;
  is_dev?: boolean;
  clientSecret?: string;
  client_secret?: string;
  redirectUris?: string[];
  redirect_uris?: string[];
  allowedOrigins?: string[];
  allowed_origins?: string[];
}
```

### Deterministic mapping rules and classification matrix (Slice P1a)

When inspecting or resolving a client document from MongoDB, the policy resolver applies the following precedence:

1. **Explicit V2 fields (Status: Migrated):**
   If both `clientType` and `accessPolicy` are explicitly set on the document, and the client passes full validation (valid redirect URIs, matching credentials, and zero conflicting metadata), the client is classified as `MIGRATED`. If validation fails or conflicting metadata remains, it is classified as `AMBIGUOUS`. The explicit values are used directly once validated.

2. **Clean Class A (Compatible Open Public Client):**
   - Explicit fields missing.
   - Legacy `isPublic: true` (or `is_public: true`).
   - No client secret present (neither `clientSecret` nor `client_secret` exists, or both are null or empty strings).
   - Valid redirect URIs registered.
   - Inferred policy: `clientType: "public"`, `accessPolicy: "open"`, `isDev: Boolean(isDev || is_dev)`.

3. **Clean Class B (Compatible Private Confidential Client):**
   - Explicit fields missing.
   - Legacy `isPublic: false` (or `is_public: false`).
   - Valid client secret present.
   - Valid redirect URIs registered.
   - Inferred policy: `clientType: "confidential"`, `accessPolicy: "private"`, `isDev: Boolean(isDev || is_dev)`.

4. **Clean Class C (Compatible Open Confidential Client):**
   - Explicit fields missing.
   - Legacy `isPublic: true` (or `is_public: true`).
   - Valid client secret present.
   - Valid redirect URIs registered.
   - Inferred policy: `clientType: "confidential"`, `accessPolicy: "open"`, `isDev: Boolean(isDev || is_dev)`.
   - Note: Represents server side web applications that authenticate to the IdP with a secret while remaining open to all platform users.

5. **Clean Class E (Compatible Private Public Client):**
   - Explicit fields missing.
   - Legacy `isPublic: false` (or `is_public: false`).
   - No client secret present.
   - Valid redirect URIs registered.
   - Inferred policy: `clientType: "public"`, `accessPolicy: "private"`, `isDev: Boolean(isDev || is_dev)`.
   - Note: Represents enterprise mobile applications or single page applications that cannot hold a secret but restrict access to assigned tenant members.

6. **Ambiguous Class D (Requires Administrative Remediation):**
   Any client record exhibiting conflicting, partial, invalid, or uncertain attributes:
   - Case D1: Contradictory boolean flags, such as `isPublic === true` and `is_public === false`, or `isDev === true` and `is_dev === false`.
   - Case D2: Missing, empty, or non array `redirectUris`.
   - Case D3: Invalid redirect URIs containing fragments (`#`), userinfo (`user:pass@`), wildcards (`*`), non http or https schemes, or non loopback insecure HTTP.
   - Case D4: Mismatched client identifier fields across `id`, `clientId`, and `client_id`.
   - Classification: `AMBIGUOUS`.
   - Inferred policy: Marked `isAmbiguous: true`. In runtime execution, it fails closed, requires private membership, requires confidential authentication if a secret is present, and logs an administrative audit alert.

### Read only inventory scanner design (Slice P1a)

The module `backend/src/identity/client-policy.ts` exposes `auditClientPolicies(db)` and the CLI script `backend/scripts/audit-client-policies.ts`:
- Connects to MongoDB in read only mode (no document insertions, updates, or deletions).
- Scans all documents in collection `oauthClient`.
- Evaluates each document against the classification matrix.
- Generates a structured JSON summary and human readable report table containing:
  - Total client count.
  - Count and IDs for `MIGRATED` clients.
  - Count and IDs for `COMPATIBLE_CLASS_A` (open public).
  - Count and IDs for `COMPATIBLE_CLASS_B` (private confidential).
  - Count and IDs for `COMPATIBLE_CLASS_C` (open confidential).
  - Count and IDs for `COMPATIBLE_CLASS_E` (private public).
  - Count, IDs, and exact reason codes for `AMBIGUOUS` clients (for example, invalid redirect URI, flag mismatch, or partial record).
- Exits with status code 0 if zero ambiguous clients exist, or status code 1 if ambiguous records require remediation.

### Rollout and rollback discipline (Later slices)

1. **Phase 1 (Slice P1a):** Deploy the policy resolver and read only audit script. Production behavior is 100% preserved. Operators run the audit script in staging and production to establish baseline client hygiene.
2. **Phase 2 (Administrative Remediation):** For any ambiguous records identified by the audit script, platform super admins update the client configuration through the management API (`PATCH /api/admin/clients/:id`), explicitly assigning `clientType` and `accessPolicy`.
3. **Phase 3 (Slice P1b Deployment):** Deploy backend enforcement routes with `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=false`. In this mode, the system validates PKCE on public clients and validates secrets on confidential clients, while open applications continue recording fallback membership rows.
4. **Phase 4 (Gate Activation):** Set `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=true`. Open applications allow eligible users to authorize and consent directly without writing rows to `user_app_registrations`. Private applications continue strict membership checks.
5. **Phase 5 (Slice P1c Deployment):** Deploy frontend administrative UI updates providing explicit selectors for client type and access policy.
6. **Rollback guarantee:** If any client experiences authorization anomalies during Phase 4, operators set `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=false` immediately. Open applications resume creating legacy membership rows upon login. Because all schema updates are additive, existing data and active token families remain valid.

### 4.4 Endpoint specific matrix and protocol enforcement (Slice P1b)

The runtime enforcement in Slice P1b governs eight distinct OAuth and OIDC protocol operations. Each endpoint enforces deterministic validation ordering, explicit authority checks, standard error codes, exact HTTP status codes, caching headers, and safe redirection behavior.

#### 1. Authorization request (`GET /api/auth/oauth2/authorize`)
- **Validation order:**
  1. Basic syntax and client identity validation: Parse `client_id` and `redirect_uri`. If `client_id` is missing, unknown, disabled, or ambiguous (`classification === "AMBIGUOUS"` or `isAmbiguous === true`), return direct HTTP 400 `invalid_client` without redirecting per RFC 6749 Section 3.1.2.4. Under no circumstances is `invalid_client` returned via redirect. If `redirect_uri` is missing or contains invalid URL syntax, return direct HTTP 400 `invalid_request` without redirecting.
  2. Redirect URI validation: Match incoming `redirect_uri` against registered client URIs via `isRegisteredRedirectUri`. Exact match of scheme, host, port, path, and query is required. Ephemeral variable ports are permitted only for native clients (`application_type === "native"`) and development clients (`isDev === true`) on loopback IP literals (`127.0.0.1`, `[::1]`) per RFC 8252 Section 7.3, with `localhost` permitted as a developer compatibility fallback per RFC 8252 Section 8.3. Non native production clients strictly forbid loopback URIs and require exact HTTPS URIs. Fragments (`#`) and userinfo credentials (`user:pass@`) are strictly rejected. If mismatch or invalid, return direct HTTP 400 `invalid_request` without redirecting per RFC 6749 Section 3.1.2.4.
  3. Mandatory PKCE S256 for authorization code clients: For both public and confidential clients using the authorization code grant, verify `code_challenge` is present and `code_challenge_method === "S256"` per OAuth 2.1 Section 4.1.1 and RFC 7636. If missing or method is `"plain"`, redirect 302 to the registered `redirect_uri` with `error=invalid_request`, an explicit error description, and preserve the client `state` parameter per RFC 6749 Section 4.1.2.1.
  4. Session authentication check: Verify user session. If unauthenticated, redirect to IdP login preserving OAuth transaction state.
  5. Authority and access policy checks:
     * If `accessPolicy === "private"`: If `user.role === "super-admin"`, redirect 302 to `redirect_uri` with `error=access_denied`, description indicating platform super admins are excluded from private tenant applications, and preserve `state`. Verify active registration via `checkUserHasAppAccess(database, sessionUser, canonicalClientId)`. If unassigned or revoked, redirect 302 to `redirect_uri` with `error=access_denied`, description indicating user is not an active tenant member, and preserve `state`.
     * If `accessPolicy === "open"`: Authenticated eligible user is allowed access. If `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED === true`, skip writing to `user_app_registrations`. If false (legacy compatibility mode), record fallback registration within the request boundary.
  6. Account eligibility check: Verify `checkAccountEligibility(user)`. If banned, disabled, inactive, deleting, or deleted, redirect 302 to `redirect_uri` with `error=access_denied` and preserve `state`.
  7. Scope and consent evaluation: If consent required, redirect 302 to `/consent`; if consent skipped or previously granted, generate authorization code, store in `oauthAuthorizationCode`, and redirect 302 to `redirect_uri?code=...&state=...`.
- **Response headers:** `Cache-Control: no-store`, `Pragma: no-cache`.
- **Safe redirect behavior:** Per RFC 6749 Section 3.1.2.4, errors in client identity or redirect URI MUST NOT redirect; they return direct HTTP 400. Redirection occurs only after client identity and redirect URI are verified. Permitted error codes on redirect are strictly limited to RFC 6749 Section 4.1.2.1 (`access_denied` and `invalid_request`); `invalid_client` is never redirected. All error redirects MUST preserve the exact `state` parameter provided by the client.

#### 2. Consent decision (`POST /api/auth/oauth2/consent`)
- **Validation order:**
  1. Session verification: User must hold an active authenticated session. If unauthenticated, return HTTP 401 Unauthorized.
  2. Input validation: Verify `clientId`, `redirectUri`, `scopes`, and `decision` ("accept" or "deny"). If invalid, return HTTP 400 `invalid_request`.
  3. Client resolution: Resolve client policy via `resolveClientPolicy`. If ambiguous (`classification === "AMBIGUOUS"`) or disabled, return HTTP 400 `invalid_client`.
  4. Redirect URI validation: Verify `redirectUri` matches registered client URIs via `isRegisteredRedirectUri`. If mismatch, return HTTP 400 `invalid_request`.
  5. Account eligibility: Check `checkAccountEligibility(user)`. If ineligible, return HTTP 403 `access_denied`.
  6. Private tenant access check: If `accessPolicy === "private"`, reject platform super admins unconditionally (`user.role === "super-admin"`) and verify `checkUserHasAppAccess`. If not active member, return HTTP 403 `access_denied` or redirect 302 with `error=access_denied&state=...`.
  7. Open access gate: If `accessPolicy === "open"` and consent granted, skip membership write when `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED === true`. If false, record fallback membership row.
  8. Decision outcome: If decision is "deny", redirect 302 to `redirectUri?error=access_denied&state=...` preserving `state`. If "accept", issue authorization code and redirect 302 to `redirectUri?code=...&state=...`.
- **Response headers:** `Cache-Control: no-store`, `Pragma: no-cache`.

#### 3. Authentication continuation (`POST /api/auth/oauth2/continue` and 2FA continuation)
- **Validation order:**
  1. Continuation token validation: Validate encrypted or signed context challenge. If missing, expired, or invalid, return HTTP 400 `invalid_request`.
  2. Multi factor verification: Verify TOTP or backup code proof. If invalid, return HTTP 400 `invalid_grant`.
  3. User eligibility and revocation check: Verify `checkAccountEligibility(user)` and `tokenVersion`. If account state changed during step up challenge, return HTTP 403 `access_denied`.
  4. Client resolution: Resolve target client via `resolveClientPolicy`. If ambiguous (`classification === "AMBIGUOUS"`) or disabled, return HTTP 400 `invalid_client`.
  5. Open access gate: If `accessPolicy === "open"`, skip membership write if `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED === true`. If false, write fallback row.
  6. Private tenant membership: If `accessPolicy === "private"`, verify active membership and super admin exclusion.
  7. Flow resumption: Issue authorization code or redirect 302 to consent or target callback, preserving `state`.
- **Response headers:** `Cache-Control: no-store`, `Pragma: no-cache`.

#### 4. Authorization code exchange (`POST /api/auth/oauth2/token` with `grant_type=authorization_code`)
- **Validation order:**
  1. Transport and method validation: Request must be `POST` with `Content-Type: application/x-www-form-urlencoded`.
  2. Extract client credentials: Parse HTTP Basic (`Authorization: Basic ...`) or request body (`client_id`, `client_secret`).
  3. Resolve client policy: Resolve client via `resolveClientPolicy`. If client not found or `classification === "AMBIGUOUS"`, return HTTP 401 `invalid_client`.
  4. Client authentication enforcement:
     * If `clientType === "public"`: Verify no client secret was supplied. If a secret is present, reject with HTTP 400 `invalid_client` (public clients must not supply secrets).
     * If `clientType === "confidential"`: Verify credentials. If `client_secret_basic` or `client_secret_post`, compare hashed secret with stored hash. If `private_key_jwt`, verify asymmetric JWT assertion against registered `jwks` or `jwks_uri`. If credentials invalid, return HTTP 401 `invalid_client` with `WWW-Authenticate: Basic realm="OAuth"` header if HTTP Basic attempted.
  5. Mandatory PKCE enforcement: For BOTH public and confidential clients using `grant_type=authorization_code`, verify `code_verifier` is present (if missing, return HTTP 400 `invalid_request`). Compute `BASE64URL(SHA256(code_verifier))` and assert exact match with stored `code.code_challenge`.
  6. Authorization code retrieval and atomic one time consumption: Find code in `oauthAuthorizationCode`. Atomically delete or mark code consumed. If code already consumed or expired, trigger replay mitigation and return HTTP 400 `invalid_grant`.
  7. Code client binding: Verify `code.clientId === client.clientId`. If mismatch, return HTTP 400 `invalid_grant`.
  8. Code redirect URI binding: Verify `code.redirectUri === request.redirect_uri`. If mismatch, return HTTP 400 `invalid_grant`.
  9. User eligibility and revocation check: Verify `checkAccountEligibility(user)` and `user.tokenVersion`. If ineligible, return HTTP 400 `invalid_grant`.
  10. Private tenant membership check: If `accessPolicy === "private"`, verify `checkUserHasAppAccess(database, user, client.clientId)`. If unassigned or revoked, return HTTP 400 `invalid_grant`. Platform super admins denied unconditionally.
  11. Token minting and linearization: Mint RS256 JWT access token, ID token (if scope openid), and refresh token. Register initial family in `oauth_token_families` with `status: "active"`. Commit issuance linearization. Return HTTP 200 with JSON payload.
- **Response headers:** `Cache-Control: no-store`, `Pragma: no-cache`, `WWW-Authenticate: Basic realm="OAuth"` (on 401 Basic auth failure).

#### 5. Refresh token exchange (`POST /api/auth/oauth2/token` with `grant_type=refresh_token`)
- **Validation order:**
  1. Transport and method validation: `POST` with `Content-Type: application/x-www-form-urlencoded`.
  2. Client authentication:
     * If `clientType === "public"`: Authenticate by `client_id` only. Strictly no client secret permitted. Strictly no PKCE `code_verifier` required per RFC 6749 Section 6.
     * If `clientType === "confidential"`: Authenticate client using registered method (`client_secret_basic`, `client_secret_post`, or `private_key_jwt`). If credentials invalid, return HTTP 401 `invalid_client` with `WWW-Authenticate: Basic realm="OAuth"` header if HTTP Basic attempted.
  3. Pre refresh eligibility check: Verify refresh token syntax and expiration in `validatePreRefreshEligibility`.
  4. Atomic CAS claim and rotation fencing: Acquire rotation lease with unique `leaseOwner` in `oauth_token_families`. Fencing token ensures stale workers cannot overwrite or release an active lease.
  5. Single use replay detection: If presented refresh token was already consumed, trigger immediate cascade revocation of the entire token family (`status: "revoked"`, `revokedAt: new Date()`) and return HTTP 401 `invalid_grant`.
  6. Post refresh eligibility and private access check: Verify user account status via `checkAccountEligibility(user)`, verify `user.tokenVersion`, and if `accessPolicy === "private"`, verify active membership in `user_app_registrations` or `app_admins`. If access revoked, fail with HTTP 401 `invalid_grant` and set `status: "revoked"` on the token family.
  7. Commit rotation: Update active token hash in `oauth_token_families`, append previous token hash to `consumedTokenHashes`, clear rotation lease, and return minted RS256 access token and new rotated refresh token with HTTP 200.
- **Response headers:** `Cache-Control: no-store`, `Pragma: no-cache`, `WWW-Authenticate: Basic realm="OAuth"` (on 401 Basic auth failure).

#### 6. User profile (`GET /api/auth/oauth2/userinfo`)
- **Validation order:**
  1. Extract access token from `Authorization: Bearer <access_token>`. If missing or malformed, return HTTP 401 `invalid_token` with `WWW-Authenticate: Bearer error="invalid_token"`.
  2. Cryptographic signature and issuer verification: Verify RS256 signature against IdP JWKS public keys. Verify `iss` matches `AUTH_ISSUER` and token is unexpired.
  3. Account eligibility check: Look up user in `user` collection. Check `checkAccountEligibility(user)` and verify token `tokenVersion` matches `user.tokenVersion`. If ineligible, return HTTP 401 `invalid_token` with `WWW-Authenticate: Bearer error="invalid_token"`.
  4. Private tenant access check: Look up client associated with token audience (`aud`). If client has `accessPolicy === "private"`, verify active membership in `user_app_registrations` or `app_admins`. If membership revoked, return HTTP 403 `forbidden`.
  5. Projection and scope filtering: Return profile claims matching granted scopes (`sub`, `email`, `name`, `profile`). Expose full emails only if email scope is granted. Local part labels remain personal data.
- **Response headers:** `Cache-Control: no-store`, `Pragma: no-cache`, `WWW-Authenticate: Bearer error="invalid_token"` (on 401 token failure).

#### 7. Token introspection (`POST /api/auth/oauth2/introspect` per RFC 7662)
- **Validation order:**
  1. Client authentication: Confidential client authentication strictly required. Public clients cannot introspect tokens without authority. Authenticate calling client via `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. If unauthenticated or ambiguous (`classification === "AMBIGUOUS"`), return HTTP 401 `invalid_client` with `WWW-Authenticate: Basic realm="OAuth"` header if HTTP Basic attempted.
  2. Input parameter validation: Verify `token` parameter is present. If missing, return HTTP 400 `invalid_request`.
  3. Token inspection: Decode token (JWT access token or opaque/hashed refresh token).
  4. Cryptographic and status validity checks: RS256 signature verification, expiration check, family status check (`status !== "revoked"` in `oauth_token_families`), account eligibility check in `checkAccountEligibility`, and `tokenVersion` check.
  5. Target client policy and private membership check: Look up client associated with token audience (`aud`). If target client has `accessPolicy === "private"`, verify user holds active assignment in `user_app_registrations` or `app_admins`. If user private membership has been revoked or deactivated, return HTTP 200 `{ active: false }`.
  6. Client audience and authority check: If calling client does not match token audience or lacks authority to introspect the token, return HTTP 200 `{ active: false }`.
  7. Outcome: If all checks pass, return HTTP 200 `{ active: true, scope, client_id, sub, exp, iat, iss, aud }`. If any check fails, return HTTP 200 `{ active: false }` per RFC 7662 Section 2.2.
- **Response headers:** `Cache-Control: no-store`, `Pragma: no-cache`.

#### 8. Token revocation (`POST /api/auth/oauth2/revoke` per RFC 7009)
- **Validation order:**
  1. Client authentication: Authenticate calling client. Confidential clients authenticate with valid credentials. Public clients authenticate with `client_id`.
  2. Input parameter validation: Verify `token` and optional `token_type_hint` (`access_token` or `refresh_token`).
  3. Resolve token: Locate token in active database tokens or `oauth_token_families`.
  4. Client binding check: Verify the token was issued to the calling client (`clientId`). A client cannot revoke tokens belonging to a different client.
  5. Revocation action: If token is a refresh token or part of a token family, atomically mark the family `status: "revoked"`, `revokedAt: new Date()` in `oauth_token_families`, increment `tokenVersion` if durable user revocation requested, and purge associated database tokens.
  6. Outcome: Per RFC 7009 Section 2.2, if the token is valid and revoked, or if the token is already invalid or nonexistent, return HTTP 200 OK (`{ success: true }` or empty body). If client authentication fails, return HTTP 401 `invalid_client`.
- **Response headers:** `Cache-Control: no-store`, `Pragma: no-cache`.

#### Comprehensive protocol endpoint matrix

| Protocol Endpoint | Method | Validation Order Summary | Authority Checks | Standard OAuth Errors | HTTP Status | Headers | Safe Redirect Behavior |
|---|---|---|---|---|---|---|---|
| `/api/auth/oauth2/authorize` | GET | 1. Syntax, 2. Client/policy, 3. Redirect URI, 4. PKCE S256, 5. Session, 6. Access policy, 7. User eligibility, 8. Consent | User session, app membership (if private), super admin exclusion | `invalid_request`, `access_denied` (redirect); `invalid_client`, `invalid_request` (direct 400) | 302, 400 | `Cache-Control: no-store`, `Pragma: no-cache` | Never redirect on invalid URI or missing/ambiguous client; redirect 302 only after URI verified, preserving state |
| `/api/auth/oauth2/consent` | POST | 1. Session, 2. Inputs, 3. Client/policy, 4. Redirect URI, 5. Eligibility, 6. Private access, 7. Bypass gate, 8. Code issue | Active session, private membership, super admin exclusion | `invalid_request`, `invalid_client`, `access_denied` | 302, 400, 401, 403 | `Cache-Control: no-store`, `Pragma: no-cache` | Direct HTTP error on invalid inputs; redirect 302 with error query on denial, preserving state |
| `/api/auth/oauth2/continue` | POST | 1. Continuation token, 2. MFA proof, 3. Eligibility, 4. Client/policy, 5. Bypass gate, 6. Private access, 7. Resume | 2FA verification, active membership, super admin exclusion | `invalid_request`, `invalid_grant`, `access_denied`, `invalid_client` | 302, 400, 403 | `Cache-Control: no-store`, `Pragma: no-cache` | Direct HTTP error on invalid token; redirect 302 on resumed authorization, preserving state |
| `/api/auth/oauth2/token` (code) | POST | 1. Transport, 2. Client auth, 3. Policy, 4. PKCE S256 verifier, 5. Code consumption, 6. Bindings, 7. Eligibility, 8. Private access, 9. Mint | Client authentication, code ownership, private membership, super admin exclusion | `invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type` | 200, 400, 401 | `Cache-Control: no-store`, `Pragma: no-cache`, `WWW-Authenticate` (on 401) | Never redirects; pure JSON response |
| `/api/auth/oauth2/token` (refresh) | POST | 1. Transport, 2. Client auth, 3. Pre eligibility, 4. CAS lease claim, 5. Replay check, 6. Post eligibility & private access, 7. Commit | Client binding, rotation lease ownership, private membership | `invalid_request`, `invalid_client`, `invalid_grant` | 200, 400, 401 | `Cache-Control: no-store`, `Pragma: no-cache`, `WWW-Authenticate` (on 401) | Never redirects; pure JSON response |
| `/api/auth/oauth2/userinfo` | GET | 1. Bearer token, 2. Signature/issuer, 3. User eligibility, 4. Private access, 5. Claims projection | Bearer token validity, private membership, granted scopes | `invalid_token`, `forbidden` | 200, 401, 403 | `Cache-Control: no-store`, `Pragma: no-cache`, `WWW-Authenticate` (on 401) | Never redirects; pure JSON claims |
| `/api/auth/oauth2/introspect` | POST | 1. Confidential client auth, 2. Token input, 3. Inspection, 4. Validity, 5. Audience & private access check, 6. Response | Confidential client authentication, audience authority, private membership | `invalid_client`, `invalid_request` | 200, 400, 401 | `Cache-Control: no-store`, `Pragma: no-cache` | Never redirects; returns `{ active: boolean }` |
| `/api/auth/oauth2/revoke` | POST | 1. Client auth, 2. Token input, 3. Token lookup, 4. Client binding, 5. Family revocation, 6. Purge | Client authentication, token client ownership | `invalid_client`, `invalid_request` | 200, 400, 401 | `Cache-Control: no-store`, `Pragma: no-cache` | Never redirects; RFC 7009 returns 200 on success or nonexistent token |

### 4.5 Client authentication rules, engine support, and refresh rotation (Slice P1b)

The identity provider integrates `@better-auth/oauth-provider` v1.6.10 and `@better-auth/core` 1.7.1 within a Hono application architecture. The installed engine manages base client and token collection schemas and core protocol primitives. Custom runtime wrappers in `backend/src/routes/auth-token*.ts`, `backend/src/routes/auth-authorize.ts`, and `backend/src/routes/auth-consent.ts` intercept protocol flows to enforce independent client dimensions, strict PKCE validation, tenant membership verification, and ownership fenced CAS refresh rotation.

#### Supported client authentication methods
1. `none`:
   * Restricted exclusively to public clients (`clientType: "public"`).
   * Stored `clientSecret` must be null or empty, and `token_endpoint_auth_method` is `"none"`.
   * Requests presenting a client secret are rejected with HTTP 400 `invalid_client`.
   * Mandatory PKCE S256 on authorization code issuance and exchange.
2. `client_secret_basic`:
   * Restricted to confidential clients (`clientType: "confidential"`).
   * Client transmits credentials in the HTTP `Authorization` header using Basic scheme (`Authorization: Basic <base64(client_id:client_secret)>`).
   * Verified against the stored secret hash. Mismatched or missing secret returns HTTP 401 `invalid_client` with `WWW-Authenticate: Basic realm="OAuth"`.
3. `client_secret_post`:
   * Restricted to confidential clients (`clientType: "confidential"`).
   * Client transmits `client_id` and `client_secret` in the `application/x-www-form-urlencoded` request body.
   * Verified against the stored secret hash. Mismatched or missing secret returns HTTP 401 `invalid_client`.
4. `private_key_jwt`:
   * Restricted to confidential clients (`clientType: "confidential"`).
   * Client authenticates by submitting a signed asymmetric JWT assertion (`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`).
   * IdP verifies the assertion against registered `jwks` or `jwks_uri`. Zero client secret is stored or permitted.

#### Unsupported client authentication methods
* `client_secret_jwt`:
  * Not enabled in the installed engine configuration.
  * Classified as `CONFLICTING_AUTH_METHOD` in `resolveClientPolicy` and flagged with `classification: "AMBIGUOUS"`. Any client configured with `client_secret_jwt` fails closed until updated to a supported method.

#### PKCE requirements
* Mandatory PKCE S256 for all authorization code clients:
  * Per OAuth 2.1 Section 4.1.1 and RFC 9700 (BCP 212), PKCE S256 is mandatory for all authorization code flows, including both public and confidential clients.
  * The challenge method `"plain"` is strictly forbidden.
* Public clients:
  * Mandatory on authorization: Request must include `code_challenge` and `code_challenge_method=S256`. Missing or invalid challenge returns HTTP 400 `invalid_request`.
  * Mandatory on code exchange: Request must include `code_verifier`. Server validates `BASE64URL(SHA256(code_verifier)) === code_challenge`. Mismatch or missing verifier returns HTTP 400 `invalid_grant`.
* Confidential clients:
  * Mandatory on authorization: Request must include `code_challenge` and `code_challenge_method=S256`. Missing or invalid challenge returns HTTP 400 `invalid_request`.
  * Mandatory on code exchange: Request must include `code_verifier`. Server validates `BASE64URL(SHA256(code_verifier)) === code_challenge`. Mismatch or missing verifier returns HTTP 400 `invalid_grant`.

#### Native loopback redirect URIs and localhost compatibility
* Under RFC 8252 Section 7.3, native applications (`application_type: "native"`) and development clients (`isDev: true`) may register loopback IP literal redirect URIs using `http://127.0.0.1` and `http://[::1]`.
* Variable ephemeral ports are permitted dynamically at runtime on loopback IP literals for native applications and development clients. The client binds to an available local port and provides that port in the `redirect_uri` parameter during authorization.
* Under RFC 8252 Section 8.3, `http://localhost` is documented and supported separately as a developer compatibility fallback. Loopback IP literals are the standard secure URIs because they prevent name resolution hijacking, whereas `localhost` can resolve across external network interfaces in non standard operating systems.
* Production web applications strictly require HTTPS and do not permit loopback redirect URIs or variable ports.

#### Client bound refresh rotation without PKCE
* Per RFC 6749 Section 6, public clients refresh tokens by submitting `grant_type=refresh_token`, `refresh_token`, and `client_id`.
* Public clients do not supply a PKCE `code_verifier` during refresh token exchange.
* Refresh security is provided by client bound refresh token rotation with single use replay detection in `oauth_token_families`:
  * Each refresh acquisition obtains a unique atomic CAS lease using `leaseOwner`.
  * Replay of an already consumed refresh token triggers immediate cascade revocation of the active token and the entire token family.
  * A paused or failed worker releases only its own owned lease via `releaseRotationLock`, ensuring a newer winning worker lease is never disturbed.

### 4.6 Complete inventory of membership reads and writes affected by open access

The migration to open access removes ambient writes to collection `user_app_registrations` for open applications when `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED === true`. All affected call sites across the application codebase are identified below:

| Source File and Location | Operation | Legacy Behavior (`BYPASS=false`) | Modern Behavior (`BYPASS=true`) | Security Invariants |
|---|---|---|---|---|
| `backend/src/routes/auth-sign-in.ts:243` | Password login (`POST /sign-in/email`) | If client is public, inserts row into `user_app_registrations` | If client `accessPolicy === "open"`, skips write; if private, never writes ambient row | Zero ambient writes for open clients; private apps require explicit prior assignment |
| `backend/src/routes/auth-sign-up.ts:142` | Email signup (`POST /sign-up/email`) | If client is public, upserts row into `user_app_registrations` | If client `accessPolicy === "open"`, skips write; if private, never writes ambient row | Zero ambient writes for open clients; private apps require explicit prior assignment |
| `backend/src/routes/auth-interceptors.ts:207` | Social login callbacks | If client is public, upserts row into `user_app_registrations` | If client `accessPolicy === "open"`, skips write; if private, never writes ambient row | Identity federation preserves open access without ambient registration rows |
| `backend/src/routes/auth-two-factor-context.ts:150` | 2FA continuation (`completeTwoFactorAuth`) | Upserts row into `user_app_registrations` | If client `accessPolicy === "open"`, skips write; if private, never writes ambient row | Multi factor continuation respects client access policy dimensions |
| `backend/src/routes/auth-authorize.ts:232` | Authorization request (`GET /authorize`) | Checks `isPublic`; writes fallback registration if public | If `accessPolicy === "open"`, skips write; if private, verifies `checkUserHasAppAccess` | Super admin exclusion unconditionally enforced; private tenant access strictly gated |
| `backend/src/routes/auth-consent.ts:127` | Consent decision (`POST /consent`) | Writes registration row on consent acceptance | If `accessPolicy === "open"`, skips write; if private, verifies active membership | Consent records user approval without creating durable database registration rows |

#### Concurrency safe membership boundaries across HTTP lifecycles
* Browser authorization (`GET /api/auth/oauth2/authorize` and `POST /consent`) and backchannel token code exchange (`POST /api/auth/oauth2/token`) execute across independent HTTP requests and separate database connections.
* Token code exchange failures must never execute blind deletes or rollbacks on `user_app_registrations`. Deleting registration rows during backchannel token failure could destroy pre existing user memberships, concurrent active logins, or explicit administrator assignments.
* Under `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=true`, zero rows are written to `user_app_registrations` for open applications, completely eliminating ambient mutations and removing the need for compensation logic.
* For private applications, memberships are pre provisioned and immutable during authentication flows.

#### Preservation of private tenant membership enforcement
* For all applications with `accessPolicy: "private"`, `checkUserHasAppAccess(database, sessionUser, canonicalClientId)` is strictly evaluated across authorization, consent, code exchange, token refresh, UserInfo, and introspection.
* If a user lacks an active assignment in `user_app_registrations` or `app_admins`:
  * Authorization: Redirects to `redirect_uri` with `302 error=access_denied`, preserving `state`.
  * Token code exchange: Rejects with HTTP 400 `invalid_grant`.
  * Token refresh: Rejects with HTTP 401 `invalid_grant` and sets token family status to `"revoked"`.
  * UserInfo: Rejects with HTTP 403 `forbidden`.
  * Introspection: Returns HTTP 200 with `{ active: false }`.
* Ambient registration rows are never created for private applications on any login, signup, or authorization path.

#### Platform super admin consumer isolation invariant
* Platform super admins hold administrative authority over the identity provider and have zero ambient authority over consumer application tenant data.
* In `checkUserHasAppAccess` (`backend/src/utils/app-access.ts:83-87`), if `user.role === "super-admin"`, access is denied (`return false`) unconditionally for all consumer applications, even if an explicit row exists in `user_app_registrations` or `app_admins`. Platform super admins must never access private consumer tenant applications.

### 4.7 Rollback procedures and recovery guarantees

To ensure operational stability and zero data loss, the platform defines three distinct rollback procedures addressing runtime issuance failures, membership transaction scope, and deployment rollbacks.

#### Procedure 1: Issuance failure cleanup
* **Trigger:** Token minting, cryptographic signing, or database commit fails during backchannel exchange or refresh.
* **Refresh rotation cleanup:**
  * The rotation lease was acquired with a unique `leaseOwner` fencing token.
  * The error handling boundary in `handleRefreshTokenGrant` executes `releaseRotationLock(database, incomingHash, canonicalClientId, leaseOwner)`.
  * Because `releaseRotationLock` requires an exact match on `rotationOwner: leaseOwner`, a stale or failing worker will never clear or corrupt an active lease held by a subsequent winning worker.
  * If token documents were inserted into MongoDB before linearization failed, `purgeTokensOnCommitFailure` purges the newly inserted tokens.
  * If the token family was left in an unrecoverable state, it is updated to `status: "revoked"` and `revokedAt: new Date()` with `revokedReason: "issuance_linearization_failed"`.
* **Authorization code exchange cleanup:**
  * The authorization code was atomically marked consumed to prevent replay attacks.
  * Any partially minted access tokens are purged from the database.
  * The consumed code is not restored, preventing code injection or replay. The client simply initiates a fresh authorization flow.

#### Procedure 2: Membership write rollback
* **Trigger:** An authorization flow fails after an ambient membership write occurred in legacy mode.
* **Legacy compatibility mode (`OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=false`):**
  * Browser authorization and token code exchange occur across independent HTTP transactions. Any compensation or cleanup must not perform blind deletes on `user_app_registrations`.
  * Cleanup must never remove pre existing registrations, concurrently active sessions, or explicitly assigned memberships.
* **Modern open access mode (`OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=true`):**
  * Zero ambient rows are written to `user_app_registrations` for open applications. Consequently, membership write rollback is an intrinsic zero cost operation that requires no database writes.
* **Private applications:**
  * Private applications never create ambient membership rows on login or authorization paths. Membership rollback is always a no op.

#### Procedure 3: Deployment rollback compatibility matrix
Rather than relying on unconditional binary rollback assumptions, compatibility between Slice P1b and earlier versions is governed by the following matrix:

| Client Classification or State | Rollback to Legacy Behavior | Compatibility Risk | Mitigation or Operator Action |
|---|---|---|---|
| Class A (Clean Open Public) | Reads legacy `isPublic: true` and `clientSecret: null`. PKCE S256 remains required. | None | Backward compatible for standard web single page apps. Additive policy fields are ignored by legacy binaries. |
| Class B (Clean Private Confidential) | Reads legacy `isPublic: false` and validates `clientSecret`. | None | Backward compatible. Private access enforcement remains identical. |
| Class C (Clean Open Confidential) | Reads legacy `isPublic: true` and validates `clientSecret`. | Low | If legacy binary permitted confidential clients with `isPublic: true`, authentication succeeds. |
| Class E (Clean Private Public) | Reads legacy `isPublic: false`. If legacy binary required secrets for private apps, public exchange fails. | Medium | If legacy binary does not support public private clients, operator must temporarily disable or reconfigure client before binary rollback. |
| Class D (Ambiguous Records) | P1a does not enforce classifier ambiguity at runtime. Ambiguous records would fall back to legacy permissive evaluation instead of failing closed. | High | Rollback to P1a requires operators to explicitly disable ambiguous client documents in MongoDB (`disabled: true`) before traffic reaches legacy nodes, or deploy a compatible patched binary. |
| Changed Credentials (Secret Removed) | Client was converted from confidential to public in P1b (secret deleted). Legacy binary expects secret and rejects token exchange. | High | Rollback requires either deploying a compatible patched binary or re provisioning a secret for the affected client before rollback. |
| Existing Token Families | Backward compatible only for clean Class A and Class B clients without credential changes. Class E or credential transitioned clients fail refresh on legacy nodes. | Medium | Operators must audit active token families. If clients experienced credential or policy transitions, rollback requires re provisioning legacy credentials or deploying a compatible patched binary. |
| Mixed Version Deployments | P1a and P1b nodes run concurrently behind a load balancer during rolling updates. The membership bypass flag does not align client authentication, PKCE rules, or private access enforcement across mixed versions. | High | Rolling rollout or rollback requires connection draining of incompatible nodes before shifting client traffic. Mixed version clusters risk transaction divergence if multi leg OAuth flows cross node versions. |

* **Feature flag toggle rollback:**
  * If unexpected client behavior occurs after activating open access bypass, operators immediately set `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=false` in application configuration.
  * Open applications immediately resume creating legacy fallback rows in `user_app_registrations`.
  * The membership bypass flag governs only ambient registration writes. It does not alter client authentication rules or private access gates.
* **Binary rollback procedure:**
  * If rolling back the application binary from Slice P1b to Slice P1a:
    * Incompatible nodes must be drained before shifting production traffic so in flight multi leg authorization code flows do not cross versions.
    * Because P1a does not enforce classifier ambiguity at runtime, operators must disable ambiguous clients in MongoDB (`disabled: true`) prior to rollback to prevent permissive legacy evaluation.
    * If any clients experienced credential transitions (such as secret revocation for public clients), the operator must re provision secrets or deploy a compatible patched binary before rolling back.
    * Token families for clients with modified credentials or non standard combinations must be validated before routing traffic to legacy nodes.

### Preservation of administrative trust boundaries

- **Client listing protection:** The route `GET /api/admin/clients` in `backend/src/routes/admin.ts:92` strictly requires `requireSuperAdmin` middleware. App admins cannot view or list all platform OAuth clients.
- **Policy modification protection:** In `PATCH /api/admin/clients/:id` (`backend/src/routes/admin-client-detail.ts:62-76`), modifying `clientType`, `accessPolicy`, `isDev`, or `isPublic` strictly requires verified super admin authority (`isSuperAdmin(sessionUser)`). App admins modifying client display details are stripped of policy fields.
- **Super admin private application exclusion:**
  - Platform super admins manage the identity provider and hold no ambient access to consumer application tenant data.
  - In `checkUserHasAppAccess` (`backend/src/utils/app-access.ts:83-87`), if `user.role === "super-admin"`, access is denied (`return false`) unconditionally for consumer applications, even if a row exists in `user_app_registrations` or `app_admins`. Platform super admins must never access private consumer tenant applications.

### Administrative interface specification (Slice P1c)

Slice P1c delivers the frontend user experience for independent client dimensions in the administrative console, updating `RegisterAppModal.tsx`, `EditAppModal.tsx`, and `AdminClients.tsx`.

#### 1. Three independent controls

The interface separates client policy into three distinct controls:
- **Client authentication type**: Radio or dropdown selecting `Confidential` (server application holding a secret) or `Public` (single page or native application using PKCE S256 without a secret).
- **User access policy**: Radio or dropdown selecting `Private` (enterprise application restricted to assigned tenant members) or `Open` (accessible to any authenticated platform user without manual assignment).
- **Development callbacks**: Toggle selecting `Production` (strict HTTPS required) or `Development` (allows loopback callbacks on `localhost`, `127.0.0.1`, `[::1]`).

#### 2. Register App modal behavior

- **Creation defaults**:
  - Client authentication type defaults to `Confidential`.
  - User access policy defaults to `Private` (fail closed security baseline).
  - Development callbacks default to `Production` (`isDev: false`).
- **Credential provisioning**:
  - When `Confidential` is selected, the modal explains that a cryptographically secure client secret will be generated and shown once upon submission.
  - When `Public` is selected, the secret section is hidden, and an informative note explains that public clients use PKCE S256 on authorization code exchange and do not possess a secret.
- **Validation and save states**:
  - The submit action is disabled while required fields (`name`, at least one redirect URI) are missing.
  * Redirect URIs are validated on blur. In production mode (`isDev: false`), insecure HTTP redirect URIs display an inline error, with the exception of native applications (`application_type: "native"`) which permit loopback IP literals (`127.0.0.1`, `[::1]`) with variable ports per RFC 8252 Section 7.3, with `localhost` supported as a developer compatibility fallback per RFC 8252 Section 8.3.
  - In production IdP deployments, toggling Development mode requires verified super admin authority and displays an alert indicating local testing status.

#### 3. Edit App modal behavior

- **Displaying legacy records**:
  - Client records that lack explicit `clientType` or `accessPolicy` fields display a neutral status badge labeled `Legacy Compatible`, showing their inferred classification.
- **Resolving ambiguous records**:
  - When a client record contains conflicting flags, missing access metadata, or invalid URIs, the edit modal displays a prominent amber warning banner: `Ambiguous configuration requiring administrative review`.
  - The banner lists the active safe reason codes (for example, missing access metadata or conflicting dev flags).
  - Operators resolve the ambiguity by explicitly selecting a Client Authentication Type and User Access Policy.
  - Saving the updated client persists explicit `clientType` and `accessPolicy` fields. The client record status advances to `Migrated` only after full validation passes, including redirect URIs, credentials (confidential clients must possess a secret or asymmetric key assertion metadata; public clients must possess no secret), and zero conflicting metadata. If validation fails or conflicting flags remain, the record remains `Ambiguous` until all issues are resolved.
- **Handling credential and policy transitions**:
  - Transition from `Confidential` to `Public`: The modal displays a critical confirmation alert explaining that the existing client secret will be revoked and deleted, and that consumer software must supply PKCE S256 verifiers. The operator must confirm the change before saving.
  - Transition from `Public` to `Confidential`: The modal prompts the operator to generate a fresh client secret upon saving.
  - Transition from `Private` to `Open`: The modal warns that tenant membership requirements will no longer be enforced once the open access gate is activated.
- **Role based permission enforcement**:
  - App Admins (who only possess scoped authority for a single client) see client policy dimensions as disabled or read only display values.
  - Only Platform Super Admins can alter `clientType`, `accessPolicy`, or `isDev`. Any attempted modification by non super admins is rejected by the backend with HTTP 403 Forbidden.

#### 4. Client list page behavior (AdminClients.tsx)

- The clients table displays three distinct visual pills for each application:
  - Client Type pill: `Confidential` or `Public`.
  - Access Policy pill: `Private` or `Open`.
  - Environment pill: `Production` or `Development`.
- Ambiguous records display an amber warning pill labeled `Ambiguous` in the status column, allowing operators to filter and remediate unmigrated clients quickly.
- The client list remains restricted exclusively to platform super admins (`GET /api/admin/clients`).

#### 5. Browser acceptance checks (Slice P1c)

- **BAC-P1C-01 (Register clean Open Public client):** Super admin opens Register App, chooses Public and Open, enters HTTPS redirect URI. Submits form. Client is created with `clientType: "public"`, `accessPolicy: "open"`, no secret is displayed or persisted, and client list displays Open Public pills.
- **BAC-P1C-02 (Register clean Private Confidential client):** Super admin opens Register App, chooses Confidential and Private, enters HTTPS redirect URI. Submits form. Modal displays newly generated client secret with copy shortcut, client document has `clientType: "confidential"`, `accessPolicy: "private"`, and client list displays Private Confidential pills.
- **BAC-P1C-03 (Register clean Open Confidential client):** Super admin opens Register App, chooses Confidential and Open. Form validates, secret is generated once, document has `clientType: "confidential"`, `accessPolicy: "open"`.
- **BAC-P1C-04 (Register clean Private Public client):** Super admin opens Register App, chooses Public and Private. Form validates, no secret is generated, document has `clientType: "public"`, `accessPolicy: "private"`.
- **BAC-P1C-05 (Remediate Ambiguous legacy client):** Super admin navigates to client list, locates an ambiguous client with amber badge, clicks Edit. Modal shows ambiguity reason codes. Super admin selects explicit Public and Open options, corrects any invalid redirect URIs or conflicting credentials, and saves. Client list refreshes; ambiguous badge disappears and status updates to Migrated only after all validation checks pass.
- **BAC-P1C-06 (Unauthorized policy edit rejection):** A scoped App Admin navigates to their assigned application in the console. Policy selectors (`clientType`, `accessPolicy`, `isDev`) are disabled or read only. If the user attempts to send policy fields via direct HTTP PATCH, backend returns HTTP 403 Forbidden and the stored policy remains unchanged.

### API and interface surface

| Endpoint or Surface | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| `/api/admin/clients` | GET | none | List of clients with policy dimensions | Super Admin only | 401, 403, 500 |
| `/api/admin/clients` | POST | `name`, `redirect_uris`, `clientType`, `accessPolicy`, `isDev` | Created client document | Super Admin only | 400, 401, 403, 500 |
| `/api/admin/clients/:id` | PATCH | `clientType`, `accessPolicy`, `isDev`, `name`, `redirect_uris` | Updated client document | Super Admin (for policy fields) | 400, 401, 403, 404, 500 |
| `scripts/audit-client-policies.ts` | CLI | `--json` (optional) | Audit report of client classifications | CLI execution | Exit 0 (clean), Exit 1 (ambiguous found) |
| `/api/auth/oauth2/authorize` | GET | `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method` | 302 redirect with code or error | Public / Session | 302 access_denied, 400 invalid_request |
| `/api/auth/oauth2/token` | POST | `grant_type`, `code`, `client_id`, `client_secret`, `code_verifier`, `refresh_token` | JSON token response | Basic / Body / PKCE | 400 invalid_grant, 401 invalid_client |

### Value sourcing

| Action | Value produced or displayed | Source |
|---|---|---|
| Resolve client policy | `clientType` ("public" or "confidential") | Explicit `oauthClient.clientType`, or derived from verified secret presence |
| Resolve client policy | `accessPolicy` ("open" or "private") | Explicit `oauthClient.accessPolicy`, or mapped from legacy `isPublic` |
| Resolve client policy | `isDev` (boolean) | Explicit `oauthClient.isDev` or `oauthClient.is_dev` |
| Resolve client policy | `isAmbiguous` (boolean) | Computed by classification rules when legacy metadata conflicts |
| Check user authorization | Access decision (allow or deny) | If `accessPolicy === "private"`, authoritative lookup in `user_app_registrations` and `app_admins` |
| Check user authorization | Open membership bypass flag | Configuration setting `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED` |
| Authorize private client | Super admin access denial | Unconditional denial in `checkUserHasAppAccess` when `user.role === "super-admin"` |

### Key invariants

1. Super admin isolation: Platform super admin accounts are strictly excluded from private consumer applications across all authorization checks, even if a membership row exists.
2. Private client protection: Applications with `accessPolicy: "private"` strictly require active registration in `user_app_registrations` or `app_admins`. Revoked or absent membership results in immediate `302 error=access_denied`.
3. Secret custody and PKCE: Public clients must never have a client secret stored or verified. Both public and confidential authorization code clients must enforce PKCE S256 on authorization and code exchange per OAuth 2.1 and RFC 9700 (BCP 212). Confidential clients must authenticate using valid credentials.
4. Public refresh rotation: Public clients refresh tokens without a PKCE verifier, secured by client bound refresh token rotation and family replay detection.
5. Loopback isolation: Native applications (`application_type: "native"`) and development clients (`isDev: true`) allow loopback IP literals (`127.0.0.1`, `[::1]`) with variable ports per RFC 8252 Section 7.3. Localhost is supported separately as a developer compatibility fallback per RFC 8252 Section 8.3. Production web clients strictly require HTTPS.
6. Zero guessing: Ambiguous, conflicting, or partial records are never altered automatically. They fail closed until an administrator explicitly assigns their policy.

### Configuration required

- `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED`: boolean (defaults to `false`). In Slice P1a, this setting is inactive. In Slice P1b, setting to `true` disables ambient writes to `user_app_registrations` for open applications.

### Critical test scenarios

- **P1a Read only audit detection:** The audit script runs against fixture databases containing clean open public, private confidential, open confidential, private public, and ambiguous records. It produces exact classification counts without modifying any document, verifying **AC-P1A-02** and **AC-P1A-04**.
- **P1a Runtime preservation:** Existing authorization, code exchange, token refresh, and login routes execute identically against legacy records before and after P1a resolver installation, verifying **AC-P1A-05**.
- **P1b Open client without membership:** An eligible authenticated user with zero rows in `user_app_registrations` completes authorization, consent, code exchange, and UserInfo for an open application when bypass is enabled. Zero rows are inserted into `user_app_registrations`, verifying **AC-P1B-01** and **AC-P1B-02**.
- **P1b Revoked private client denial:** A user with a revoked registration or deactivated record in `user_app_registrations` or `app_admins` authorizes against a private client and is denied at authorize (`302 access_denied`), token exchange (`400 invalid_grant`), refresh (`401 invalid_grant` with token family status `"revoked"`), UserInfo (`403 forbidden`), and introspection (`{ active: false }`), verifying **AC-P1B-01** and **AC-P1B-08**.
- **P1b Super admin consumer exclusion:** A platform super admin attempting authorization on a private consumer application receives `302 error=access_denied` unconditionally, even if an explicit row exists in `user_app_registrations` or `app_admins`, verifying **AC-P1B-06**.
- **P1b PKCE enforcement:** Any authorization code client attempting authorization without PKCE S256 challenge, or code exchange without matching code verifier, is rejected. A public client attempting code exchange with a client secret is rejected, verifying **AC-P1B-03**.
- **P1b Public client refresh rotation:** A public client successfully refreshes tokens using `client_id` and `refresh_token` without a PKCE verifier. Replaying an already consumed refresh token immediately revokes the active token and the entire token family with status `"revoked"`, verifying **AC-P1B-04**.
- **P1b Strict isDev and loopback ports:** A development client or native application successfully authorizes against `http://127.0.0.1:45678/callback` when `http://127.0.0.1/callback` was registered. A non native production client attempting loopback redirect is rejected with HTTP 400, verifying **AC-P1B-05**.

## Build plan

The build plan follows a tracer bullet approach across three distinct slices:

### Slice P1a: Classification, Resolver, and Read Only Inventory
1. Create `backend/src/identity/client-policy.ts` implementing `resolveClientPolicy`, `auditClientPolicies`, classification types, and mapping rules, satisfies **AC-P1A-01**, **AC-P1A-03**, **AC-P1A-04**.
2. Create `backend/scripts/audit-client-policies.ts` as an executable CLI tool reporting clean and ambiguous client records, satisfies **AC-P1A-02**.
3. Create unit tests in `backend/tests/unit/client-policy-classification.test.ts` verifying all mapping rules, clear classes, ambiguous edge cases, and zero runtime mutation, satisfies **AC-P1A-01**, **AC-P1A-02**, **AC-P1A-03**, **AC-P1A-04**, **AC-P1A-05**.

### Slice P1b: Runtime Enforcement and Open Access Gate

Slice P1b represents the smallest cohesive backend implementation slice to activate independent client dimensions and the open access gate without frontend changes.

#### 1. Affected files and responsibilities
- `backend/src/config/schema.ts` and `backend/src/config/index.ts`: Add `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED` boolean flag defaulting to `false` (under 300 lines).
- `backend/src/utils/client-resolver.ts`: Integrate `resolveClientPolicy` into canonical client resolution. Enforce strict boolean `isDev` parsing and native loopback ephemeral port rules per RFC 8252 (under 300 lines).
- `backend/src/routes/auth-authorize.ts`: Enforce open versus private access policy. Gate ambient membership writes using `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED`. Enforce mandatory PKCE S256 for all authorization code clients (both public and confidential). Enforce unconditional super admin exclusion from private tenant apps (under 300 lines).
- `backend/src/routes/auth-consent.ts`: Gate membership writes on consent approval. Enforce private tenant membership verification and super admin exclusion (under 300 lines).
- `backend/src/routes/auth-token-auth.ts`: Enforce client authentication rules in token handler. Reject client secrets presented by public clients. Verify secrets for confidential clients. Verify asymmetric assertions for `private_key_jwt` (under 300 lines).
- `backend/src/routes/auth-token-code.ts`: Enforce mandatory PKCE `code_verifier` for all authorization code clients (both public and confidential) on authorization code exchange (under 300 lines).
- `backend/src/routes/auth-token-refresh.ts`: Enforce verifier free client bound refresh rotation for public clients. Preserve atomic CAS lease claim with `leaseOwner` and single use replay cascade revocation (under 300 lines).
- `backend/src/routes/auth-sign-in.ts`: Skip ambient `user_app_registrations` write for open applications when bypass is enabled (under 300 lines).
- `backend/src/routes/auth-sign-up.ts`: Skip ambient `user_app_registrations` write for open applications when bypass is enabled (under 300 lines).
- `backend/src/routes/auth-interceptors.ts`: Skip ambient `user_app_registrations` write on social login callbacks for open applications when bypass is enabled (under 300 lines).
- `backend/src/routes/auth-two-factor-context.ts`: Skip ambient `user_app_registrations` write on 2FA continuation for open applications when bypass is enabled (under 300 lines).
- `backend/src/routes/admin-client-detail.ts`: Restrict policy field modifications (`clientType`, `accessPolicy`, `isDev`) strictly to verified super admins (under 300 lines).
- `backend/tests/security/client-policy-enforcement.test.ts`: Focused security integration test suite verifying all runtime enforcement invariants and consumer integration recipes (under 300 lines).

#### 2. Acceptance criteria mapping
- **AC-P1B-01 (Umbrella 0008 AC-06):** Open applications allow eligible users to authorize and consent without inserting rows into `user_app_registrations` when `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=true`.
- **AC-P1B-02 (Umbrella 0008 AC-06):** Ambient membership writes for open applications are removed from password login, email signup, social login callbacks, and 2FA continuation when bypass is active.
- **AC-P1B-03 (Umbrella 0008 AC-05):** Mandatory PKCE S256 for all authorization code clients (both public and confidential) on authorization and code exchange. Public clients strictly omit secrets. Confidential clients authenticate using valid credentials.
- **AC-P1B-04:** Public clients executing token refresh use client bound refresh rotation without requiring a PKCE verifier. Replayed refresh tokens trigger immediate token family revocation with status `"revoked"`.
- **AC-P1B-05:** Native clients (`application_type: "native"`) and development mode clients (`isDev: true`) allow ephemeral variable ports on loopback IP literals (`127.0.0.1`, `[::1]`) per RFC 8252 Section 7.3, while `localhost` is supported for developer tool compatibility per RFC 8252 Section 8.3. Non native production clients strictly forbid loopback URIs and strictly require exact HTTPS redirect URIs.
- **AC-P1B-06:** Platform super admin accounts are strictly excluded from private consumer applications across all authorization checks.
- **AC-P1B-07 (Umbrella 0008 AC-14):** Protocol endpoints and offline RS256 token verification against JWKS remain fully compatible. Zero direct database access is granted to consumers.
- **AC-P1B-08:** Current private membership and client policy validation are required in token introspection (`POST /api/auth/oauth2/introspect`). Revoked or deactivated private access returns `{ active: false }`.

#### 3. Real API and consumer verification scenarios
- **Scenario 1 (Open Public Single Page App Recipe):**
  A Vite single page application configured with `clientType: "public"` and `accessPolicy: "open"`. Initiates authorization with `code_challenge` (S256), zero secret. Completes consent and code exchange with `code_verifier`. Authenticates successfully with zero rows created in `user_app_registrations`. Refreshes tokens by presenting `refresh_token` and `client_id` without verifier. Presenting an already consumed refresh token triggers immediate family revocation.
- **Scenario 2 (Open Confidential Server BFF Recipe):**
  A Next.js App Router Backend for Frontend configured with `clientType: "confidential"` and `accessPolicy: "open"`. Initiates authorization with `code_challenge` (S256). Authenticates to `/api/auth/oauth2/token` via `client_secret_basic` presenting matching `code_verifier`. Authorization code exchange mints RS256 JWT tokens with zero membership rows in `user_app_registrations`. JWT cryptographically verifies offline against `/.well-known/jwks.json`.
- **Scenario 3 (Private Public Mobile Recipe):**
  A native mobile application configured with `clientType: "public"` and `accessPolicy: "private"`. An unassigned user attempting authorization receives `302 error=access_denied`. A provisioned tenant member in `user_app_registrations` completes PKCE S256 authorization successfully.
- **Scenario 4 (Private Confidential Enterprise Recipe):**
  An enterprise tenant service configured with `clientType: "confidential"` and `accessPolicy: "private"`. Authenticates via client secret. An unassigned user or revoked member is denied. A platform super admin attempting authorization receives `302 error=access_denied` unconditionally.
- **Scenario 5 (Ambiguous Client Fail Closed Scenario):**
  A legacy client with conflicting flags or malformed metadata (`classification === "AMBIGUOUS"` or `isAmbiguous === true`). Rejects authorization requests directly with HTTP 400 `invalid_request` without redirecting. Rejects token requests with HTTP 401 `invalid_client`. Rejects introspection with `{ active: false }` or HTTP 401 `invalid_client`.

### Slice P1c: Frontend Administrative Controls
10. Update `frontend/pages/admin/RegisterAppModal.tsx`, `EditAppModal.tsx`, and `AdminClients.tsx` to provide explicit selectors for client type and access policy, satisfies **AC-P1C-01**.

## Migration plan

**Strategy**: Strangler pattern with additive schema fields and feature gate.

**Phases**:
1. Phase 1 (Slice P1a Audit): Deploy the policy resolver and read only audit script. Run `npm run audit:client-policies` against staging and production databases to produce an exact client inventory.
2. Phase 2 (Administrative Remediation): Super admins inspect any ambiguous records and submit explicit assignments for `clientType` and `accessPolicy` via management API or admin console.
3. Phase 3 (Slice P1b Deployment): Deploy backend enforcement routes with `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=false` as a safety baseline.
4. Phase 4 (Gate Activation): Set `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=true`. Open applications allow immediate access without creating registration rows. Private applications continue strict membership checks.
5. Phase 5 (Slice P1c UI Deployment): Deploy frontend administrative interface updates.

**Rollback**:
If unexpected behavior occurs during Phase 4, set `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=false` immediately. The system safely reverts to creating ambient membership rows for open clients. Because all changes are additive, database records remain valid and no data is lost.

**Risks**:
- Risk: An operator might assume an ambiguous client is open when it was intended to be private.
  Mitigation: Ambiguous records fail closed by default, requiring explicit administrator confirmation before access rules change.
- Risk: A consumer application expecting user app registration rows might query the database directly.
  Mitigation: Centralized IdP rule 2 strictly forbids direct consumer database queries. All communication uses standard OAuth endpoints.

## Consequences

**Positive**:
- Clear separation between client authentication capability (`clientType`) and user authorization boundary (`accessPolicy`).
- Non destructive migration path with complete auditability and zero guessing.
- Elimination of unnecessary database writes in `user_app_registrations` for open public applications.
- Full preservation of private tenant isolation and super admin access restrictions.

**Negative / Tradeoffs**:
- Requires maintaining fallback compatibility logic during the transition window.
- Platform super admins must manually review and remediate ambiguous client records identified by the audit script.

**Neutral**:
- Configuration requires one new optional feature flag (`OPEN_APP_MEMBERSHIP_BYPASS_ENABLED`).
- Frontend admin console displays two separate controls for client type and access policy instead of a single public toggle.

## Follow up

- [ ] Execute `audit:client-policies` on current staging and production databases to establish the baseline count of legacy records.
- [ ] Confirm with consumer application maintainers that no consumer service directly inspects `user_app_registrations`.
- [ ] Prepare P2 verified signup specifications after P1 client policy migration is implemented and accepted.

## References

**Project sources:**
- Root `AGENTS.md`: The 10 Golden Rules for AI Agents and 18 Security Review Questions.
- `docs/ARCHITECTURE.md`: OAuth 2.1 protocol architecture and tenant isolation topology.
- `docs/SECURITY.md`: Normative security architecture and trust model.
- `docs/PHASES.md`: Section 3, P1 client dimensions build plan and exit criteria.
- `docs/IMPLEMENTATION_MAP.md`: Proposed module `backend/src/identity/client-policy.ts`.
- `docs/specs/0008-multi-account-identity-platform/index.md`: Umbrella specification for verified multi account identity platform.

**Practices & standards:**
- RFC 6749: The OAuth 2.0 Authorization Framework.
- RFC 6750: OAuth 2.0 Bearer Token Usage.
- RFC 7009: OAuth 2.0 Token Revocation.
- RFC 7636: Proof Key for Code Exchange by OAuth Public Clients.
- RFC 7662: OAuth 2.0 Token Introspection.
- RFC 8252: OAuth 2.0 for Native Apps (Loopback interface redirection and ephemeral ports).
- RFC 9700 / BCP 212: OAuth 2.0 Security Best Current Practice.
- OAuth 2.1 Draft: Mandatory PKCE S256 for all authorization code flows.
