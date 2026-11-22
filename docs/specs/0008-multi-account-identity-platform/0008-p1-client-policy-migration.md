# 0008-P1. Client policy migration and open access without membership

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
- **AC-P1B-03 (Traceable to umbrella 0008 AC-05):** Better Auth enforces client authentication types. Public clients must omit client secrets and supply PKCE S256 code challenges on authorization and code verifiers on token exchange. Confidential clients must authenticate using valid credentials.
- **AC-P1B-04:** Public clients executing token refresh (`grant_type=refresh_token`) use client bound refresh token rotation without requiring a PKCE verifier. Replayed refresh tokens trigger immediate family revocation.
- **AC-P1B-05:** Development mode parsing enforces strict boolean values. In development mode, native loopback redirect URIs (`localhost`, `127.0.0.1`, `[::1]`) allow ephemeral variable ports per RFC 8252 Section 7.3, while non loopback URIs require strict exact port equality. Production clients strictly require HTTPS.
- **AC-P1B-06:** Platform super admin accounts are strictly excluded from private consumer applications across all authorization checks, even if a record exists in `user_app_registrations` or `app_admins`.
- **AC-P1B-07 (Traceable to umbrella 0008 AC-14):** Existing consumer protocol endpoints (`/api/auth/oauth2/*`) and offline RS256 token verification against JWKS remain fully compatible. Zero direct database access is granted to consumers.
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
   If both `clientType` and `accessPolicy` are explicitly set on the document, the client is classified as `MIGRATED`. The explicit values are used directly.

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

### Better Auth client authentication enforcement (Slice P1b)

Better Auth's OAuth provider plugin stores client definitions in collection `oauthClient`:
- **Confidential clients (`clientType: "confidential"`):**
  - Better Auth verifies `client_secret` against the stored hash on `/api/auth/oauth2/token`.
  - Clients authenticate via HTTP Basic (`Authorization: Basic <base64(client_id:client_secret)>`) or request body (`client_id` and `client_secret`).
  - Requests with missing, malformed, or mismatched credentials are rejected with HTTP 401 `invalid_client`.
- **Public clients (`clientType: "public"`):**
  - Stored `clientSecret` is null or undefined, and `token_endpoint_auth_method` is set to `"none"`.
  - Requests submitting a `client_secret` are rejected with HTTP 400 `invalid_client` (public clients must not supply secrets).
  - PKCE S256 is mandatory. The authorization request (`/api/auth/oauth2/authorize`) must include `code_challenge` and `code_challenge_method=S256`. The token request (`/api/auth/oauth2/token`) must include `code_verifier`. Better Auth verifies that `BASE64URL(SHA256(code_verifier)) === code_challenge`.
- **Public client token refresh:**
  - When refreshing tokens (`grant_type=refresh_token`), public clients authenticate by supplying `client_id` only.
  - Public clients do NOT supply a PKCE code verifier on refresh requests per RFC 6749 Section 6.
  - Refresh security is provided by client bound refresh token rotation with single use replay detection in `oauth_token_families`. Any replayed refresh token immediately revokes the active token and the entire token family.

### Development environment and loopback rules (Slice P1b)

- **Strict boolean parsing:** The property `isDev` is parsed strictly as a boolean (`Boolean(target.isDev ?? target.is_dev)`). Non boolean strings or numeric values cannot enable development mode.
- **Production IdP protection:** On a production IdP (`NODE_ENV === "production"`), creating or updating a client with `isDev: true` requires verified super admin authority (`isSuperAdminOp === true`) or global configuration `ALLOW_DEV_CLIENTS_IN_PRODUCTION === true`.
- **Native loopback port exception:**
  - In development mode (`isDev: true`), redirect URIs may use loopback hostnames (`localhost`, `127.0.0.1`, `[::1]`).
  - Per RFC 8252 Section 7.3, native clients running on loopback interfaces may bind to variable ephemeral ports. During redirect URI validation in `isRegisteredRedirectUri`, loopback URIs allow port variance between the registered URI and the incoming request URI.
  - For non loopback URIs, port matching must be strictly exact.
  - Production clients (`isDev: false`) strictly forbid loopback URIs, intranet IP addresses, and insecure HTTP.

### Complete mapping of affected runtime paths

1. **OAuth authorization (`GET /api/auth/oauth2/authorize`):**
   - Resolves canonical client and policy dimensions via `resolveClientPolicy`.
   - If `accessPolicy === "private"`: checks `checkUserHasAppAccess(database, sessionUser, canonicalClientId)`. If inactive or unassigned, redirects to callback with `302 error=access_denied`.
   - If `accessPolicy === "open"`: if `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED === true`, skips writing to `user_app_registrations`. If false (legacy mode), records membership row.
2. **OAuth consent and continuation (`POST /api/auth/oauth2/consent` and `/api/auth/oauth2/continue`):**
   - Validates session user and target client policy.
   - Private applications strictly verify active assignment in `user_app_registrations` or `app_admins`.
3. **Authorization code exchange (`POST /api/auth/oauth2/token` with `grant_type=authorization_code`):**
   - Intercepts client credentials in `authenticateTokenClient`.
   - Public clients enforce PKCE S256 and reject client secrets.
   - Confidential clients enforce valid secret authentication.
   - Verifies pre code user eligibility, registers initial token family, mints RS256 JWT, and commits issuance linearization.
4. **Refresh token exchange (`POST /api/auth/oauth2/token` with `grant_type=refresh_token`):**
   - Validates pre refresh eligibility and private application access in `validatePreRefreshEligibility`.
   - Public clients supply `client_id` without secret or PKCE verifier.
   - Performs atomic CAS lock, rotates token family, checks replay detection, and validates post refresh eligibility in `validatePostRefreshEligibility`.
   - If user is revoked or private app membership is deactivated, refresh fails with HTTP 401 `invalid_grant` and token family is revoked.
5. **Online token validation (`GET /api/auth/oauth2/userinfo` and `POST /api/auth/oauth2/introspect`):**
   - Verifies RS256 token against JWKS public keys.
   - UserInfo route checks account eligibility and private app access before returning profile claims.
   - Introspection route returns `active: false` if user account is ineligible or private application assignment has been revoked.
6. **Authentication membership write paths (Phase out under open access gate):**
   - Password login (`POST /sign-in/email` in `backend/src/routes/auth-sign-in.ts:243`): Currently inserts into `user_app_registrations` for public clients. Under Slice P1b with bypass enabled, this insert is skipped when client is open.
   - Email signup (`POST /sign-up/email` in `backend/src/routes/auth-sign-up.ts:142`): Currently upserts into `user_app_registrations` for public clients. Under Slice P1b with bypass enabled, this upsert is skipped when client is open.
   - Social login callbacks (`backend/src/routes/auth-interceptors.ts:207`): Currently upserts into `user_app_registrations` for public clients. Under Slice P1b with bypass enabled, this upsert is skipped when client is open.
   - Multi factor authentication continuation (`completeTwoFactorAuth` in `backend/src/routes/auth-two-factor-context.ts:150`): Currently upserts into `user_app_registrations`. Under Slice P1b with bypass enabled, this upsert is skipped when client is open.

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
  - Redirect URIs are validated on blur. In production mode, insecure HTTP or loopback URIs display an inline error.
  - In production IdP deployments, toggling Development mode requires verified super admin authority and displays an alert indicating local testing status.

#### 3. Edit App modal behavior

- **Displaying legacy records**:
  - Client records that lack explicit `clientType` or `accessPolicy` fields display a neutral status badge labeled `Legacy Compatible`, showing their inferred classification.
- **Resolving ambiguous records**:
  - When a client record contains conflicting flags, missing access metadata, or invalid URIs, the edit modal displays a prominent amber warning banner: `Ambiguous configuration requiring administrative review`.
  - The banner lists the active safe reason codes (for example, missing access metadata or conflicting dev flags).
  - Operators resolve the ambiguity by explicitly selecting a Client Authentication Type and User Access Policy.
  - Saving the updated client persists explicit `clientType` and `accessPolicy` fields, which advances the record status to `Migrated` and clears all ambiguity reason codes.
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
- **BAC-P1C-05 (Remediate Ambiguous legacy client):** Super admin navigates to client list, locates an ambiguous client with amber badge, clicks Edit. Modal shows ambiguity reason codes. Super admin selects explicit Public and Open options and saves. Client list refreshes; ambiguous badge disappears and status updates to Migrated.
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
3. Secret custody: Public clients must never have a client secret stored or verified, and must enforce PKCE S256 on code exchange. Confidential clients must authenticate using their client secret.
4. Public refresh rotation: Public clients refresh tokens without a PKCE verifier, secured by client bound refresh token rotation and family replay detection.
5. Loopback isolation: Loopback redirect URIs (`localhost`, `127.0.0.1`, `[::1]`) are permitted only when `isDev: true`. Variable ephemeral ports are allowed on loopback hosts only per RFC 8252. Production clients strictly require HTTPS.
6. Zero guessing: Ambiguous, conflicting, or partial records are never altered automatically. They fail closed until an administrator explicitly assigns their policy.

### Configuration required

- `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED`: boolean (defaults to `false`). In Slice P1a, this setting is inactive. In Slice P1b, setting to `true` disables ambient writes to `user_app_registrations` for open applications.

### Critical test scenarios

- **P1a Read only audit detection:** The audit script runs against fixture databases containing clean open public, private confidential, open confidential, private public, and ambiguous records. It produces exact classification counts without modifying any document, verifying **AC-P1A-02** and **AC-P1A-04**.
- **P1a Runtime preservation:** Existing authorization, code exchange, token refresh, and login routes execute identically against legacy records before and after P1a resolver installation, verifying **AC-P1A-05**.
- **P1b Open client without membership:** An eligible authenticated user with zero rows in `user_app_registrations` completes authorization, consent, code exchange, and UserInfo for an open application when bypass is enabled. Zero rows are inserted into `user_app_registrations`, verifying **AC-P1B-01** and **AC-P1B-02**.
- **P1b Revoked private client denial:** A user with a revoked registration or deactivated record in `user_app_registrations` or `app_admins` authorizes against a private client and is denied at authorize (`302 access_denied`), token exchange (`400 invalid_grant`), refresh (`401 invalid_grant`), UserInfo (`403 forbidden`), and introspection (`active: false`), verifying **AC-P1B-01**.
- **P1b Super admin consumer exclusion:** A platform super admin attempting authorization on a private consumer application receives `302 error=access_denied` unconditionally, even if an explicit row exists in `user_app_registrations` or `app_admins`, verifying **AC-P1B-06**.
- **P1b Public client PKCE enforcement:** A public client attempting authorization without PKCE S256 challenge, or code exchange without code verifier, is rejected. A public client attempting code exchange with a secret is rejected, verifying **AC-P1B-03**.
- **P1b Public client refresh rotation:** A public client successfully refreshes tokens using `client_id` and `refresh_token` without a PKCE verifier. Replaying an already consumed refresh token immediately revokes the active token and the entire token family, verifying **AC-P1B-04**.
- **P1b Strict isDev and loopback ports:** A development client successfully authorizes against `http://127.0.0.1:45678/callback` when `http://127.0.0.1/callback` was registered. A production client attempting loopback redirect is rejected with HTTP 400, verifying **AC-P1B-05**.

## Build plan

The build plan follows a tracer bullet approach across three distinct slices:

### Slice P1a: Classification, Resolver, and Read Only Inventory
1. Create `backend/src/identity/client-policy.ts` implementing `resolveClientPolicy`, `auditClientPolicies`, classification types, and mapping rules, satisfies **AC-P1A-01**, **AC-P1A-03**, **AC-P1A-04**.
2. Create `backend/scripts/audit-client-policies.ts` as an executable CLI tool reporting clean and ambiguous client records, satisfies **AC-P1A-02**.
3. Create unit tests in `backend/tests/unit/client-policy-classification.test.ts` verifying all mapping rules, clear classes, ambiguous edge cases, and zero runtime mutation, satisfies **AC-P1A-01**, **AC-P1A-02**, **AC-P1A-03**, **AC-P1A-04**, **AC-P1A-05**.

### Slice P1b: Runtime Enforcement and Open Access Gate
4. Update `backend/src/utils/client-resolver.ts` and `backend/src/utils/client-config-validator.ts` to normalize independent dimensions and validate strict `isDev` and loopback port matching, satisfies **AC-P1B-03**, **AC-P1B-05**.
5. Update `backend/src/routes/admin-clients.ts` and `admin-client-detail.ts` to support super admin creation and modification of explicit policy dimensions while enforcing super admin boundaries, satisfies **AC-P1C-02**.
6. Update `backend/src/routes/auth-authorize.ts`, `auth-consent.ts`, and `auth-token-refresh-validate.ts` to enforce `accessPolicy === "private"`, enforce super admin consumer exclusion, and gate open application membership writes, satisfies **AC-P1B-01**, **AC-P1B-06**.
7. Update `backend/src/routes/auth-token-auth.ts`, `auth-token-code.ts`, and `auth-token-refresh.ts` to enforce PKCE S256 on public clients, secret authentication on confidential clients, and verifier free client bound refresh rotation, satisfies **AC-P1B-03**, **AC-P1B-04**.
8. Update `auth-sign-in.ts`, `auth-sign-up.ts`, `auth-interceptors.ts`, and `auth-two-factor-context.ts` to skip ambient membership writes for open clients when bypass is enabled, satisfies **AC-P1B-02**.
9. Create comprehensive security integration tests in `backend/tests/security/client-policy-enforcement.test.ts` verifying open access without membership, revoked private access denial, super admin exclusion, and token lifecycle invariants, satisfies **AC-P1B-01**, **AC-P1B-02**, **AC-P1B-03**, **AC-P1B-04**, **AC-P1B-05**, **AC-P1B-06**, **AC-P1B-07**.

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
- RFC 6749 Section 2.1: Client Types (Public and Confidential).
- RFC 8252: OAuth 2.0 for Native Apps (Loopback interface redirection and ephemeral ports).
- OAuth 2.1 Draft: Mandatory PKCE S256 for all authorization code flows.
