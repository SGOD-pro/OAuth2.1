# 0008-P1. Client policy migration and open access without membership

**Date:** 2026-11-22

## Summary

This specification establishes independent client dimensions for OAuth V2 by separating client type, access policy, and development environment. It provides a read only audit tool that flags ambiguous legacy client configurations without guessing or mutating database records. Existing client authentication and private tenant boundaries remain fully preserved. A safe feature gate enables eligible users to access open applications without creating unnecessary user app registration records.

## Context

Legacy SWYRA Auth used a single boolean field named `isPublic` to represent two unrelated concepts. First, it represented client authentication capability, meaning whether a client is a public client such as a single page browser application or a confidential client that can protect a client secret. Second, it represented application membership policy, meaning whether an application is open to any authenticated platform user or private to a specific tenant.

Conflating these two concepts creates significant security and operational risks. A public single page application might need private access restrictions for enterprise tenants. Conversely, a confidential server side application might need to be open to all authenticated users. When one boolean governs both, developers and administrators are forced into unnatural workarounds, or security controls fail open.

In addition, loopback development redirect URIs were tied to `isDev`, but legacy code sometimes assumed development clients are always public or production clients are always confidential. In V2, an identity provider hosts both development and production clients across both public and confidential types.

We need a clean additive migration that resolves `clientType`, `accessPolicy`, and `isDev` as three independent dimensions. We must never guess how to classify an ambiguous legacy client record, and we must never rewrite client documents without explicit administrative review. Finally, open applications must allow eligible users to authorize and consent directly without forcing an ambient membership record into `user_app_registrations`, while private applications must strictly enforce explicit membership.

## Requirements

**User stories:**
- As a platform administrator, I want to classify OAuth clients by their actual authentication capability (`public` or `confidential`) and access policy (`open` or `private`) independently so that my security boundaries accurately reflect application architectures.
- As a platform operator, I want to run a read only audit script that detects conflicting or ambiguous legacy client records so that I can remediate them before activating new access policies.
- As an end user, I want to sign in to open applications without being blocked by missing ordinary membership records or creating redundant registration rows.
- As an enterprise tenant owner, I want private applications to strictly require explicit active membership in `user_app_registrations` or `app_admins` so that unauthorized users are denied immediately.

**Acceptance criteria:**
- **AC-05 (Traceable to umbrella 0008):** `clientType` (`public` or `confidential`), `accessPolicy` (`open` or `private`), and `isDev` (`true` or `false`) resolve independently. Legacy record migration rejects ambiguity without guessing.
- **AC-06 (Traceable to umbrella 0008):** An eligible authenticated user enters an open application without requiring an ordinary membership record. A private unassigned or revoked user is denied immediately at authorize, token exchange, refresh, and online validation.
- **AC-14 (Traceable to umbrella 0008):** Existing consumer protocol and data APIs remain available with standard scopes, consent, and privacy protections. No consumer application receives direct database access.
- **AC-P1-01:** The policy resolver classifies every possible combination of `clientType`, `accessPolicy`, and `isDev` deterministically.
- **AC-P1-02:** The read only inventory script inspects all clients in `oauthClient` and reports counts for migrated, compatible class A, compatible class B, and ambiguous class D records with zero database writes.
- **AC-P1-03:** Conflicting records, such as `isPublic: true` with an active client secret or `isPublic: false` without a client secret, are categorized as ambiguous class D and fail closed in sensitive flows until explicitly remediated.
- **AC-P1-04:** Super admin users have zero automatic bypass or membership in consumer applications. Private access checks fail closed for unassigned super admins.
- **AC-P1-05:** When open application membership bypass is enabled by configuration, authorization code issuance for open clients succeeds without inserting into `user_app_registrations`.
- **AC-P1-06:** Token exchange and refresh flows validate that public clients omit secrets and supply PKCE, while confidential clients authenticate with valid credentials.

## Options considered

### Option 1: Direct in place database rewrite

Run a one time migration script that overwrites legacy client records in MongoDB, guessing `clientType` and `accessPolicy` from existing boolean flags and secret presence.

**Pros:**
- Simple one time script.
- Eliminates legacy fallback code paths immediately.

**Cons:**
- Dangerous guessing on ambiguous records, such as public apps with stray secrets or private mobile apps.
- Irreversible changes to live client configuration without administrator review.
- Breaks backward compatibility if old and new backend instances run concurrently during deployment.

### Option 2: Additive independent dimensions with read only audit inventory and runtime fallback (Chosen)

Keep legacy fields untouched on disk. Introduce explicit optional fields `clientType` and `accessPolicy` alongside existing `isDev`. Build a pure resolver function that reads explicit fields first and falls back to safe mapping rules for legacy records. Provide a read only audit script that highlights ambiguous records for administrative remediation. Gate open access without membership behind an explicit configuration switch.

**Pros:**
- Zero downtime and completely non destructive.
- Zero guessing on ambiguous records; operators receive a clear report.
- Full backward compatibility for existing consumers and running backend workers.
- Allows gradual administrative remediation through standard management routes.

**Cons:**
- Requires maintaining compatibility fallback logic in the resolver during the transition period.
- Requires an administrative review step for ambiguous records before decommissioning legacy fields.

### Option 3: Separate configuration schemas for V1 and V2 clients

Maintain two completely different database collections, one for legacy OAuth clients and another for V2 identity platform clients.

**Pros:**
- Completely isolates V2 logic from V1 logic.

**Cons:**
- Massive code duplication across authentication and administrative routes.
- Two sets of database indexes and caches to maintain.
- Confusion for operators managing client credentials across split registries.

## Decision

**Chosen option**: Option 2: Additive independent dimensions with read only audit inventory and runtime fallback.

We establish `clientType`, `accessPolicy`, and `isDev` as three orthogonal properties in `backend/src/identity/client-policy.ts`. Legacy clients resolve through strict compatibility rules, ambiguous records are flagged by a read only audit script without mutating data, and open access without membership is enabled through an explicit feature gate.

**Implementation skills**: None.

## Rationale

Option 2 honors the core engineering principles in root AGENTS.md. It avoids silent guesses, never weakens private tenant boundaries, and maintains zero downtime during upgrades. By providing a read only audit script, platform operators gain full visibility into client inventory before flipping the open access feature gate.

Option 1 was rejected because automatic heuristic migrations risk exposing private tenant data if a private client is mistakenly classified as open. Option 3 was rejected because maintaining two client registries adds unnecessary complexity and violates the simplicity first principle.

## Feature design

### Data model sketch

The MongoDB collection `oauthClient` receives additive, optional fields. Legacy fields remain intact for backward compatibility:

```typescript
export interface OAuthClientPolicyFields {
  // V2 explicit dimensions
  clientType?: "public" | "confidential";
  accessPolicy?: "open" | "private";
  isDev?: boolean;

  // Migration and audit metadata
  policyVersion?: number;
  policyMigratedAt?: Date;
  policyMigratedBy?: string;

  // Legacy fields (retained during migration)
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

### Mapping rules and classification matrix

When resolving a client record, the policy resolver applies the following precedence:

1. **Explicit V2 fields take precedence:**
   If `clientType` and `accessPolicy` are explicitly set, the client is classified as `MIGRATED`. The explicit values are used directly.

2. **Clear Class A (Compatible Open Public Client):**
   - Explicit fields missing.
   - Legacy `isPublic: true` (or `is_public: true`).
   - No client secret present (neither `clientSecret` nor `client_secret` exists, or both are empty strings).
   - Valid redirect URIs registered.
   - Classification: `COMPATIBLE_CLASS_A`.
   - Inferred policy: `clientType: "public"`, `accessPolicy: "open"`, `isDev: Boolean(isDev || is_dev)`.

3. **Clear Class B (Compatible Private Confidential Client):**
   - Explicit fields missing.
   - Legacy `isPublic: false` (or `is_public: false`).
   - Valid client secret present.
   - Valid redirect URIs registered.
   - Classification: `COMPATIBLE_CLASS_B`.
   - Inferred policy: `clientType: "confidential"`, `accessPolicy: "private"`, `isDev: Boolean(isDev || is_dev)`.

4. **Ambiguous Class D (Requires Administrative Remediation):**
   Any client record that does not match the clean patterns above:
   - Case D1: `isPublic: true` with an active client secret. (Could be an open confidential web app, or a public SPA with an accidental leftover secret).
   - Case D2: `isPublic: false` without a client secret. (Could be a private mobile app needing public client authentication, or an improperly provisioned confidential app).
   - Case D3: Contradictory boolean flags, such as `isPublic: true` and `is_public: false`.
   - Case D4: Missing or invalid redirect URIs.
   - Classification: `AMBIGUOUS`.
   - Inferred policy: Fails closed. The resolver marks `isAmbiguous: true`. In runtime authorization, it falls back to strict legacy verification and logs an audit alert. It never opens access without certainty.

### Read only inventory scanner design

A dedicated module in `backend/src/identity/client-policy.ts` exposes `auditClientPolicies(db)` and an executable script in `backend/scripts/audit-client-policies.ts`:

- Connects to MongoDB in read only mode (no updates or deletes).
- Fetches all records from `oauthClient`.
- Classifies each record into `MIGRATED`, `COMPATIBLE_CLASS_A`, `COMPATIBLE_CLASS_B`, or `AMBIGUOUS`.
- Emits structured JSON summary and human readable table containing:
  - Total client count.
  - Count and list of migrated clients.
  - Count and list of clear compatible clients.
  - Count and detailed explanation for every ambiguous client (client ID, name, conflicting fields, reason for ambiguity).
- Exits with code 0 if zero ambiguous clients are found, or code 1 if ambiguous clients require remediation.

### Ambiguity handling and safety rules

- No automatic mutations: The audit tool and the runtime resolver never update MongoDB documents automatically.
- Remediation mechanism: Operators remediate ambiguous records by submitting an explicit update through the super admin API (`PATCH /api/admin/clients/:id`), explicitly supplying both `clientType` and `accessPolicy`.
- Fail closed enforcement: If an ambiguous client is invoked in authorization or token exchange before remediation, it is treated with the safest legacy restriction. If `isPublic` was false, private membership is required. If secret presence is conflicted, confidential secret authentication is required.

### API and interface surface

| Endpoint or Surface | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| `/api/admin/clients` | GET | none | List of clients with `clientType`, `accessPolicy`, `isDev`, `isAmbiguous` | Super Admin or App Admin | 401, 403, 500 |
| `/api/admin/clients` | POST | `name`, `redirect_uris`, `clientType`, `accessPolicy`, `isDev` | Created client record with canonical IDs | Super Admin | 400, 401, 403, 500 |
| `/api/admin/clients/:id` | PATCH | `clientType`, `accessPolicy`, `isDev`, `name`, `redirect_uris` | Updated client record | Super Admin (policy fields) | 400, 401, 403, 404, 500 |
| `scripts/audit-client-policies.ts` | CLI | `--json` (optional) | Audit report of client classifications | CLI execution | Exit 0 (clean), Exit 1 (ambiguous found) |
| `/api/auth/oauth2/authorize` | GET | `client_id`, `redirect_uri`, `state`, `code_challenge` | 302 redirect with code or error | Public / Session | 302 access_denied, 400 invalid_request |
| `/api/auth/oauth2/token` | POST | `grant_type`, `code`, `client_id`, `client_secret`, `code_verifier` | Tokens JSON | Basic / Body / PKCE | 400 invalid_grant, 401 invalid_client |

### Value sourcing

| Action | Value produced or displayed | Source |
|---|---|---|
| Resolve client policy | `clientType` ("public" or "confidential") | `oauthClient.clientType`, or inferred from legacy secret absence |
| Resolve client policy | `accessPolicy` ("open" or "private") | `oauthClient.accessPolicy`, or inferred from legacy `isPublic` |
| Resolve client policy | `isDev` (boolean) | `oauthClient.isDev` or `oauthClient.is_dev` |
| Resolve client policy | `isAmbiguous` (boolean) | Computed by classification rules when legacy flags conflict |
| Check user authorization | Access decision (allow or deny) | If `accessPolicy === 'private'`, authoritative check in `user_app_registrations` and `app_admins` |
| Check user authorization | Membership bypass flag | Configuration setting `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED` |
| List clients | Client summary cards | Database documents merged with resolved policy dimensions |

### Key invariants

1. Super admin isolation: Super admin credentials grant no ambient membership or bypass in consumer applications. Unassigned super admins attempting OAuth on private apps are denied.
2. Private client protection: Applications with `accessPolicy: "private"` strictly require active registration in `user_app_registrations` or `app_admins`. Revoked or absent membership results in immediate `302 error=access_denied`.
3. Secret custody: Public clients (`clientType: "public"`) must never have a client secret issued or stored, and must enforce PKCE S256. Confidential clients (`clientType: "confidential"`) must authenticate using their client secret.
4. Loopback isolation: Loopback redirect URIs (`http://localhost:*`, `http://127.0.0.1:*`) are permitted only when `isDev: true`. Production clients (`isDev: false`) strictly require HTTPS.
5. Zero guessing: Ambiguous records are never altered automatically. They fail closed until an administrator explicitly sets their policy.

### Configuration required

- `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED`: boolean (defaults to `false` in development and production). When `false`, open apps continue recording legacy membership upon first sign in. When set to `true`, open apps allow eligible users to authorize and consent directly without writing to `user_app_registrations`.

### Critical test scenarios

- Happy path open client: An eligible authenticated user without any record in `user_app_registrations` authorizes against an open public client and receives an authorization code, verifying **AC-06** and **AC-P1-05**.
- Private client unassigned denial: An authenticated user with no assignment in `user_app_registrations` or `app_admins` authorizes against a private client and receives `302 error=access_denied`, verifying **AC-06** and **AC-P1-04**.
- Private client super admin denial: A platform super admin without an explicit assignment for a private client authorizes and receives `302 error=access_denied`, verifying **AC-06** and **AC-P1-04**.
- Public client secret rejection: A public client attempting token exchange with a client secret or without PKCE verifier is rejected, verifying **AC-05** and **AC-P1-06**.
- Confidential client secret requirement: A confidential client attempting token exchange without credentials or with an invalid secret is rejected, verifying **AC-05** and **AC-P1-06**.
- Ambiguity inventory detection: The audit script runs against a fixture database containing clean and ambiguous records, accurately identifying conflicting records without modifying any document, verifying **AC-05**, **AC-P1-02**, and **AC-P1-03**.

## Build plan

The build plan follows a tracer bullet approach, standing up the thin policy resolver first, followed by the read only audit tool, backend validation, route integration, and administrative user interface controls:

1. Create the client policy module in `backend/src/identity/client-policy.ts` containing the core resolver, types, and classification matrix, satisfies **AC-05**, **AC-P1-01**, **AC-P1-03**.
2. Create the read only audit script in `backend/scripts/audit-client-policies.ts` to inspect MongoDB and report clean and ambiguous client records, satisfies **AC-05**, **AC-P1-02**.
3. Update `backend/src/utils/client-resolver.ts` and `backend/src/utils/client-config-validator.ts` to integrate independent dimensions and canonical normalization, satisfies **AC-05**, **AC-P1-01**.
4. Update administrative routes in `backend/src/routes/admin-clients.ts` and `admin-client-detail.ts` to support reading, creating, and updating `clientType` and `accessPolicy`, satisfies **AC-05**, **AC-P1-04**.
5. Update OAuth authorization and token routes in `backend/src/routes/auth-authorize.ts`, `auth-consent.ts`, and `auth-token-refresh-validate.ts` to respect resolved policy and enforce the open access feature gate, satisfies **AC-06**, **AC-P1-05**, **AC-P1-06**.
6. Update frontend administrative modals in `frontend/pages/admin/RegisterAppModal.tsx`, `EditAppModal.tsx`, and `AdminClients.tsx` to provide explicit selectors for client type and access policy, satisfies **AC-05**.
7. Create comprehensive regression and adversarial test suites in `backend/tests/security/client-policy-migration.test.ts` verifying all matrix combinations, satisfies **AC-05**, **AC-06**, **AC-14**, **AC-P1-01**, **AC-P1-02**, **AC-P1-03**, **AC-P1-04**, **AC-P1-05**, **AC-P1-06**.

## Migration plan

**Strategy**: Strangler pattern with additive schema fields and feature gate.

**Phases**:
1. Phase 1 (Audit and additive deployment): Deploy the new resolver, validator, and read only audit script. Run `npm run audit:client-policies` in staging and production to produce an exact inventory of existing clients.
2. Phase 2 (Administrative remediation): For any client flagged as ambiguous, platform administrators use the admin console or management API to explicitly set `clientType` and `accessPolicy`.
3. Phase 3 (Feature gate activation): Once zero ambiguous records exist, set `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=true`. Open applications allow immediate access without creating registration rows. Private applications continue strict membership checks.
4. Phase 4 (Legacy cleanup): In a future V2 milestone, remove fallback inference logic once all clients have durable explicit fields.

**Rollback**:
If unexpected behavior occurs during Phase 3, set `OPEN_APP_MEMBERSHIP_BYPASS_ENABLED=false` immediately. The system safely reverts to creating ambient membership rows for open clients. Because all changes are additive, database records remain valid and no data is lost.

**Risks**:
- Risk: An operator might assume an ambiguous client is open when it was intended to be private.
  Mitigation: Ambiguous records fail closed by default, requiring explicit administrator confirmation before access rules change.
- Risk: A consumer application expecting user app registration rows might query the database directly.
  Mitigation: Centralized IdP rule 2 strictly forbids direct consumer database queries. All communication uses standard OAuth endpoints.

## Consequences

**Positive**:
- Clear separation between client authentication capability (`clientType`) and user authorization boundary (`accessPolicy`).
- Safe, non destructive migration path with full auditability.
- Elimination of unnecessary database writes in `user_app_registrations` for open public applications.
- Full preservation of private tenant isolation and super admin access restrictions.

**Negative / Tradeoffs**:
- Requires a transition period where backend code maintains fallback compatibility logic for unmigrated clients.
- Platform administrators must manually review and remediate ambiguous client records identified by the audit script.

**Neutral**:
- Configuration requires one new optional feature flag (`OPEN_APP_MEMBERSHIP_BYPASS_ENABLED`).
- Frontend admin console displays two separate controls for client type and access policy instead of a single public toggle.

## Follow-up

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
