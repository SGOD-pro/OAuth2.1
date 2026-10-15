# 0005. Application configuration simplification

**Date**: 2026-10-15
**Status**: Accepted

## Summary

This decision simplifies OAuth 2.1 client application registration and maintenance across the SWYRA Auth platform. It automatically derives allowed CORS origins from registered redirect URIs whenever allowed origins are omitted or empty, eliminating manual origin entry friction and preventing browser token exchange failures. Explicitly supplied origins are preserved intact without unwanted overrides. Non web schemes (such as native mobile custom app schemes) are safely ignored during origin extraction. In addition, client document property mappings are centralized so that both camelCase and snake_case properties resolve consistently across MongoDB queries, Better Auth interactions, and administrative API responses.

## Requirements

**User stories**:
* As an administrator registering a new web application, I want allowed CORS origins to be automatically populated from my redirect URIs so that browser token exchange works immediately without manual double entry.
* As an administrator managing a multi domain or CDN hosted application, I want explicitly specified allowed origins to be preserved so that custom origin requirements are respected.
* As a mobile application developer registering a native application with custom URI schemes (such as `myapp://oauth/callback`), I want origin derivation to safely skip non web schemes without throwing validation errors.
* As an API consumer or SDK developer, I want client configuration responses to expose consistent fields whether my application expects camelCase or snake_case property naming.

**Acceptance criteria**:
* **AC-1**: Origin auto derivation extracts unique, valid web origins (`http://` and `https://` with hostname and optional port) from redirect URIs, stripping paths, queries, and trailing slashes while lowercasing hostnames.
* **AC-2**: If `allowed_origins` (or `allowedOrigins`) is omitted or empty on client creation or update, the backend automatically derives it from `redirect_uris`.
* **AC-3**: If `allowed_origins` is explicitly supplied by an administrator, explicit origins are respected and preserved without unwanted overrides.
* **AC-4**: Non web URI schemes (for example, custom native mobile app schemes and URNs) are safely skipped without throwing errors during origin derivation.
* **AC-5**: Client document field mapping is centralized through `normalizeOAuthClientFields` so both camelCase and snake_case variants resolve consistently without duplicate manual conversions.
* **AC-6**: The frontend admin console provides an auto derivation helper and automatic origin synchronization when adding redirect URIs.

## Decision

**Chosen option**: Option 1: Automatic CORS origin derivation with explicit origin preservation and centralized dual casing normalization

We implement `deriveAllowedOriginsFromRedirectUris` in `backend/src/utils/security.ts` and integrate it into `validateOAuthClientConfiguration`. We export a shared `deriveOrigins` utility in `frontend/lib/security.ts` for consistent frontend behavior in `RegisterAppModal.tsx` and `EditAppModal.tsx`. We implement `normalizeOAuthClientFields` to canonicalize client objects across all data stores and route handlers.

**Implementation skills**: none

## Rationale

Reasoning and options: see [rationale.md](rationale.md).

## Feature design

**Origin Auto Derivation Rules (`deriveAllowedOriginsFromRedirectUris` and `deriveOrigins`)**:
1. Input: array of redirect URI strings (defensively tolerating non array, null, or undefined inputs).
2. For each string:
   * Trim whitespace.
   * Parse via standard `URL` parser inside a `try / catch` block.
   * Check protocol: must be exactly `http:` or `https:`.
   * Extract `parsed.origin`. Ensure origin is non empty and not `"null"`.
   * Add to a `Set<string>` to guarantee uniqueness and case normalization.
3. Return unique origins as a string array. Non web schemes (e.g. `myapp://`, `com.example://`, `urn:`) and malformed strings are safely ignored.

**Client Configuration Validation Integration (`validateOAuthClientConfiguration`)**:
* When `targetState.allowed_origins` is empty or omitted, auto derive effective origins from `targetState.redirect_uris`.
* If explicit origins are provided, validate them directly against environment rules (loopback permitted in development mode, HTTPS required in production mode).
* Populate `effectiveAllowedOrigins` on the validation result object.

**Centralized Field Normalization (`normalizeOAuthClientFields`)**:
* Maps raw client documents from MongoDB or Better Auth into canonical objects exposing both property conventions:
  * Identifier: `id`, `clientId`, `client_id`
  * Name: `name`, `client_name`
  * Redirect URIs: `redirectUris`, `redirect_uris`
  * Allowed Origins: `allowedOrigins`, `allowed_origins`
  * Development Mode: `isDev`, `is_dev`
  * Public Application Mode: `isPublic`, `is_public`
  * Consent and Session: `skipConsent`, `skip_consent`, `enableEndSession`, `enable_end_session`
  * Credentials: `clientSecret`, `client_secret` (when present on creation)
  * Status: `disabled`
* Preserves any unmapped custom metadata fields without data loss.

**Admin Routes and Cache Synchronization**:
* `POST /api/admin/clients`: derives allowed origins when empty, validates atomically, persists extra metadata in MongoDB, records audit event, and returns dual casing response.
* `PATCH /api/admin/clients/:id` and `PATCH /api/admin/app/:clientId/config`: recalculates derived origins when allowed origins are empty and redirect URIs change, updates MongoDB, invalidates the CORS origin cache, and returns normalized client representation.

**Frontend Admin Console (`RegisterAppModal.tsx` and `EditAppModal.tsx`)**:
* When adding a redirect URI via `TagInput`, `onAdd` extracts derived origins and automatically appends unique web origins to `allowedOrigins`.
* Provides an on demand "Auto derive from redirect URIs" helper button for one click origin population.

## Value sourcing

| Value | Source |
|---|---|
| Redirect URIs | Request body `redirect_uris` or `redirectUris` array |
| Explicit Allowed Origins | Request body `allowed_origins` or `allowedOrigins` array |
| Derived Allowed Origins | Computed via `deriveAllowedOriginsFromRedirectUris(redirectUris)` |
| Client Identifier | Database document `clientId`, `client_id`, `id`, or `_id` |
| Client Name | Request body or document `name` or `client_name` |
| Development Mode Flag | Request body or document `isDev` or `is_dev` boolean |
| Public Mode Flag | Request body or document `isPublic` or `is_public` boolean |

## Build plan

* [x] Implement `deriveAllowedOriginsFromRedirectUris` in `backend/src/utils/security.ts` (satisfies AC-1, AC-4)
* [x] Integrate origin auto derivation into `validateOAuthClientConfiguration` (satisfies AC-2, AC-3)
* [x] Centralize client document field mapping via `normalizeOAuthClientFields` and update `resolveOAuthClient` (satisfies AC-5)
* [x] Integrate auto derivation and normalized responses into `backend/src/routes/admin.ts` client endpoints (satisfies AC-2, AC-5)
* [x] Export shared `deriveOrigins` utility in `frontend/lib/security.ts` (satisfies AC-1, AC-6)
* [x] Add auto sync on URI entry and helper button in `frontend/pages/admin/RegisterAppModal.tsx` and `EditAppModal.tsx` (satisfies AC-6)
* [x] Add comprehensive automated unit test suite in `backend/tests/unit/config-simplification.test.ts` covering 10 test scenarios (satisfies AC-1 through AC-6)

## Consequences

* Application onboarding is streamlined: web clients require only callback URLs to be functional.
* Browser CORS issues during token exchange are prevented by default.
* Native mobile applications are accommodated seamlessly without invalid origin generation.
* Internal codebase maintainability is significantly improved by eliminating ad hoc property name translations.
* Complete backward compatibility is maintained for all external administrative clients and SDKs.

## Follow-up

* Feature implementation, verification, and testing are complete.
