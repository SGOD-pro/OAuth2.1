# Review, v2, 2026-11-25

**Reviewed by**: Gemini 4 Hydrogen (High) (author on Gemini 4 Hydrogen (High); same model fallback disclosed as an independent reviewer model is unavailable in this session)
**Scope**: Branch v2, Slice P1c administrative client registration, policy editing, scoped admin authorization enforcement, credential lifecycle handling, legacy remediation UI, and browser acceptance suite
**Verdict**: Approve

## Summary

This change completes Slice P1c across the backend admin API and frontend admin console:
1. Administrative API authorization and validation:
   Super administrators can register clients defaulting to Confidential, Private, and Production and edit client type, access policy, callback environment, redirect URIs, and CORS origins across all four combinations. Scoped app administrators receive HTTP 403 (`ERR_POLICY_FORBIDDEN`) if they attempt to submit V2 policy mutation fields on client detail or app config PATCH endpoints, leaving stored client policy documents unchanged while preserving backwards compatibility for legacy tests that do not send V2 policy fields.
2. Independent policy UI and credential lifecycle:
   Added independent radio/toggle controls in `RegisterAppModal.tsx`, `EditAppModal.tsx`, and filtering/badges in `AdminClients.tsx`, `AdminClientsToolbar.tsx`, and `AdminClientsTable.tsx`. Creation and Public to Confidential upgrades display the plaintext `client_secret` exactly once through `ClientSecretOneTimeCard`. Confidential to Public transitions require explicit confirmation, strip stored secrets, set `token_endpoint_auth_method` to `none`, and immediately revoke active tokens, authorization codes, and token families. Private to Open widening requires explicit confirmation.
3. Legacy compatibility, ambiguity blocking, and classification accuracy:
   Fixed `client-policy.ts` so Confidential Development clients (`isDev: true` with native applicationType mapping) are not falsely classified as ambiguous. Server validation evaluates `validateOAuthClientConfiguration` and canonical `resolveClientPolicy` on candidate updates, blocking `Migrated` promotion with HTTP 400 and safe `reasonCodes` until configuration errors are remediated. Redirect URIs validate inline on blur and block fragment identifiers.

## Security Review Focus

1. Permissions and fail closed boundaries:
   Platform super admin checks remain enforced via `requireSuperAdmin` on collection routes (`GET/POST /api/admin/clients`), and non super admins attempting `clientType`, `accessPolicy`, `tokenEndpointAuthMethod`, `regenerateSecret`, `rotateSecret`, or `policyVersion` mutations on `PATCH /api/admin/clients/:id` or `PATCH /api/admin/app/:clientId/config` are rejected with HTTP 403 prior to database writes.
2. Credential handling:
   Secrets are stripped from client list and detail responses via `stripSensitiveClientFields`, exposing only `hasClientSecret` booleans. Plaintext secrets are emitted solely in creation (`201`) or Public to Confidential generation (`200`) responses. Confidential to Public transitions unset `clientSecret` and clear active access tokens, refresh tokens, codes, and families.
3. Legacy migration guarantees:
   Clients cannot transition to `policyVersion: 2` (`Migrated`) unless server side candidate resolution returns `MIGRATED`. Ambiguous clients render safe reason codes and remediation prompts without leaking internal details or bypasses.

## Verification Evidence

* Backend TypeScript check (`npm run typecheck`): 0 diagnostics.
* Frontend lint and bundle build (`npm --prefix frontend run lint && npm --prefix frontend run build:ui`): 0 ESLint errors, clean production Vite build.
* Unit test suites (`npm run test:unit`): All 16 suites passed, 0 failures.
* P1c admin policy API suite (`npm run test:p1c-admin-api`): 5 passed, 0 failed.
* P1c admin browser acceptance suite (`npm run test:p1c-admin-browser`, Playwright against real backend and static UI): `BAC-P1C-01` through `BAC-P1C-06` passed alongside blur validation, `Confidential` to `Public` secret revocation, and `Public` to `Confidential` one time secret flows.
* Local consumer E2E (`npm run test:local-consumer-e2e`): All 11 flows passed.
* Live browser E2E (`npm run test:browser-e2e`): All 5 phases passed.
* Security test suite harness (`npm run test:all-security`): 42 suites passed, 0 failed.
* Integration contract and docs checks (`npm run security:integration-check && npm run security:docs-check`): 0 violations and 0 errors.
* Rule 7 file size check: Every new and modified backend and frontend source file is strictly under 300 lines.
