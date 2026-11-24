# Review, v2, 2026-11-24

**Reviewed by**: Gemini 3.8 Flash High (author on Gemini 3.8 Flash High / Antigravity; same model fallback disclosed as independent reviewer model is unavailable in this session)
**Scope**: Branch v2, UserInfo engine success handling repair, accDoc scoping, client context gating, introspection caller authentication gating, engine error preservation, and TypeScript diagnostics resolution
**Verdict**: Approve

## Summary

This change repairs UserInfo engine success handling and introspection caller authentication gating before P1c:
1. UserInfo engine success path repaired:
   accDoc was previously declared inside a try block and referenced outside, causing ReferenceError and stream consumption exceptions. accDoc is now cleanly scoped. Validated client context is strictly required before returning protected claims; missing client audience fails closed with HTTP 401 invalid_token. Query client_id parameter substitution is strictly rejected with HTTP 400 invalid_request. Unassigned private client access returns HTTP 403 forbidden. Revoked token families return HTTP 401. Failures return fresh unconsumed responses.
2. Proven caller authentication for introspection:
   Introspection now strictly preserves engine client authentication failures, including HTTP 401 for invalid Basic credentials or missing credentials, and HTTP 400 invalid_client for wrong request body secrets. Engine outages and 500 errors never return active true. For custom RS256 access tokens, caller authentication is authoritatively proven through the engine handler probe before token claims are inspected. Request client_id alone is strictly insufficient. Cross client token introspection returns active false per RFC 7662 Section 4.
3. Backend TypeScript checking:
   Backend TypeScript checking verified clean with zero diagnostics across the entire backend source tree using the repository tsconfig configuration.

## UserInfo Engine Success Architecture

1. Scoping and Response Stream Safety:
   accDoc lookup is scoped safely in outer function scope, making authoritative database token metadata available during client audience resolution.
   If parsing fails or an unhandled exception occurs, fresh error responses are returned, completely preventing Response body already used runtime errors.

2. Client Context Requirement:
   Protected user claims are never returned without an authoritative target client context. Tokens lacking client audience fail closed with HTTP 401 invalid_token.
   Private client membership is verified against user_app_registrations, returning HTTP 403 forbidden when assignment has been deleted.

## Introspection Caller Authentication Gating

1. Engine Failure Preservation:
   Engine authentication rejections (HTTP 401 for Basic auth and missing credentials, HTTP 400 for body secrets) are returned directly, preserving the security gate.
   Engine internal errors and outages (HTTP 500) never fall through to JWT verification and never return active true.

2. Proven Caller Verification:
   When evaluating custom RS256 access tokens, caller authentication is verified against the installed engine via sentinel token probe.
   Unauthenticated callers or confidential clients presenting client_id without valid credentials fail closed with HTTP 401 or 400 invalid_client.
   Valid authenticated callers inspect only tokens issued to their own client identifier; cross client requests return active false.

## Verification Evidence

* UserInfo and Introspection regression suite (`tests/security/userinfo-introspect-auth.test.ts`): All 11 tests passed.
  * UserInfo engine success allows valid access for authorized member on private client (passed)
  * UserInfo engine success denies access with HTTP 403 when private client assignment is deleted (passed)
  * UserInfo engine success rejects query client substitution with HTTP 400 (passed)
  * UserInfo engine success fails closed with HTTP 401 when client context is missing (passed)
  * Introspection rejects unauthenticated caller with missing credentials with HTTP 401 (passed)
  * Introspection rejects confidential caller supplying client_id without client_secret with HTTP 401 (passed)
  * Introspection preserves engine rejection for wrong Basic credentials with HTTP 401 (passed)
  * Introspection preserves engine rejection for wrong body credentials with HTTP 400 (passed)
  * Introspection denies cross client token introspection with HTTP 200 active false (passed)
  * Introspection allows valid authenticated caller to introspect their own RS256 token with HTTP 200 active true (passed)
  * Introspection fails closed and never returns active true on engine error (passed)
* TypeScript checking: `./frontend/node_modules/.bin/tsc --project backend/tsconfig.json --noEmit` exited with 0 diagnostics.
* Unit test suites (`npm run test:unit`): All 16 suites passed.
* Local consumer E2E (`npm run test:local-consumer-e2e`): All 11 flows passed.
* Integration contract check (`npm run security:integration-check`): 0 violations.
* Documentation consistency check (`npm run security:docs-check`): 0 errors.
* Rule 7 compliance: All modified and new production and test source files remain strictly under 300 lines.
* Prose invariant: Zero punctuation hyphens or dashes in review prose.
