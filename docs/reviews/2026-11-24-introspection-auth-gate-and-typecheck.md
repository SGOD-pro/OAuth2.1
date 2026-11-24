# Review, v2, 2026-11-24

**Reviewed by**: Gemini 3.8 Flash High (author on Gemini 3.8 Flash High / Antigravity; same model fallback disclosed as independent reviewer model is unavailable in this session)
**Scope**: Branch v2, introspection authentication gating, response shape enforcement, header preservation, typecheck configuration, CI changes, and test isolation
**Verdict**: Approve

## Summary

This change closes the remaining introspection authentication gate and evidence gaps before P1c:
1. Introspection caller authentication gating and response shape enforcement:
   In auth-introspect.ts, custom RS256 JWT validation previously proceeded after engine responses other than 400, 401, and >=500. It now requires an explicit successful engine authentication probe before entering custom JWT validation. All non-200 responses from the engine are preserved directly, including HTTP 403 forbidden and HTTP 429 rate limits along with their response headers such as Retry-After. Malformed HTTP 200 responses lacking boolean active properties fail closed with HTTP 502 server_error. Sentinel probe responses that unexpectedly return active true fail closed with HTTP 502. Engine exceptions and connection crashes fail closed with HTTP 503 server_error. An otherwise valid stored JWT never returns active true under any engine error, outage, or non-200 status.
2. Controlled engine failure testing and outage fixture:
   A dedicated regression suite tests controlled engine responses for HTTP 403, HTTP 429 with Retry-After, HTTP 500, malformed HTTP 200, unexpected sentinel active true, and thrown exceptions. Genuine engine execution is preserved and verified for valid Basic credentials, invalid Basic credentials, and invalid body credentials. The misleading nonexistent client credential rejection test in userinfo-introspect-auth.test.ts was replaced with an authentic engine outage fixture throwing an error and returning HTTP 503.
3. Reproducible backend TypeScript typecheck:
   Added a declared typescript compiler dependency in backend/package.json. Configured typecheck script executing tsc with noEmit against tsconfig.json. Added a dedicated typecheck step in CI keeping bundling and typechecking as separate checks.

## Architecture and Gating Invariants

1. Caller Authentication Gating:
   When introspecting custom RS256 access tokens, caller authentication is authoritatively established via sentinel token probe sent to the engine handler.
   Only when the engine authenticates the caller and returns HTTP 200 with active false does execution proceed to custom JWT verification.
   Engine rejections (HTTP 401 for invalid Basic credentials, HTTP 400 for invalid body credentials, HTTP 403 forbidden) are returned directly without entering custom JWT logic.
   Engine rate limits (HTTP 429) are returned directly, preserving status and rate limit headers such as Retry-After.
   Engine internal errors (HTTP 500) and thrown exceptions fail closed with server_error status and never return active true.

2. Response Shape Enforcement:
   HTTP 200 responses from the engine are parsed and strictly checked for a valid object containing a boolean active property.
   Malformed or non-JSON payloads fail closed with HTTP 502 server_error.
   If the sentinel probe returns active true, the unexpected response is rejected with HTTP 502 server_error.

3. Typecheck Isolation and CI:
   Backend typechecking runs via a declared compiler dependency (typescript version 5.8.3).
   Typecheck is executed independently in CI before building bundles, separating static type verification from compilation artifacts.

## Verification Evidence

* Introspection controlled failures suite (`tests/security/introspect-controlled-failures.test.ts`): All 9 tests passed.
  * Preserves engine HTTP 403 response and headers, never active true (passed)
  * Preserves engine HTTP 429 rate limit response and Retry-After header, never active true (passed)
  * Fails closed on engine HTTP 500 error, never active true (passed)
  * Fails closed (502) on malformed engine HTTP 200 payload lacking active boolean (passed)
  * Fails closed (502) when sentinel probe unexpectedly returns active true (passed)
  * Fails closed (503) when engine handler throws unexpected exception (passed)
  * Succeeds with genuine engine probe for valid Basic credentials (200 active true) (passed)
  * Rejects with genuine engine for invalid Basic credentials (401) (passed)
  * Rejects with genuine engine for invalid body credentials (400) (passed)
* UserInfo and Introspection regression suite (`tests/security/userinfo-introspect-auth.test.ts`): All 11 tests passed, including the replaced genuine engine outage fixture.
* TypeScript checking: `npm run typecheck` (`tsc --project tsconfig.json --noEmit`) exited with 0 diagnostics.
* Unit test suites (`npm run test:unit`): All 16 suites passed.
* Local consumer E2E (`npm run test:local-consumer-e2e`): All 11 flows passed.
* Integration contract check (`npm run security:integration-check`): 0 violations.
* Documentation consistency check (`npm run security:docs-check`): 0 errors.
* Rule 7 compliance: All modified and new production and test source files remain strictly under 300 lines.
* Prose invariant: Verified zero punctuation hyphens or dashes across review prose.
