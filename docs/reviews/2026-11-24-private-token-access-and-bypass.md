# Review, v2, 2026-11-24

**Reviewed by**: Gemini 3.8 Flash High (author on Gemini 3.8 Flash High / Antigravity; same model fallback disclosed as independent reviewer model is unavailable in this session)
**Scope**: Branch v2, private client authoritative active assignment, token derived client binding, independent membership removal verification, and open app bypass flow completion
**Verdict**: Approve

## Summary

This change closes critical private token access gaps and completes open app bypass flow evidence before P1c:
1. Authoritative active assignment: Every private client (both explicit V2 private records and compatible legacy private records where isPublic is false) requires authoritative active assignment. Empty assignment collections strictly deny access. The isExplicit loophole in checkPrivateAppTokenAccess has been completely eliminated. Missing, disabled, or ambiguous target clients fail closed.
2. UserInfo client binding: Target client context in UserInfo is derived strictly from validated token claims or authoritative engine records. Query client_id parameter substitution is strictly rejected with HTTP 400 when it does not match the token client context.
3. Independent membership removal verification: Membership removal has been verified independently. Active credentials were issued, membership removed, and UserInfo and token introspection probed before attempting refresh. Deletion, explicit revocation, app admin assignments, legacy and V2 private clients, and super admin exclusions were all exercised. Refresh denial with HTTP 401 and token family revocation in storage were separately verified.
4. Open app bypass flow completion: Consent required authorization, MFA continuation, and social callback flows were exercised under controlled provider fixtures. When bypass is enabled, all flows succeed with zero ambient writes in user_app_registrations. When bypass is disabled, compatibility registration rows are recorded reliably.

## Policy Ownership and Token Derived Client Binding

1. Authoritative Resolution:
UserInfo and token introspection now derive target client context directly from validated access token claims or authoritative engine account records.
Supplying a query parameter client_id that mismatches the token client context is rejected with HTTP 400 invalid_request.
Target client lookup validates that the client exists, is not disabled, and is not ambiguous; otherwise UserInfo returns HTTP 401 and introspection returns active false.

2. Elimination of isExplicit Loophole:
Previously, legacy private clients without isExplicit set to true could fall through to a check that allowed access when assignment collections were empty.
Removing this loophole ensures that every private client requires active registration or admin assignment, while preserving super admin exclusion and revocation precedence.

## Independent Membership Removal Evidence

1. UserInfo and Introspection Probe Before Refresh:
Tests prove that immediately upon assignment deletion or explicit revocation, UserInfo returns HTTP 403 and token introspection returns active false, while the token family in storage remains active until refresh is attempted.

2. Refresh Denial and Token Family Revocation:
Subsequent refresh token presentation on the private client fails with HTTP 401 invalid_grant, and the token family is immediately marked as revoked in MongoDB storage.

## Evidence and Verification Results

* Private token access regression suite (`tests/security/private-token-access.test.ts`): All 6 tests passed.
  * Compatible legacy private client denies UserInfo (403) and introspection (active false) on assignment deletion, followed by refresh denial (401) and family revocation (passed)
  * Explicit private client denies UserInfo (403) and introspection (active false) on explicit revocation, followed by refresh denial (401) and family revocation (passed)
  * Query client_id substitution is rejected without overriding token client context (passed)
  * Missing, disabled, or ambiguous target clients fail closed (passed)
  * App admin only assignment authorized and denied when assignment removed before refresh (passed)
  * Super admin strictly excluded from private app token access even if assignment exists (passed)
* Open app bypass flows regression suite (`tests/security/open-app-bypass-flows.test.ts`): All 3 tests passed.
  * Consent required authorization exercises zero ambient writes when enabled, and records compatibility row when disabled (passed)
  * MFA continuation exercises zero ambient writes when enabled, and records compatibility row when disabled (passed)
  * Social callback exercises zero ambient writes when enabled, and records compatibility row when disabled (passed)
* Unit test suites (`npm run test:unit`): All 16 suites passed.
* Local consumer E2E (`npm run test:local-consumer-e2e`): All 11 flows passed.
* Full security suite (`npm run test:all-security`): All 39 security suites passed (100 percent).
* Integration contract check (`npm run security:integration-check`): 0 violations.
* Documentation consistency check (`npm run security:docs-check`): 0 errors.
* Source file rules: All modified and new production and test source files remain strictly under 300 lines.
* Prose check: Verified zero punctuation hyphens or dashes in added review prose.
