# Review, v2, 2026-11-24

**Reviewed by**: Gemini 3.8 Flash High (author on Gemini 3.8 Flash High / Antigravity; same model fallback disclosed as independent reviewer model is unavailable in this session)
**Scope**: Branch v2, authenticate confidential client before code mutation, process group cleanup for test runner, and bounded database deletion
**Verdict**: Approve

## Summary

This change corrects two critical boundaries in SWYRA Auth:
1. Authentication before code mutation: Ensures that confidential client credentials are fully verified through the installed Better Auth engine before authorization codes are consumed or burned, and before token families are revoked on replay.
2. Robust process group lifecycle and bounded database cleanup: Ensures that when a test suite leader exits while its child descendant ignores SIGTERM, the descendant process is terminated via SIGKILL escalation before database dropping begins. All suite cleanup paths (timeout, interruption signals, and natural exit) coordinate through a unified cleanup routine. Database drop operations enforce an explicit operation deadline alongside connection timeouts.

## Authentication Before Mutation Verification

1. Prevention of Premature Code Consumption:
Previously, the authorization code grant handler invoked `verifyAndConsumeAuthorizationCode` before forwarding the request to the authentication engine. If an attacker supplied an invalid client secret with a valid authorization code, the code was consumed atomically and burned in MongoDB before the engine returned an HTTP 401 error. This prevented the legitimate confidential client from subsequently exchanging its valid code.
With this change, `authenticateTokenClient` verifies confidential client credentials via the installed engine's introspection handler prior to grant delegation. Unauthenticated requests are rejected immediately with HTTP 401 and an appropriate Basic challenge header, leaving the authorization code in pending status.

2. Prevention of Unauthenticated Family Revocation on Replay:
Previously, replaying an already consumed authorization code with incorrect credentials triggered family revocation in `verifyAndConsumeAuthorizationCode`, allowing an unauthenticated attacker to revoke legitimate active user sessions.
With this change, the unauthenticated replay is rejected at client authentication. The active token family remains active and unaffected. When the legitimate client replays the consumed code with valid credentials, client authentication succeeds and replay revocation is correctly executed.

3. Engine Verification Reuse:
The implementation delegates credential validation to `authProvider.handler` on the introspection probe path without implementing competing hash verifiers or weakening atomic single use code consumption.

4. Public Client Preservation:
Public clients continue to authenticate via PKCE S256 verification during code consumption without requiring client secrets. Requests by public clients supplying client secrets continue to be rejected with HTTP 400.

## Process Group and Resource Lifecycle

1. Stubborn Descendant Termination:
On POSIX systems, `terminateProcessGroup` targets the negative process ID `-pid`. If child descendants ignore SIGTERM (such as workers trapping the signal), the runner waits through a bounded grace period and escalates to SIGKILL. The process group is confirmed dead before database dropping begins.

2. Signal Code Detection:
Child termination detection inspects both `exitCode` and `signalCode`. When a process terminates due to SIGKILL or SIGTERM, Node sets `exitCode` to null and records `signalCode`. Checking both ensures terminated processes are recognized immediately without false timeout waits.

3. Unified Coordinated Cleanup:
All termination paths (runner timeout, SIGINT interruption, SIGTERM interruption, and natural suite completion) route through `coordinateSuiteCleanup`. Process group termination is strictly completed before database removal is attempted.

4. Bounded Database Cleanup:
`dropDatabaseBounded` applies `maxTimeMS` to the MongoDB command and wraps the operation in a bounded promise timeout with reliable client closure inside a finally block. Stalled database drops fail within the bounded deadline rather than hanging the test runner.

## Evidence and Verification Results

* Authenticate before mutation reproduction suite (`tests/security/auth-before-mutation-repro.test.ts`): All 3 tests passed.
  * REPRO 1: Wrong Basic secret does not consume code and allows legitimate exchange (passed)
  * REPRO 2: Wrong body client secret does not consume code and allows legitimate exchange (passed)
  * REPRO 3: Replaying code with wrong credentials does not revoke legitimate token family, while legitimate client replay revokes family (passed)
* Security runner lifecycle suite (`tests/security/runner-lifecycle-cleanup.test.ts`): All 4 tests passed.
  * Stubborn descendant ignoring SIGTERM terminated cleanly via SIGKILL escalation (passed)
  * Child exit detected via signalCode when exitCode is null (passed)
  * Bounded database cleanup throws within deadline on stalled connection (passed)
  * Coordinated process termination precedes database removal (passed)
* PKCE enforcement suite (`npm run test:pkce-enforcement`): All 19 tests passed.
* Unit test suites (`npm run test:unit`): All 16 suites passed.
* Local consumer E2E (`npm run test:local-consumer-e2e`): All 11 flows passed.
* Integration contract check (`npm run security:integration-check`): 0 violations.
* Documentation consistency check (`npm run security:docs-check`): 0 errors.
* File line counts: All modified and added source files remain strictly under 300 lines.
* Prose check: Verified zero punctuation hyphens or dashes in added review prose.
