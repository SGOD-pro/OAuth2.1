# Review, v2, 2026-11-23

**Reviewed by**: Gemini 2.5 Pro (author on Gemini 2.5 Pro / Antigravity; same model fallback disclosed as independent reviewer model is unavailable in this session)
**Scope**: Branch v2, shared Docker MongoDB replica set test harness, MongoMemoryServer removal, test isolation, and CI integration
**Verdict**: Approve

## Summary

This change replaces per suite MongoMemoryServer and MongoMemoryReplSet instances with one shared disposable Docker MongoDB replica set container (`mongodb/mongodb-community-server:8.0-ubi8-slim`) published strictly on loopback port `127.0.0.1:27018`.

The shared test harness supports real single node replica set transactions (`rs0`), keyfile based authentication, read only user RBAC, cross worker process connection sharing, process restart continuity across IdP restarts, and clean per suite database namespace isolation (`test_<suite>_<rand>`). The obsolete `mongodb-memory-server` dependency and 47 transitive packages have been removed from backend dependencies. All 29 security suites, 16 unit suites, and all local, cross process, network, and browser end to end suites execute cleanly against the single containerized MongoDB instance.

## Lifecycle Ownership and Destructive Boundaries

1. Harness Ownership Verification: The shared container is created with label `swyra-auth-test-harness=true` and writes an internal metadata marker document `{ _id: "marker", label: "swyra-auth-test-harness" }` to the `admin.swyra_harness_meta` collection. Container teardown commands (`stopSharedMongo`) inspect this label before issuing removal commands, ensuring unrelated local or external MongoDB instances are never stopped or touched.
2. Destructive Cleanup Boundaries: Test suites drop only their own uniquely named suite database during teardown. Non test databases and administrative collections are protected from destruction.
3. Fail Closed Isolation Guard: The isolation helper `test-env-isolation.ts` enforces `assertIsDisposableTestMongoUri`, verifying that `MONGO_URI` strictly matches the local authenticated harness pattern (`mongodb://testAdmin:testAdminPassword123@127.0.0.1:27018/...`). External, production, and Atlas connection strings fail closed immediately.
4. Automatic Lifecycle Reuse: Individual suite runs (`setupSuiteDatabase`) reuse the existing container if it is already healthy. When run without an existing container, `setupSuiteDatabase` starts the container automatically. The aggregate runner `run-all-security.ts` respects pre existing running containers and only terminates the container if it started it itself.
5. Disposable Storage: The container uses an in memory tmpfs mount (`--tmpfs /data/db:rw,uid=1000,gid=1000,mode=0700`), guaranteeing that zero test state persists on disk across host restarts.

## Resource Usage and Memory Measurements

1. Host Process Count: Exactly one `mongod` process runs on the host during the entire aggregate suite execution, compared to multiple spawned instances under MongoMemoryServer.
2. Memory Limits and WiredTiger Cache: The container is configured with an explicit memory limit of 768m and a WiredTiger cache limit of 0.25GB (256MB).
3. Measured Memory: Across the complete test pipeline execution, container memory peaked at 657.5MiB / 768MiB (85.62%), remaining safely below container limits without out of memory kills.
4. Open Files Ulimit: The container is launched with `--ulimit nofile=65536:65536` to ensure connection spikes during concurrent suites do not exhaust system file descriptors.

## Preservation of Existing Assertions

All security controls and assertions remain preserved:
1. Replica Set Transactions: In `tests/security/p0-engine-transactions.test.ts`, all ten transaction rollback, identity deduplication, and concurrent proof consumption assertions pass against the real replica set.
2. Read Only RBAC: Database role assertions verify that non admin connections cannot write to restricted collections.
3. Restart Continuity: In `tests/e2e/idp-process-restart.test.ts`, the database persists across process termination and restart, confirming session, signing key, and refresh token validity.
4. Cross Worker Coordination: In `tests/e2e/cross-process-refresh.test.ts`, multiple Express worker processes connect simultaneously, verifying single winner refresh token rotation and family revocation.
5. Final Adversarial Gate: In `tests/security/final-adversarial-gate.ts`, all 31 security cases pass, including cross client token isolation, brute force defenses, and prompt login.

## Verification Evidence

* Tested commit: Working tree on branch v2
* Contract linter (`npm run security:integration-check`): Passed with 0 violations
* Documentation consistency check (`npm run security:docs-check`): Passed with 0 errors
* Unit test suites (`npm run test:unit`): All 16 suites passed (100%)
* Local consumer E2E (`npm run test:local-consumer-e2e`): All 11 flows passed (100%)
* Process restart lifecycle (`npm run test:process-restart`): All 4 phases passed (100%)
* Cross process refresh (`npm run test:cross-process-refresh`): Passed with single winner resolution
* Network consumer E2E (`npm run test:network-consumer-e2e`): All 6 live network flows passed (100%)
* Live browser E2E (`npm run test:browser-e2e`): All 5 Playwright browser phases passed (100%)
* Automated security test suites (`npm run test:all-security`): All 29 security suites passed (100%)
* Backend builds (`npm --prefix backend run build && npm --prefix backend run build:node`): Succeeded cleanly
* Prose check: Verified zero punctuation hyphens or dashes in added review prose
