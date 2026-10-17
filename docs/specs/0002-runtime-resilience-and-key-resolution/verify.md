# Verify: Runtime resilience and key resolution · spec 0002 · updated 2026-10-14
_Steps derived from spec 0002 acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## Automated commands
- [x] `npm --prefix backend run test:runtime-resilience` → Runs unit test suite asserting connection timeouts and event listeners, bounded public key cache and key identifier isolation, self healing RS256 key generation with fail closed encryption error handling, in flight concurrent token rotation race tolerance, stale rotation lock reclamation, and grace window replay theft cascade revocation with 0 failures → AC-1, AC-2, AC-3, AC-4, AC-5, AC-6
- [x] `npm --prefix backend run test:process-restart` (or `npm run test:process-restart`) → Runs real IdP process restart test retaining disposable database with 0 failures → AC-1, AC-3
- [x] `npm --prefix backend run test:cross-process-refresh` (or `npm run test:cross-process-refresh`) → Runs multi process concurrent consumer refresh test asserting single winner atomic rotation and deterministic reauthentication recovery (HTTP 401 session_expired) with 0 failures → AC-5, AC-6
- [x] `npm --prefix backend run test:network-consumer-e2e` (or `npm run test:network-consumer-e2e`) → Runs live multi process network consumer E2E test suite across Next.js, Express, and IdP with 0 failures → AC-3, AC-5, AC-6
- [x] `npm --prefix backend run test:browser-e2e` (or `npm run test:browser-e2e`) → Runs live Playwright headless Chromium browser test suite against running IdP frontend and consumers verifying real browser cookie behavior, transparent automatic token refresh, and account switching within the same browser context with 0 failures → AC-1, AC-3, AC-5, AC-6
- [x] `npm --prefix backend run test:local-consumer-e2e` → Runs 11 flow in process protocol consumer E2E test suite with 0 failures → AC-1, AC-3, AC-5, AC-6
- [x] `npm --prefix backend run test:all-security:local` (or `npm run test:all-security:local`) → Runs all 14 security test suites locally against in memory MongoDB with 0 failures → AC-1, AC-2, AC-3, AC-4, AC-5, AC-6
- [x] `npm --prefix backend run test:admin-scoping` → Runs admin scoping unit suite asserting role isolation and Super Admin preservation with 0 failures → AC-3
- [x] `npm --prefix backend run security:integration-check` → Verifies integration contract rules and client isolation policies with 0 violations → AC-3, AC-5
- [x] `npm --prefix backend run security:docs-check` → Verifies route manifest and documentation consistency with 0 errors → AC-1, AC-3
- [x] `npm --prefix backend run build` → Backend TypeScript compilation and esbuild bundle generation succeeds with 0 errors → AC-1, AC-2, AC-3, AC-4, AC-5, AC-6

## Acceptance criteria coverage
- AC-1 (resilient connection timeouts and automatic reconnection on dropped sockets): Covered by `test:runtime-resilience` Test 1 and `mongo.ts` connection state resets
- AC-2 (initial connection failure recovery on getDb calls): Covered by `test:runtime-resilience` Test 1 and `mongo.ts` connection state resets
- AC-3 (public key lookup by key identifier with cache and fallback): Covered by `test:runtime-resilience` Test 2, `admin-auth.ts` bounded cache, and token verification routes
- AC-4 (self healing RS256 keypair generation on private key decryption error): Covered by `test:runtime-resilience` Test 3 and `auth.ts` self healing logic with fail closed encryption guards
- AC-5 (concurrent refresh token rotation tolerance within 2000ms grace window): Covered by `test:runtime-resilience` Test 4 and `state.ts` CAS race handling with stale lock reclamation
- AC-6 (token family cascade revocation on replay presentation outside grace window): Covered by `test:runtime-resilience` Test 4 and `state.ts` theft detection

## Value sourcing verification
- Database handle: Verified via `getDb()` returning resilient connection instance, with `database` Proxy forwarder
- Key identifier: Verified via `decodeProtectedHeader(token).kid` passed to `getIdpPublicKey(kid)`
- Cached public key: Verified via bounded in memory `publicKeyCache` in `admin-auth.ts` with FIFO eviction (50 max entries)
- Self healed private key: Verified via `generateAndStoreFreshKeypair` persisting fresh encrypted RS256 doc in `jwks` collection
- Token family status: Verified via atomic compare and swap in `oauth_token_families` preserving active status on concurrent losers and reclaiming stale locks after 15 seconds
