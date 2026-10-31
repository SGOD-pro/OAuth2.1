# Verify: Explicit administrator identities and portal isolation (spec 0007)

## UI and manual
- [x] Sign in to MAuth console as super admin, verify access granted (AC-1, AC-6)
- [x] Sign in to consumer application as app admin, verify access granted (AC-1, AC-4)
- [x] Attempt MAuth console sign in as app admin, verify access denied (AC-2, AC-6)
- [x] Perform OAuth 2.1 code flow with PKCE in real browser, verify callback and token minting (AC-1, AC-3)
- [x] Test account switching in real browser using prompt=login, verify clean identity transition (AC-8)

## Commands
- [x] `npm run test:all-security` -> all 21 suites pass (AC-1, AC-2, AC-3, AC-4, AC-5, AC-6, AC-7)
- [x] `npm run test:browser-e2e` -> all 5 real browser phases pass (AC-1, AC-3, AC-4, AC-8)
- [x] `MONGO_URI="mongodb+srv://hostile/prod" tsx backend/tests/security/final-adversarial-gate.ts` -> 31 passed (AC-1, AC-2, AC-5)
- [x] `tsx backend/tests/security/cors-cache-correctness.test.ts` -> 8 passed (AC-5)
- [x] `tsx backend/tests/security/membership-lifecycle.test.ts` -> 6 passed (AC-4, AC-6)
- [x] `tsx backend/scripts/measure-performance-baseline.ts` -> latency and indexes confirmed (AC-5)

## Acceptance criteria coverage
- AC-1 Domain roles enforced across backend routes, session handlers, and token generation: met
- AC-2 Super admin and app admin mutual exclusion enforced: met
- AC-3 Consumer token role resolution isolates super admins from app admin privileges: met
- AC-4 Authoritative user identifier keys for app admin records: met
- AC-5 Structured error codes and request identifiers on management routes: met
- AC-6 Central platform routes strictly require super admin authority: met
- AC-7 Idempotent migration script with audit and apply modes: met
- AC-8 Frontend console guards fail closed without loops: met

