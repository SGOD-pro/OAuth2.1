# Security baseline before identity platform V2

**Date:** 2026-11-19.
**Inspected branch:** `main`.
**Inspected HEAD:** `161ad99ca4ba0de88cff1267b33807db61da306c`.
**Local starting tree:** Clean isolated checkout, created from fetched `origin/main`.
GitHub branch lookup also showed `ui` at the same SHA. No HANDOFF file was found.
**Scope:** Account creation, admin MFA, session/account model, token minting and
introspection, privacy projections, rate-limit fallbacks, current docs and release gates.
**Verdict:** Do not enable the proposed open identity rollout yet. This is a targeted
source review plus bounded local checks, not a full penetration test or certification.
No production probes, database mutations, deployments or runtime fixes were performed.

## Findings

| ID | Priority | Finding and observed evidence | Required action |
|---|---|---|---|
| SEC-01 | High | `mintJwtAccessToken` signs without requiring an existing active verified user. A direct function probe produced verified RS256 tokens for missing, banned, disabled and unverified account fixtures. | Shared account-eligibility guard before mint/issuance commit; real route and race regressions |
| SEC-02 | High, source finding | Introspection returns the plugin response immediately when active, before local status checks. Its JWT fallback checks token presence but does not reject absent/banned/disabled users or check account revocation timestamps before active=true. | Apply one account/client/session/family eligibility contract to both branches; prove real endpoint behavior |
| SEC-03 | High against V2 requirement | Email verification defaults false; signup creates user/account before any mailbox OTP. Enabling verification has no delivery callback configured in the inspected auth instance. Admin sync sets emailVerified=true by provisioning assertion. | Verified registration intents and invitation claiming; do not treat a configuration toggle as implemented OTP enrollment |
| SEC-04 | High against V2 requirement | Admin sync creates app-admins with twoFactorEnabled=false; TOTP plugin is installed, but admin middleware does not require enrollment or MFA freshness. | Mandatory setup-only enrollment and backend MFA checks on all admin/plugin/bearer/social/recovery paths |
| SEC-05 | Medium | Custom access-token minting adds email/name without checking granted email/profile scopes. Scoped admin assigned-user API returns the full email. Audit fields also retain identifiers. | Server-side claim/projection minimization and explicit data inventory; do not rely on UI masking |
| SEC-06 | Medium, availability | Auth-sensitive dual-store failure uses a bounded process-local emergency limiter. Multiple Lambda workers do not share that budget. | Durable sensitive-operation quotas and edge controls; fail closed on unavailable budgets for signup/OTP/recovery |
| SEC-07 | High if copied, documentation | Former Next.js recipe stored unsigned role/identity JSON in app_session; SPA recipe persisted access tokens and omitted complete OIDC validation. No consumer cookie-trust exploit was executed. | Unsafe recipes removed in this docs change; audit executable consumer fixtures separately |

SEC-01 is a reproduced production-function defect using test dependency injection,
not proof that an unauthenticated attacker can directly call the helper. SEC-02 is
source-based and needs endpoint reproduction. Existing management middleware does
perform several account-state checks; do not generalize the finding to every route.
SEC-03/04 are confirmed gaps against the new requirements, not claims that optional
verification/MFA always violated the previous product policy.

### Pinned source evidence

- [Mint and claim projection, auth.ts lines 193 onward](https://github.com/SGOD-pro/OAuth2.1/blob/161ad99ca4ba0de88cff1267b33807db61da306c/backend/src/routes/auth.ts#L193)
- [Introspection, auth.ts lines 1858 onward](https://github.com/SGOD-pro/OAuth2.1/blob/161ad99ca4ba0de88cff1267b33807db61da306c/backend/src/routes/auth.ts#L1858)
- [Signup interceptor, auth.ts lines 728 onward](https://github.com/SGOD-pro/OAuth2.1/blob/161ad99ca4ba0de88cff1267b33807db61da306c/backend/src/routes/auth.ts#L728)
- [Verification configuration, utils/auth.ts lines 112 onward](https://github.com/SGOD-pro/OAuth2.1/blob/161ad99ca4ba0de88cff1267b33807db61da306c/backend/src/utils/auth.ts#L112)
- [Admin provisioning, admin-sync.ts lines 122 onward](https://github.com/SGOD-pro/OAuth2.1/blob/161ad99ca4ba0de88cff1267b33807db61da306c/backend/src/utils/admin-sync.ts#L122)
- [Admin authorization middleware](https://github.com/SGOD-pro/OAuth2.1/blob/161ad99ca4ba0de88cff1267b33807db61da306c/backend/src/middleware/admin-auth.ts)
- [Assigned user projection, admin.ts lines 1981 onward](https://github.com/SGOD-pro/OAuth2.1/blob/161ad99ca4ba0de88cff1267b33807db61da306c/backend/src/routes/admin.ts#L1981)
- [Rate limiter fallback, rate-limit.ts](https://github.com/SGOD-pro/OAuth2.1/blob/161ad99ca4ba0de88cff1267b33807db61da306c/backend/src/middleware/rate-limit.ts)
- [Former integration recipes at inspected HEAD](https://github.com/SGOD-pro/OAuth2.1/blob/161ad99ca4ba0de88cff1267b33807db61da306c/docs/INTEGRATION.md#L335)

## Independently executed checks

Node.js `v24.22.3`. Reused installed backend dependencies with a byte-identical
package-lock SHA-256 `ffd95c4de1437dce136d8676609b9a44cf7f4ffc9e4b2a121b20441c7eaccad3`.
No production environment file was loaded. The dependency reuse is not a fresh npm
registry vulnerability audit.

| Check | Observed outcome |
|---|---|
| `node --import tsx scripts/check-security-doc-consistency.ts` from backend | PASS, 6 checks both before and after documentation edits |
| `node --import tsx ../scripts/security/check-integration-contract.ts` from backend | PASS, 5 checks both before and after documentation edits |
| `node --import tsx tests/unit/security-utils.test.ts` | PASS, 8 checks |
| `node --import tsx tests/unit/admin-scoping.test.ts` | PASS; mocked unit suite, not real MongoDB/HTTP coverage |
| Direct `mintJwtAccessToken` probe with `setTestDbOverride` and test signing-key override | Signed tokens verified for all 4 ineligible account fixtures; email included for scope=openid in the banned-email fixture |
| `node --import tsx tests/unit/admin-isolation-policy.test.ts` | BLOCKED before assertions: MongoMemoryServer process SIGABRT |
| `node --import tsx tests/security/nosql-injection-boundary.test.ts` | BLOCKED before assertions: MongoMemoryServer process SIGABRT |

Normal npm scripts invoking the tsx CLI first failed creating its IPC pipe with EPERM.
The loader invocation above avoids that CLI pipe without changing test source.
Database-backed tests remained blocked. Do not count blocked suites as passed or
attribute the MongoDB process abort to a demonstrated application defect.

### SEC-01 reproduction method

Run as a temporary ESM TypeScript script with `node --import tsx` from backend.
Set test-only environment values for NODE_ENV, MONGO_URI, BETTER_AUTH_SECRET,
BETTER_AUTH_URL, FRONTEND_URL, GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET. Do not use
production configuration. Import the real functions below, generate an ephemeral
RS256 keypair, and restore overrides/close the client after completion.

```typescript
// Imports are relative to backend for an equivalent local scratch probe.
import assert from "node:assert/strict";
import { generateKeyPair, jwtVerify } from "jose";
import { setTestDbOverride, closeDb } from "./src/db/mongo";
import { mintJwtAccessToken, setSigningKeyOverrideForTesting } from "./src/routes/auth";

const keys = await generateKeyPair("RS256");
setSigningKeyOverrideForTesting(async () => ({ privateKey: keys.privateKey, kid: "audit-only" }));
let user: any = null;
setTestDbOverride({
  collection: (name: string) => ({
    findOne: async () => name === "user" ? user : null,
    find: () => ({ toArray: async () => [] }),
  }),
} as any);
try {
  for (const fixture of [
    null,
    { id: "audit-user", role: "user", banned: true, email: "audit@example.invalid" },
    { id: "audit-user", role: "user", disabled: true },
    { id: "audit-user", role: "user", emailVerified: false },
  ]) {
    user = fixture;
    const token = await mintJwtAccessToken({ userId: "audit-user", clientId: "audit-client", scope: "openid" });
    assert.ok(token); // Observed unsafe baseline; fixed behavior must reject.
    await jwtVerify(token, keys.publicKey, {
      issuer: process.env.BETTER_AUTH_URL, audience: "audit-client", algorithms: ["RS256"],
    });
  }
} finally {
  setSigningKeyOverrideForTesting(null);
  setTestDbOverride(null);
  await closeDb();
}
```

## Previously reported evidence, not independently rerun

The existing November 15 review reports consumer MFA 18 passing, private isolation
10 passing, session expiry 5 passing, backend builds and unit suites passing. The
user also reported Redis CORS 49 passing and infrastructure isolation 6 passing.
These summaries are not independent verification of the current runtime in this turn.

## Release gaps and limits

- No complete dependency/CVE audit, secret-history scan, external penetration test,
  live gateway/WAF review, browser chooser test, production-key audit or deletion
  restore drill was performed. These remain release tasks.
- README claimed MIT, but no tracked LICENSE file was found at the inspected HEAD.
  Confirm ownership/dependency provenance and add an explicit license before claiming
  a complete open-source release. README now records this gate rather than licensing
  the project on the owner's behalf.
- CI pull_request paths currently omit docs-only changes. The required local doc
  checks were run; enabling a docs-only CI gate is a tracked release follow-up.
- Historic docs contain security claims broader than current evidence. Updated
  canonical docs distinguish inspected behavior from required V2 controls.

Next runtime step: phase 0 of [PHASES.md](../PHASES.md), account eligibility across
minting, code/refresh, UserInfo and both introspection branches. Preserve current
private/admin policy until its separate audited migration.
