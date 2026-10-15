# Scope: SWYRA OAuth 2.1 Identity Provider Remediation

Remediation plan to resolve post deployment authentication lockouts, decouple multi tenant administrator identities, enable zero deploy local testing, and simplify client configuration.

**Build approach:** Tracer Bullet (vertical slices where each fix is built and verified through backend logic, database state, admin interface, and security tests).
**Workflow:** GA (after /develop, run /check verify, /test, a fresh model /check review, then /document). The project default level of rigor. /architect is the recommended first stop for a feature with a real decision, but skippable when you already know the build. Any feature can carry its own tag to do more or less.

_These are recommendations to keep your build orderly, not requirements. Skip anything that does not fit: if you already know how to build a feature, use /develop and skip /architect. You decide when a feature is `done`._

## At a glance

| # | Feature | Phase | Status |
|---|---------|-------|--------|
| A | OAuth 2.1 protocol engine | Foundation | existing |
| B | Multi tenant client registry | Foundation | existing |
| C | Admin console interface | Foundation | existing |
| D | Deployment and edge proxy | Foundation | in-progress |
| 1 | Admin identity decoupling and role scoping | Slice 1 | done |
| 2 | Runtime resilience and key resolution | Slice 2 | done |
| 3 | Gateway secret persistence and deploy pipeline | Slice 3 | done |
| 4 | Dev isolation and dual mode client URIs | Slice 4 | done |
| 5 | Application configuration simplification | Slice 5 | done |

## Existing foundations

### A. OAuth 2.1 protocol engine · existing
Core authorization server implementing authorization code flow with PKCE S256, token minting, userinfo, revocation, introspection, and offline RS256 token verification.
code in `backend/src/routes/auth.ts` and `backend/src/db/state.ts`

### B. Multi tenant client registry · existing
Client registration storage, public and confidential client profiles, cryptographic secret hashing, and application membership tracking.
code in `backend/src/routes/admin.ts` and `backend/src/utils/security.ts`

### C. Admin console interface · existing
Management dashboard for OAuth clients, redirect URIs, application administrators, and operational metrics.
code in `frontend/src/` and `frontend/pages/admin/`

### D. Deployment and edge proxy · in-progress
AWS Lambda backend deployment and Vercel edge proxy routing with internal gateway secret authentication. Finish resolving cold start and proxy configuration persistence via /develop.
code in `backend/deploy.sh` and `scripts/prepare-vercel-config.mjs`

## Slice 1: Admin identity decoupling and role scoping

### 1. Admin identity decoupling and role scoping · done
Separate global super admin status from per application consumer admin assignments so cold starts never demote main administrators or cross assign permissions between clients.
**Done when:** global super admins never lose unscoped status during identity sync, per client admin roles resolve dynamically at token minting and userinfo, and admin login cleanly resets scoped sessions.
- [x] Design it (spec): `/architect admin identity decoupling and role scoping`
- [x] Build it: `/develop admin identity decoupling and role scoping`
   - [x] Guard Super Admin accounts and track multi app memberships in identity sync (AC-1, AC-2, AC-4)
   - [x] Implement dynamic per client role resolution in OAuth token and userinfo routes (AC-3)
   - [x] Support multi app administration in scoped admin middleware and token checks (AC-7)
   - [x] Update admin creation and migration scripts with Super Admin conflict guards (AC-6)
   - [x] Clean up admin console login session handling for scoped accounts (AC-5)
- [x] Verify it: `/check verify admin identity decoupling and role scoping`
- [x] Test it: `/test admin identity decoupling and role scoping`
- [x] Review it (fresh model): `/check review admin identity decoupling and role scoping`
- [x] Document it: `/document admin identity decoupling and role scoping`
[0001](../specs/0001-admin-identity-decoupling-and-role-scoping/index.md) · code in `backend/src/utils/admin-sync.ts`, `backend/src/routes/auth.ts`, `backend/src/middleware/admin-auth.ts`, `frontend/pages/admin/AdminLogin.tsx`

## Slice 2: Runtime resilience and key resolution

### 2. Runtime resilience and key resolution · done
Harden MongoDB connection pooling across idle pauses, match JWKS signing keys by kid header with graceful fallback, and tolerate token refresh concurrency without false revocation.
**Done when:** database connections automatically recover on dropped sockets, token verification resolves rotated keys by kid without falling back to opaque tokens, and concurrent refresh requests within grace window return clean errors without family revocation.
- [x] Design it (spec): `/architect runtime resilience and key resolution`
- [x] Build it: `/develop runtime resilience and key resolution`
   - [x] Configure resilient MongoDB connection pooling and dropped socket recovery (AC-1, AC-2)
   - [x] Match JWKS public signing keys by token header key identifier with in memory cache (AC-3)
   - [x] Implement self healing RS256 keypair generation on private key decryption error (AC-4)
   - [x] Tolerate concurrent refresh token requests within grace window without family revocation (AC-5, AC-6)
- [x] Verify it: `/check verify runtime resilience and key resolution`
- [x] Test it: `/test runtime resilience and key resolution`
- [x] Review it (fresh model): `/check review runtime resilience and key resolution`
- [x] Document it: `/document runtime resilience and key resolution`
[0002](../specs/0002-runtime-resilience-and-key-resolution/index.md) · code in `backend/src/db/mongo.ts`, `backend/src/middleware/admin-auth.ts`, `backend/src/routes/auth.ts`, `backend/src/db/state.ts`

## Slice 3: Gateway secret persistence and deploy pipeline

### 3. Gateway secret persistence and deploy pipeline · done
Guarantee that Vercel builds generate internal gateway secrets across all Git and manual deploys, and pass gateway secrets in AWS Lambda deployment scripts.
**Done when:** frontend build runs prepare-vercel-config with if-present flag on all Vercel deployments, and backend deployment script enforces and passes gateway secret parameter overrides.
- [x] Build it: `/develop gateway secret persistence and deploy pipeline`
   - [x] Support if-present flag and LAMBDA_BACKEND_URL in scripts/prepare-vercel-config.mjs
   - [x] Integrate prepare-vercel-config with if-present into frontend build script
   - [x] Validate and pass gateway secret parameter overrides in backend/deploy.sh
- [x] Verify it: `/check verify gateway secret persistence and deploy pipeline`
- [x] Review it (fresh model): `/check review gateway secret persistence and deploy pipeline`
- [x] Document it: `/document changelog`
[0003](../specs/0003-gateway-secret-persistence-and-deploy-pipeline/verify.md) · code in `scripts/prepare-vercel-config.mjs`, `frontend/package.json`, `backend/deploy.sh`

## Slice 4: Dev isolation and dual mode client URIs

### 4. Dev isolation and dual mode client URIs · done
Enable zero deploy local testing by allowing development clients to register both loopback and HTTPS redirect URIs, allowing loopback gateway bypass in local development, and fixing environment templates.
**Done when:** development clients permit both loopback and HTTPS redirect URIs, unconfigured gateway secret permits loopback calls in development mode, and local startup scripts launch cleanly.
- [x] Design it (spec): `/architect dev isolation and dual mode client URIs`
- [x] Build it: `/develop dev isolation and dual mode client URIs`
   - [x] Allow loopback and valid HTTPS URIs on development clients in security validator (AC-1, AC-2)
   - [x] Permit Super Admins to provision dev clients in production without global flag (AC-3)
   - [x] Implement environment aware loopback gateway bypass in admin auth middleware (AC-4, AC-5)
   - [x] Align root .env.example with development defaults and shared gateway secret (AC-6)
   - [x] Fix directory paths in startup scripts and add convenience npm scripts (AC-7)
- [x] Verify it: `/check verify dev isolation and dual mode client URIs`
- [x] Test it: `/test dev isolation and dual mode client URIs`
- [x] Review it (fresh model): `/check review dev isolation and dual mode client URIs`
- [x] Document it: `/document dev isolation and dual mode client URIs`
[0004](../specs/0004-dev-isolation-and-dual-mode-client-uris/index.md) · code in `backend/src/utils/security.ts`, `backend/src/middleware/admin-auth.ts`, `backend/src/config/index.ts`, `start-all.sh`, `.env.example`, `backend/tests/unit/dev-isolation.test.ts`

## Slice 5: Application configuration simplification

### 5. Application configuration simplification · done
Reduce application onboarding friction by automatically deriving allowed CORS origins from redirect URIs and standardizing client field naming.
**Done when:** creating or editing an OAuth client automatically derives CORS origins from redirect URIs on both backend and frontend, and client document field mapping is centralized.
- [x] Build it: `/develop application configuration simplification`
   - [x] Auto derive allowed CORS origins from redirect URIs in backend validator and routes (AC-1, AC-2, AC-3, AC-4)
   - [x] Centralize client document field mapping across camelCase and snake_case (AC-5)
   - [x] Provide auto derivation and sync helper in frontend admin console (AC-6)
   - [x] Verify origin derivation and field normalization with automated unit tests (AC-1, AC-2, AC-3, AC-4, AC-5)
- [x] Verify it: `/check verify application configuration simplification`
- [x] Test it: `/test application configuration simplification`
- [x] Review it (fresh model): `/check review application configuration simplification`
- [x] Document it: `/document application configuration simplification`
[0005](../specs/0005-application-configuration-simplification/index.md) · code in `backend/src/utils/security.ts`, `backend/src/routes/admin.ts`, `frontend/pages/admin/RegisterAppModal.tsx`, `frontend/pages/admin/EditAppModal.tsx`, `backend/tests/unit/config-simplification.test.ts`

## Deferred
Out of scope for the current remediation slice, kept so the plan stays honest.
- **Consumer sample app test harness**: automated end to end integration test suites executing sample consumer apps against the live identity provider · needs a decision · GA
- **Developer self service portal**: self service registration portal for external developers to request client credentials without main admin console access · needs a decision · GA

## Legend

**The decision box.** Every feature carries exactly one, the sub task whose label ends with `(spec)`. Its wording varies (`Design it (spec)` normally, `Decide the stack (spec)` on Stack & architecture), so skills locate it by that `(spec)` suffix, never by an exact label. Every other box is an execution box and /architect never ticks one.

**Feature lifecycle**: the scope updates as a feature moves; each row is what it shows and who sets it:

| State | Set by | The feature shows |
|---|---|---|
| `planned` · needs a decision | /scope | one box: `Design it (spec): /architect <feature>` |
| `in-progress` (designed) | **/architect at spec capture** | `Design it` ticked; spec linked; `Build it: /develop <feature>` + **2 to 5 milestones**; the tier's closing boxes (`Verify it` Alpha+, `Test it` Beta+, `Review it` + `Document it` GA); any surfaced follow up enrolled |
| `in-progress` (building) | /develop | milestone sub boxes tick one by one; code pointer filled |
| `in-progress` (verified) | /check verify | `Build it` + milestones ticked; `Verify it` ticked |
| `done` | **you, when you decide it is** (any skill sets it when you say so); /sync reconciles | boxes you ran ticked, skipped ones marked skipped; the tier's last stage (`Prototype` → after /develop; `Alpha` → after /check verify; `Beta`/`GA` → after /test) is the suggested point to call it done; /sync captures conventions |

- **Next step** = the first unticked box (always a command or a tracked milestone).
- **needs a decision** = run /architect first; otherwise straight to /develop (or /audit for standards & tooling). The tag drops once the spec is captured.
- **Atomic build tasks live in the spec's `## Build plan`, not here**: the scope carries only the milestone rollup.
- **Status** `planned` → `in-progress` → `done`, plus `existing` (pre workflow) and `dropped` (deselected from scope, kept for history).
- **Approach tag** beside a heading (e.g. `· Facade`) overrides the project default for that feature; no tag = inherits it.
- **Workflow tier tag** beside a heading (e.g. `· GA`, `· Prototype`) sets that one feature's rigor above or below the project default; no tag inherits the default. It decides the feature's check boxes and each skill's next suggestion.
- **Workflow** (header line) is the project default, what runs after /develop: **Prototype** = nothing (trust develop's own build time self check); **Alpha** = /check verify; **Beta** = /check verify then /test; **GA** = adds a fresh model /check review then /document. A feature built on an unratified decision (an `Assumed` spec) stays flagged, but that never blocks `done`.
- **Pointer line** (`spec <n> · code in <path>`): the spec link added by /architect, the code path by /develop.
