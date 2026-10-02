# Canonical AI Agent Integration Contract & Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish an authoritative, normative AI Agent Integration Contract, machine-readable integration policy (`docs/security/integration-policy.json`), static integration linter (`scripts/security/check-integration-contract.ts`), and fully reconciled documentation (`AGENTS.md`, `docs/AI_AGENT_INTEGRATION_CONTRACT.md`, `docs/INTEGRATION_GUIDE.md`, `docs/SECURITY_CANONICAL.md`) enforcing zero production fallbacks, strict client separation, offline RS256 JWKS verification, and fail-closed security.

**Architecture:** A centralized OAuth 2.1 / OIDC Identity Provider (SWYRA Auth) issues RS256 JWTs and enforces strict client isolation (`isDev` vs `isPublic`, loopback vs HTTPS). Consumer applications (Next.js BFF, React SPA, Express, FastAPI, Django) interact exclusively via standard HTTP endpoints and validate access tokens offline via JWKS. A machine-readable JSON policy codifies all client types, modes, callback rules, and forbidden patterns. A TypeScript linter validates integration code and documentation against this policy.

**Tech Stack:** TypeScript, Node.js (v24/26), Hono, JSON Schema, Jose, PyJWT, Bash

**Spec:** User request: "OAUTH2.1 — CANONICAL AI AGENT INTEGRATION CONTRACT" (38 sections)

## Global Constraints

- Never connect consumer applications to the SWYRA Auth MongoDB database (`MONGO_URI` is IdP-private).
- Never install duplicate auth frameworks (Better Auth, NextAuth, Auth.js, Passport, Supabase Auth, Lucia) in consumer apps.
- Never expose `client_secret` to client-side bundles or public environment variables (`NEXT_PUBLIC_*`, `VITE_*`).
- Never allow production localhost fallbacks (`AUTH_CALLBACK_URL || "http://localhost..."` is strictly prohibited; must fail closed).
- Never conflate IdP server runtime environment (`NODE_ENV`) with OAuth client development mode (`isDev`).
- Never conflate client development mode (`isDev`) with multi-tenant access mode (`isPublic`).
- Never conflate identity authentication (IdP) with local application authorization (consumer business permissions).
- Never permit dynamic redirect URI construction from `Host` headers or untrusted user input.
- Never bypass PKCE (`S256`) or `state` parameter validation in authorization code flows.
- Offline token validation must verify RS256 signature, `iss`, `aud` (matching consumer `CLIENT_ID`), and `exp`.
- All documentation files (`AGENTS.md`, `docs/AI_AGENT_INTEGRATION_CONTRACT.md`, `docs/INTEGRATION_GUIDE.md`, `docs/SECURITY_CANONICAL.md`) must be idempotent and share identical canonical terminology.

## Review Focus

1. **Deterministic JSON Policy**: `docs/security/integration-policy.json` must be strictly formatted with deterministic key ordering and cover all 6 required domains (`clientTypes`, `clientModes`, `callbackRules`, `credentialRules`, `tokenValidationRules`, `forbiddenPatterns`).
2. **Fail-Closed Code Recipes**: All code recipes in `docs/AI_AGENT_INTEGRATION_CONTRACT.md` and `docs/INTEGRATION_GUIDE.md` must remove any default fallback values (e.g. `|| "http://localhost:3000..."`) and throw clear configuration errors if required environment variables are unset.
3. **Linter Accuracy**: `scripts/security/check-integration-contract.ts` must accurately detect localhost fallback literals, exposed secrets, dynamic Host redirects, and auth bypasses without false positives on legitimate IdP server code or test fixtures.
4. **Documentation Idempotency**: Verify that `AGENTS.md`, `docs/SECURITY_CANONICAL.md`, `docs/INTEGRATION_GUIDE.md`, and `docs/AI_AGENT_INTEGRATION_CONTRACT.md` cite the exact same 10 Golden Rules, client types, and protocol endpoints.
5. **Gate Execution**: Both `npm run security:docs-check` and `npm run security:integration-check` must pass with 0 errors.

---

## Task 1: Create Machine-Readable Integration Policy

**Files:**
- Create: `docs/security/integration-policy.json`
- Test: Validate with Node.js `JSON.parse` and schema verification.

**Interfaces:**
- Produces: `docs/security/integration-policy.json` containing top-level keys:
  - `$schema`
  - `version`
  - `title`
  - `authority`
  - `clientTypes` (`public`, `confidential`)
  - `clientModes` (`production`, `development`)
  - `callbackRules` (`production`, `development`, `globalForbidden`)
  - `credentialRules` (`serverOnly`, `clientSafe`, `prohibitedPrefixes`)
  - `tokenValidationRules` (`algorithms`, `requiredClaims`, `offlineVerification`)
  - `forbiddenPatterns` (array of explicit anti-patterns with severity and reasons)
  - `securityReviewQuestions` (the 18 canonical verification questions)

- [ ] **Step 1: Write `docs/security/integration-policy.json`**
  Ensure deterministic key ordering, precise regexes for loopback vs HTTPS, forbidden prefixes (`NEXT_PUBLIC_CLIENT_SECRET`, `VITE_CLIENT_SECRET`), and canonical rule definitions.

- [ ] **Step 2: Validate JSON syntax and structure**
  Run: `node -e 'const p = JSON.parse(fs.readFileSync("docs/security/integration-policy.json")); console.log("Keys:", Object.keys(p));'`
  Expected: All 6 required sections + metadata present and valid.

---

## Task 2: Create Integration Contract Linter Script

**Files:**
- Create: `scripts/security/check-integration-contract.ts`
- Modify: `backend/package.json` (add `"security:integration-check"` script)
- Create: `package.json` (root package.json delegating to backend or invoking tsx)

**Interfaces:**
- Consumes: `docs/security/integration-policy.json`, repository files (`docs/`, `test/`, etc.)
- Produces: CLI tool `scripts/security/check-integration-contract.ts` detecting:
  1. Localhost fallback literals (`|| "http://localhost..."`, `|| 'http://localhost...'`, `|| "http://127.0.0.1..."`)
  2. Public `CLIENT_SECRET` patterns (`NEXT_PUBLIC_*CLIENT_SECRET*`, `VITE_*CLIENT_SECRET*`)
  3. Node environment auth bypasses (`NODE_ENV !== "production"` returning early or disabling auth)
  4. Explicit `DISABLE_AUTH` flags
  5. Insecure redirect construction (`req.headers.host`, `headers['x-forwarded-host']` used directly in redirect_uri)
  6. IdP MongoDB connections in consumer apps (`MONGO_URI` usage outside IdP backend)
  7. Duplicate auth engines (`better-auth`, `next-auth`, `@auth/core`, `passport`, `lucia` in consumer deps)
  8. Obsolete `/auth` redirects
  9. Algorithm `none` or `HS256` token validation for RS256 IdP tokens
  10. Verification of documentation consistency against `integration-policy.json`

- [ ] **Step 1: Implement `scripts/security/check-integration-contract.ts`**
  Write complete scanner with target path flexibility (`--target <path>` or default workspace audit).

- [ ] **Step 2: Configure `package.json` scripts**
  Add script to `backend/package.json` and root `package.json`.

- [ ] **Step 3: Run the linter to verify current baseline**
  Run: `npm run security:integration-check` (or `./backend/node_modules/.bin/tsx scripts/security/check-integration-contract.ts`).
  Examine any detected violations in docs or consumer sample apps.

---

## Task 3: Rewrite and Harden `docs/AI_AGENT_INTEGRATION_CONTRACT.md`

**Files:**
- Modify: `docs/AI_AGENT_INTEGRATION_CONTRACT.md`

**Interfaces:**
- Consumes: The 38 sections of the prompt specification and `docs/security/integration-policy.json`.
- Produces: The authoritative, comprehensive 38-section Normative Contract containing:
  1. Canonical Architecture & Identity Boundaries
  2. The 10 Golden Rules for AI Agents
  3. Client Type Decision Tree (Public vs Confidential, Dev vs Prod, `isPublic` tenant access mode independence)
  4. Production vs Development Separation (`NODE_ENV` vs `isDev`)
  5. Development Client Rule (Strict loopback, no lookalike domains, no intranet/metadata IPs)
  6. Production Client Rule (Strict HTTPS, no loopback)
  7. Local vs Production Consumer Configuration
  8. Zero Production Fallbacks (Mandatory fail-closed configuration validation)
  9. Canonical OAuth 2.1 / OIDC Flow (Mermaid sequence + step-by-step RFC flow)
  10. State + PKCE Rules (`S256`, cryptographic randomness, single-use transaction state)
  11. Confidential Client Rule (Server-only secret, server-side token exchange)
  12. Public Client Rule (No secret, PKCE only)
  13. JWT Validation Rule (Offline RS256, JWKS caching, strict `iss`/`aud`/`exp` checking, reject `none`/`HS256`)
  14. Session Rule (IdP Token vs Consumer Application Session)
  15. Logout Rule (Local app logout vs IdP RP-initiated logout)
  16. Application Authorization (AuthN != AuthZ, app admin != platform admin)
  17. App Admin Rule (Tenant staff credentials, scoped JWT isolation)
  18. Database Ownership Rule (Consumer never connects to IdP MongoDB)
  19. Redirect URI Rule (Static configuration, no `Host` header, no wildcards)
  20. Return-To Destination Rule (Safe relative paths only, reject `//` or external domains)
  21. CORS Rule (CORS != redirect URI, never `*`)
  22. CSRF Rule (Retain CSRF on state-changing endpoints)
  23. Auth Header Rule (`Bearer <token>`, client auth)
  24. Environment Variable Rules (Server-only vs public client variables)
  25. Error Handling (Fail closed, never proceed as authenticated on error)
  26. Performance Rule (JWKS caching, avoid redundant introspection)
  27. Framework-Specific Rules & Hardened Production Recipes (Next.js 14+ BFF, Pure React SPA with PKCE, FastAPI, Express, App Admin)
  28. Integration Implementation Checklist (Pre-flight & Post-implementation)
  29. Prohibited Integration Patterns (Complete catalog)
  30. AI Agent Change Boundary (Smallest secure change, inspect existing auth)
  31. The 18 Security Review Questions for Agents
  32. Canonical File Structure for Consumer Apps
  33. Documentation Consistency Rule
  34. Machine-Readable Policy Reference
  35. Integration Linter Reference

- [ ] **Step 1: Draft the hardened `docs/AI_AGENT_INTEGRATION_CONTRACT.md`**
  Ensure all 38 sections are fully detailed with production-ready, fail-closed TypeScript and Python recipes.

- [ ] **Step 2: Review for any localhost fallback literals**
  Verify that all code examples throw on missing env vars instead of falling back to localhost.

---

## Task 4: Harmonize `AGENTS.md`, `docs/INTEGRATION_GUIDE.md`, and `docs/SECURITY_CANONICAL.md`

**Files:**
- Modify: `AGENTS.md`
- Modify: `docs/INTEGRATION_GUIDE.md`
- Modify: `docs/SECURITY_CANONICAL.md`
- Modify: `backend/scripts/check-security-doc-consistency.ts`

**Interfaces:**
- Produces: 100% idempotent documentation and automated consistency checks.

- [ ] **Step 1: Update `AGENTS.md`**
  Update to feature the 10 Golden Rules, fast endpoint directory, decision tree, the 18 security review questions, and links to the canonical contract and policy.

- [ ] **Step 2: Update `docs/INTEGRATION_GUIDE.md`**
  Ensure recipes and environment variable tables explicitly distinguish production HTTPS from development loopback, remove any unqualified localhost defaults, and cite the normative contract.

- [ ] **Step 3: Update `docs/SECURITY_CANONICAL.md`**
  Synchronize Section 7 with the 10 Golden Rules and reference `docs/security/integration-policy.json` and `npm run security:integration-check`.

- [ ] **Step 4: Update `backend/scripts/check-security-doc-consistency.ts`**
  Add `docs/security/integration-policy.json` to the required canonical files check and verify that the 10 Golden Rules are enforced across docs.

---

## Task 5: Audit Repository for Sensitive Terms & Final Verification

**Files:**
- Audit: All repository matches for `localhost`, `CLIENT_SECRET`, `NEXT_PUBLIC`, `VITE_`, `DISABLE_AUTH`, `bypass`, `debug`, `state`, `code_verifier`, `code_challenge`, `redirect_uri`, `audience`, `issuer`, `MongoDB`.

- [ ] **Step 1: Run comprehensive grep audit**
  Search all security-sensitive keywords across docs, scripts, and tests. Verify each match is legitimate and compliant with the contract.

- [ ] **Step 2: Run `npm run security:docs-check`**
  Verify that automated documentation consistency check passes with 0 errors.

- [ ] **Step 3: Run `npm run security:integration-check`**
  Verify that the integration contract linter passes with 0 errors.

- [ ] **Step 4: Run `npm run test:client-mode-transition`**
  Verify that the 22 client mode transition security tests pass cleanly.

- [ ] **Step 5: Prepare final structured summary**
  Provide the complete report matching Section 38 requirements.

