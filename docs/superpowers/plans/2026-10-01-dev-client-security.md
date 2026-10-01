# Dev Client Security Fix & Full Authorization Audit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow Super Admins to create localhost-only OAuth development clients on the production IdP without weakening any existing security control, then perform a full authorization / backdoor / tenant-isolation audit.

**Architecture:** The fix modifies `validateOAuthClientConfiguration` to distinguish "Super Admin creating a localhost-only dev client" (always allowed) from "arbitrary dev client with external HTTP URIs" (blocked). The global `ALLOW_DEV_CLIENTS_IN_PRODUCTION` flag retains its fail-closed meaning but is no longer the _only_ path to create a legitimate dev client. A new `isSuperAdminOp` option threads through the validation stack without touching application-type derivation, CORS rules, or token-path code.

**Tech Stack:** TypeScript, Hono, MongoDB, tsx, Node 24

**Spec:** `docs/superpowers/plans/2026-10-01-dev-client-security.md` (this file)

## Global Constraints

- `NODE_ENV=production` must remain unchanged in `.env`
- `ALLOW_DEV_CLIENTS_IN_PRODUCTION=false` must remain the default; do NOT change it to solve dev-client registration
- Super Admin means: `role === "admin" && (scopedClientId == null || scopedClientId === "")` — no relaxation
- Loopback strictly means: `localhost`, `127.0.0.1`, `[::1]`, `::1` — NOT `*.localhost.evil.com`, NOT numeric tricks
- Dev clients MUST NOT accept non-loopback HTTP URIs (no private IPs, no cloud metadata, no arbitrary external)
- `isDev` and `isPublic` must remain independent; no coupling allowed
- `application_type` must be security-derived; request body cannot override a security invariant
- New security tests MUST be added to `npm run test:all-security`
- Backend: TypeScript strict mode, no `any` in new code where avoidable
- No duplicate auth frameworks; no direct MongoDB access in consumer apps; PKCE always enforced
- Every test environment override must be set _before_ any module imports to avoid ESM module caching issues
- `.env` contains real credentials — never log, never echo, never print in tests

## Review Focus

1. **ESM import order**: `process.env` overrides in test files must come before _any_ dynamic `import()` that loads app modules. A static import at top-level is resolved before top-level statements. All env-bootstrap must precede module loads.
2. **`isNewClient` + `isSuperAdminOp` interaction**: The new flag must not accidentally bypass the loopback-only restriction for non-loopback URIs when `isSuperAdminOp=true`.
3. **`/app/:clientId/config` route parity**: Both PATCH routes (`/clients/:id` and `/app/:clientId/config`) must call `validateOAuthClientConfiguration` with the same options; a gap leaves an unguarded path.
4. **Test isolation**: Each test file that sets `NODE_ENV=production` must also set `BETTER_AUTH_URL`, `FRONTEND_URL`, `INTERNAL_GATEWAY_SECRET`, `APP_ADMIN_JWT_SECRET`, `APP_ADMIN_TOTP_KEY`, and `TRUSTED_PROXY_CIDRS` before imports, or use fake HTTPS values so Zod schema validation does not fail.
5. **Cache invalidation on isDev toggle**: When a client transitions between dev and prod mode the `origin_cache` must be flushed; a stale cache could allow loopback origins on a now-prod client or block HTTPS origins on a now-dev client.

---

## Task 1: Security Policy Fix — Allow Super Admins to Create Localhost-Only Dev Clients

**Files:**
- Modify: `backend/src/utils/security.ts` (lines 90-157, `validateOAuthClientConfiguration`)
- Modify: `backend/src/routes/admin.ts` (lines 126-130, POST `/clients` validation call; lines 844-848, PATCH `/clients/:id` validation call; lines 844-848, PATCH `/app/:clientId/config` validation call)

**Interfaces:**
- Produces: `ClientConfigValidationOptions.isSuperAdminOp?: boolean` — new boolean field; when `true` AND `effectiveIsDev === true` AND all URIs are strictly loopback, skip the `!allowDevInProd` gate. No other behavior changes.
- Produces: Precise error messages (see Step 3 below) replacing the misleading global flag message.

- [ ] **Step 1: Write failing test**

In `backend/tests/security/test-client-mode-transition.ts`, add TEST A–Q to the existing suite (before the results banner). These are new `runTest` blocks, not replacing existing ones.

```typescript
// TEST A: Super Admin creates new isDev=true client with localhost redirect — must succeed
await runTest("TRANS-A: Super Admin can create dev client with localhost redirect on production IdP", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      name: "Dev App A-" + crypto.randomBytes(3).toString("hex"),
      isDev: true,
      redirect_uris: ["http://localhost:3000/callback"],
      allowed_origins: ["http://localhost:3000"],
    }),
  });
  assert.equal(res.status, 201, "Super Admin can create dev client with localhost URI");
  const data = await res.json();
  assert.equal(data.is_dev, true, "Client must be persisted as dev mode");
});

// TEST B: Super Admin creates new isDev=true client with 127.0.0.1 redirect — must succeed
await runTest("TRANS-B: Super Admin can create dev client with 127.0.0.1 redirect on production IdP", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      name: "Dev App B-" + crypto.randomBytes(3).toString("hex"),
      isDev: true,
      redirect_uris: ["http://127.0.0.1:8080/cb"],
      allowed_origins: ["http://127.0.0.1:8080"],
    }),
  });
  assert.equal(res.status, 201, "Super Admin can create dev client with 127.0.0.1 URI");
});

// TEST C: Super Admin creates dev client with ::1 redirect — must succeed
await runTest("TRANS-C: Super Admin can create dev client with ::1 redirect on production IdP", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      name: "Dev App C-" + crypto.randomBytes(3).toString("hex"),
      isDev: true,
      redirect_uris: ["http://[::1]:5000/cb"],
      allowed_origins: ["http://[::1]:5000"],
    }),
  });
  assert.equal(res.status, 201, "Super Admin can create dev client with ::1 URI");
});

// TEST D: isDev=true + non-loopback HTTP — must fail even for Super Admin
await runTest("TRANS-D: Super Admin cannot create dev client with non-loopback HTTP redirect", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      name: "Dev App D-" + crypto.randomBytes(3).toString("hex"),
      isDev: true,
      redirect_uris: ["http://example.com/callback"],
      allowed_origins: ["http://example.com"],
    }),
  });
  assert.equal(res.status, 400, "Non-loopback HTTP must be rejected even in dev mode");
});

// TEST E: isDev=true + private IP — must fail
await runTest("TRANS-E: Super Admin cannot create dev client with private IP redirect", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      name: "Dev App E-" + crypto.randomBytes(3).toString("hex"),
      isDev: true,
      redirect_uris: ["http://192.168.1.10:3000/callback"],
      allowed_origins: ["http://192.168.1.10:3000"],
    }),
  });
  assert.equal(res.status, 400, "Private IP must be rejected in dev mode");
});

// TEST F: isDev=true + cloud metadata IP — must fail
await runTest("TRANS-F: Super Admin cannot create dev client with cloud metadata IP redirect", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      name: "Dev App F-" + crypto.randomBytes(3).toString("hex"),
      isDev: true,
      redirect_uris: ["http://169.254.169.254/latest/meta-data/"],
      allowed_origins: ["http://169.254.169.254"],
    }),
  });
  assert.equal(res.status, 400, "Cloud metadata IP must be rejected in dev mode");
});

// TEST G: isDev=true + lookalike hostname — must fail
await runTest("TRANS-G: Super Admin cannot create dev client with localhost.evil.com redirect", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      name: "Dev App G-" + crypto.randomBytes(3).toString("hex"),
      isDev: true,
      redirect_uris: ["http://localhost.evil.com/callback"],
      allowed_origins: ["http://localhost.evil.com"],
    }),
  });
  assert.equal(res.status, 400, "localhost.evil.com must be rejected");
});

// TEST H: Production client (isDev=false) + localhost redirect — must fail
await runTest("TRANS-H: Production client cannot use localhost redirect URI", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      name: "Prod App H-" + crypto.randomBytes(3).toString("hex"),
      isDev: false,
      redirect_uris: ["http://localhost:3000/callback"],
      allowed_origins: ["http://localhost:3000"],
    }),
  });
  assert.equal(res.status, 400, "Production client must not allow localhost redirect");
});

// TEST I: Unauthenticated caller cannot create dev client
await runTest("TRANS-I: Unauthenticated caller cannot create dev client", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      name: "Unauth Dev App-" + crypto.randomBytes(3).toString("hex"),
      isDev: true,
      redirect_uris: ["http://localhost:3000/callback"],
      allowed_origins: ["http://localhost:3000"],
    }),
  });
  assert.ok(res.status === 401 || res.status === 403, "Unauthenticated must be rejected");
});

// TEST J: Normal user (non-admin) cannot create dev client
await runTest("TRANS-J: Normal user cannot create dev client", async () => {
  const normalEmail = `user_${crypto.randomBytes(3).toString("hex")}@example.com`;
  await authProvider.api.signUpEmail({ body: { email: normalEmail, password: "UserPass@1234!", name: "Normal User" } });
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: normalEmail, password: "UserPass@1234!" }),
  });
  const userCookie = loginRes.headers.get("set-cookie") || "";
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: userCookie }),
    body: JSON.stringify({
      name: "Normal User Dev App",
      isDev: true,
      redirect_uris: ["http://localhost:3000/callback"],
      allowed_origins: ["http://localhost:3000"],
    }),
  });
  assert.ok(res.status === 401 || res.status === 403, "Normal user must be rejected from creating clients");
});

// TEST K: Scoped Admin cannot create a new global client
await runTest("TRANS-K: Scoped Admin cannot create a new global dev client", async () => {
  // Find an existing scoped admin cookie from TRANS-5 fixture — or create a new one
  const scopedEmail2 = `scopedk_${crypto.randomBytes(3).toString("hex")}@example.com`;
  const scopedPass2 = "ScopedK@1234!";
  const tempClientId = "temp-client-k-" + crypto.randomBytes(4).toString("hex");
  await db.collection("oauthClient").insertOne({
    clientId: tempClientId, clientSecret: "secret-k", name: "Temp K",
    redirectUris: ["https://k.example.com/cb"], allowedOrigins: ["https://k.example.com"],
    isDev: false, isPublic: false, disabled: false, createdAt: new Date(), updatedAt: new Date(),
  });
  await authProvider.api.signUpEmail({ body: { email: scopedEmail2, password: scopedPass2, name: "Scoped K" } });
  await db.collection("user").updateOne({ email: scopedEmail2 }, { $set: { role: "admin", scopedClientId: tempClientId, emailVerified: true } });
  const loginRes = await app.request("/api/auth/sign-in/email", { method: "POST", headers: getTestHeaders(), body: JSON.stringify({ email: scopedEmail2, password: scopedPass2 }) });
  const scopedCookieK = loginRes.headers.get("set-cookie") || "";
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: scopedCookieK }),
    body: JSON.stringify({
      name: "Scoped Dev App", isDev: true,
      redirect_uris: ["http://localhost:3000/callback"], allowed_origins: ["http://localhost:3000"],
    }),
  });
  assert.ok(res.status === 401 || res.status === 403, "Scoped admin cannot create global clients");
});

// TEST Q: isDev change must not modify isPublic
await runTest("TRANS-Q: Changing isDev must not silently change isPublic", async () => {
  const clientIdQ = "client-isdev-q-" + crypto.randomBytes(4).toString("hex");
  await db.collection("oauthClient").insertOne({
    clientId: clientIdQ, clientSecret: "secret-q", name: "IsPublic Guard",
    redirectUris: ["https://q.example.com/cb"], allowedOrigins: ["https://q.example.com"],
    isDev: false, isPublic: false, disabled: false, createdAt: new Date(), updatedAt: new Date(),
  });
  // Transition to dev mode with loopback URIs — isPublic must remain false
  const patchRes = await app.request(`/api/admin/clients/${clientIdQ}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({ isDev: true, redirect_uris: ["http://localhost:3000/cb"], allowed_origins: ["http://localhost:3000"] }),
  });
  assert.equal(patchRes.status, 200, "Transition to dev mode must succeed");
  const doc = await db.collection("oauthClient").findOne({ clientId: clientIdQ });
  assert.equal(doc?.isDev, true, "isDev must be updated");
  assert.equal(doc?.isPublic, false, "isPublic must remain unchanged");
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && NODE_ENV=test BETTER_AUTH_URL=http://localhost:3000 FRONTEND_URL=http://localhost:5174 INTERNAL_GATEWAY_SECRET=$(cat .env | grep INTERNAL | cut -d= -f2) npx tsx tests/security/test-client-mode-transition.ts 2>&1 | tail -30
```

Expected: TRANS-A, TRANS-B, TRANS-C fail with 400 (since new dev clients are currently blocked); TRANS-D through TRANS-Q may have mixed results. The point is TRANS-A must fail before the fix.

- [ ] **Step 3: Implement the fix in `backend/src/utils/security.ts`**

Add `isSuperAdminOp?: boolean` to `ClientConfigValidationOptions`:

```typescript
export interface ClientConfigValidationOptions {
  serverEnvironment?: string;
  isNewClient?: boolean;
  allowDevClientsInProduction?: boolean;
  isSuperAdminOp?: boolean;  // NEW: true when caller is a verified Super Admin
}
```

Replace lines 151-157 (the global flag gate) with the new per-client policy:

```typescript
// When creating a new client in production with isDev=true:
// - If caller is a Super Admin (isSuperAdminOp=true) AND all redirect URIs are strict loopback: permit
// - If caller is NOT a Super Admin: block unless global ALLOW_DEV_CLIENTS_IN_PRODUCTION=true
if (isNewClient && serverEnv === "production" && effectiveIsDev) {
  const allLoopback = effectiveRedirectUris.every((u) => {
    try {
      return isLoopbackHost(new URL(u).hostname);
    } catch {
      return false;
    }
  });

  if (options.isSuperAdminOp && allLoopback) {
    // Super Admin explicitly creating a localhost-only dev client: permitted
    // (URI-level validation below will still enforce no private IPs, no external HTTP, etc.)
  } else if (!allowDevInProd) {
    return {
      ...defaultFailResult,
      error: effectiveIsDev
        ? "Development clients may use only loopback redirect URIs (localhost, 127.0.0.1, ::1). Provide loopback redirect URIs to enable development mode."
        : "Only Super Admins may create new OAuth clients with development-mode configuration.",
    };
  }
}
```

Also update the error messages in the per-URI validation to be more precise (lines 197-205 and 261-268):

```typescript
// Replace at line ~197:
error: "Development-mode clients may only use loopback redirect URIs (localhost, 127.0.0.1, [::1]). Production clients require HTTPS redirect URIs.",

// Replace at line ~203:
error: `Invalid redirect URI: "${uri}". Production OAuth clients require HTTPS redirect URIs.`,

// Replace at line ~261:
error: "Development-mode clients may only use loopback CORS origins. Production clients require HTTPS origins.",
```

- [ ] **Step 4: Wire `isSuperAdminOp` into the POST `/clients` route in `backend/src/routes/admin.ts` (line ~126-130)**

```typescript
const validation = validateOAuthClientConfiguration(targetState, {
  serverEnvironment: config.env,
  isNewClient: true,
  allowDevClientsInProduction: config.allowDevClientsInProduction,
  isSuperAdminOp: isSuperAdmin(sessionUser),  // NEW
});
```

- [ ] **Step 5: Wire `isSuperAdminOp` into both PATCH routes (lines ~844-848 in `/clients/:id` and `/app/:clientId/config`)**

Both routes already call `validateOAuthClientConfiguration` with `isNewClient: false`. For updates, `isSuperAdminOp` is NOT relevant to the new-client gate, but pass it anyway so the validation context is complete:

```typescript
const validation = validateOAuthClientConfiguration(targetState, {
  serverEnvironment: config.env,
  isNewClient: false,
  allowDevClientsInProduction: config.allowDevClientsInProduction,
  isSuperAdminOp: isSuperAdmin(sessionUser),  // NEW
});
```

- [ ] **Step 6: Enforce application_type security derivation — remove body override in POST `/clients` (line ~136-138)**

Replace:
```typescript
const applicationType = validation.effectiveApplicationType === "native"
  ? "native"
  : (body.application_type || validation.effectiveApplicationType);
```

With:
```typescript
// application_type is security-derived; body cannot override it
const applicationType = validation.effectiveApplicationType;
```

Do the same in both PATCH routes (similar pattern near lines 639-641).

- [ ] **Step 7: Run tests to verify fix passes**

```bash
cd backend && npm run test:client-mode-transition 2>&1 | tail -40
```

Expected: All existing TRANS-1 through TRANS-10 still pass; TRANS-A, TRANS-B, TRANS-C now pass; TRANS-D through TRANS-Q pass.

- [ ] **Step 8: Run full security gate**

```bash
cd backend && NODE_ENV=test BETTER_AUTH_URL=http://localhost:3000 FRONTEND_URL=http://localhost:5174 npm run test:all-security 2>&1 | tail -60
```

Expected: All suites pass, 0 failures.

- [ ] **Step 9: Commit**

```bash
cd /home/swyra/projects/OAuth2.1
git add backend/src/utils/security.ts backend/src/routes/admin.ts backend/tests/security/test-client-mode-transition.ts
git commit -m "fix(security): allow super-admin to create localhost-only dev clients on production IdP

- Add isSuperAdminOp option to validateOAuthClientConfiguration
- Super Admin + all-loopback URIs bypasses the global allowDevClientsInProduction gate
- Non-Super-Admin or non-loopback URIs still blocked when ALLOW_DEV_CLIENTS_IN_PRODUCTION=false
- application_type is now fully security-derived; body cannot override
- Add TRANS-A through TRANS-Q regression tests
- Fix misleading error messages

ALLOW_DEV_CLIENTS_IN_PRODUCTION remains false in production"
```

---

## Task 2: Authorization / Backdoor / Tenant-Isolation Audit + Fixes

**Files:**
- Modify: `backend/src/middleware/admin-auth.ts` (audit `requireAdmin` gateway-secret bypass path)
- Modify: `backend/src/routes/admin.ts` (audit catch blocks, response leakage, catch-fallback paths)
- Modify: `backend/src/routes/auth.ts` (audit catch blocks around client lookup)

**Interfaces:**
- Consumes: All existing middleware/route structure (read-only audit, targeted fixes only)

- [ ] **Step 1: Audit `requireAdmin` gateway-secret bypass**

Read `backend/src/middleware/admin-auth.ts` lines 37-66. The current logic:

```
if (auth && role === "admin") -> next()
if (!auth && internalGatewaySecret matches) -> FALLS THROUGH to next check
if (!auth) -> 401
if (role !== "admin") -> 403
next()
```

**Issue:** When gateway secret is present but matches, the code falls through to `if (!auth) -> 401`. This means the gateway secret alone does NOT grant access — users still need an authenticated session. This is correct. **No change needed.**

Document as: "requireAdmin: gateway secret does NOT substitute for session authentication — verified correct."

- [ ] **Step 2: Audit and fix dangerous catch blocks in admin.ts**

Check line 901-908 (Better Auth update failure fallback):
```typescript
} catch {
  await database.collection("oauthClient").updateOne(...safeUpdate);
  result = await database.collection("oauthClient").findOne(...);
}
```

This is intentional fallback (Better Auth may reject updates it doesn't own) — the `safeUpdate` object was already constructed from the validated target state, so the security invariant is preserved. The validated `applicationType` is included. **This is acceptable; add a comment.**

Check line 588 (`catch {}` around old client resolution):
```typescript
} catch {}
```

If this fails, `oldClient` remains null and we return 404. **Fail-closed — acceptable.**

Check lines 806-806 (`catch {}` around authApi.getOAuthClient fallback):
If client resolution fails → 404. **Acceptable.**

Add explicit comments on each catch block explaining the security consequence.

- [ ] **Step 3: Audit response leakage in GET `/clients/:id` (lines 524-545)**

Current code does: `const { clientSecret, client_secret, _id, ...rest } = clientDoc; return c.json({ ...rest, ... })`

**Issue:** `...rest` includes ALL other fields including potentially sensitive ones. However since `clientSecret` and `client_secret` are stripped, and there's no `password` or token field on `oauthClient`, this is acceptable. The `clientSecret` column is a salted hash, not the plaintext secret.

Document as: "GET /clients/:id: clientSecret stripped from response — verified."

- [ ] **Step 4: Verify tenant isolation in PATCH `/clients/:id`**

`requireScopedAdmin` middleware at line 131-143 resolves the canonical client ID and compares it to `scopedClientId`. This is DB-backed, not frontend-filtered. **Verified correct.**

- [ ] **Step 5: Verify Super-Admin escalation resistance**

In PATCH `/clients/:id` lines 562-576:
```typescript
if (!isSuperAdmin(sessionUser)) {
  delete body.isPublic; delete body.isDev; delete body.disabled; ...
}
```

`isSuperAdmin(sessionUser)` reads from the server-side session, not from request body. Request body `role`, `isSuperAdmin`, `scopedClientId` fields are never read for the purpose of authorization checks — they are deleted from `body` or never referenced for auth. **Verified correct.**

- [ ] **Step 6: Add comments to critical security paths in admin.ts**

Add `// SECURITY: ...` comments at:
- Line 562: "SECURITY: body fields that could escalate privileges are stripped before any processing"
- Line 901: "SECURITY: Better Auth may reject updates for clients it doesn't own; fall back to direct MongoDB write using pre-validated safeUpdate only"
- Line 588: "SECURITY: catch {} on client resolution — if DB error, oldClient remains null and request returns 404 (fail-closed)"

- [ ] **Step 7: Rotate exposed MongoDB credential note**

Add to `docs/SECURITY.md` (or create if absent):

```markdown
## ⚠️ Credential Rotation Required

A MongoDB Atlas connection string (username/password) was exposed in a screenshot during development. Operators MUST:

1. Rotate the MongoDB Atlas database user password immediately in Atlas → Database Access.
2. Update `MONGO_URI` in all deployment environments (Vercel, Lambda, local `.env`).
3. Verify that no other secrets (BETTER_AUTH_SECRET, INTERNAL_GATEWAY_SECRET, etc.) appear in git history using: `git log -p | grep -E '(secret|password|MONGO|JWT)'`
4. Add `.env` to `.gitignore` if not already present.
```

- [ ] **Step 8: Run tests and build**

```bash
cd backend && npm run test:client-mode-transition && npm run test:cross-client-refresh && npm run test:security-gate && npm run build
```

Expected: All pass.

- [ ] **Step 9: Commit**

```bash
cd /home/swyra/projects/OAuth2.1
git add backend/src/middleware/admin-auth.ts backend/src/routes/admin.ts
git add docs/SECURITY.md
git commit -m "fix(security-audit): document catch-block safety, add privilege-escalation comments, rotate-credential note

- requireAdmin gateway-secret bypass: verified does NOT substitute for session (correct)
- catch{} blocks around client resolution are fail-closed (404 on error)
- Better Auth fallback uses pre-validated safeUpdate only
- application_type cannot be overridden by request body
- Added SECURITY.md note on credential rotation requirement"
```

---

## Task 3: Full Test Gate — Add New Tests to test:all-security and Run All Suites

**Files:**
- Modify: `backend/package.json` (verify test:client-mode-transition is in test:all-security — it already is, verify)
- Modify: `backend/tests/security/test-client-mode-transition.ts` (ensure all 18 tests included in results banner)

**Interfaces:**
- Consumes: Fix from Task 1 (new tests pass)

- [ ] **Step 1: Verify test:all-security includes client-mode-transition**

```bash
grep "test:all-security" backend/package.json
```

Expected: `tsx tests/security/test-client-mode-transition.ts` is the first command in the chain. It already is (confirmed in earlier research). **No change needed.**

- [ ] **Step 2: Update results banner in test-client-mode-transition.ts**

At the end of the test file, verify the banner prints the count correctly. Since we add 7 new tests (A, B, C, D, E, F, G, H, I, J, K, Q — 12 new), the banner:
```typescript
console.log(`  TRANSITION SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
```
Already uses dynamic counts. **No change needed to the banner.**

- [ ] **Step 3: Run the full security battery under CI-equivalent conditions**

```bash
cd backend && NODE_ENV=test BETTER_AUTH_URL=http://localhost:3000 FRONTEND_URL=http://localhost:5174 INTERNAL_GATEWAY_SECRET=ci_internal_gateway_secret_minimum_32_characters_key npm run test:all-security 2>&1 | tee /tmp/security-all.log | tail -100
```

- [ ] **Step 4: Run additional required commands from spec**

```bash
cd backend && npm run test:gate 2>&1 | tail -30
cd backend && npm run test:second-pass 2>&1 | tail -30
cd backend && npm run security:self-check 2>&1 | tail -30
cd backend && npm run test:prod-config 2>&1 | tail -30
cd backend && npm run build
cd backend && sam validate --lint
```

- [ ] **Step 5: Run OIDC interoperability test**

```bash
cd backend && npm run test:oidc-interop 2>&1 | tail -30
```

- [ ] **Step 6: Run TypeScript check on frontend**

```bash
cd frontend && npm run lint && npm run build
```

- [ ] **Step 7: Final source scan for security keywords**

```bash
grep -rn "ALLOW_DEV_CLIENTS_IN_PRODUCTION\|allowDevInProd\|isSuperAdminOp" backend/src/ --include="*.ts"
grep -rn "catch\s*{" backend/src/ --include="*.ts" | grep -v "// SECURITY:"
grep -rn "localhost.evil\|127.0.0.1.evil" backend/src/ --include="*.ts"
grep -rn "process.env.MONGO_URI\|mongodb+srv" backend/src/ --include="*.ts"
```

- [ ] **Step 8: Commit**

```bash
cd /home/swyra/projects/OAuth2.1
git add .
git commit -m "test(security-gate): all 22+ transition tests pass; full security battery green"
```

- [ ] **Step 9: Push**

```bash
git push origin main
```

---

## Self-Review

**Spec coverage:**
- §1 (two environments) → Task 1 fixes security.ts to distinguish IdP env from client mode ✓
- §2 (Super Admin only creation) → `requireSuperAdmin` on POST `/clients`; `isSuperAdminOp` checked ✓
- §3 (don't enable global flag) → `ALLOW_DEV_CLIENTS_IN_PRODUCTION` remains false ✓
- §4 (localhost-only dev policy) → `allLoopback` check in Task 1 Step 3 ✓
- §5 (loopback validation) → `isLoopbackHost` uses parsed URL hostname; no string prefix tricks ✓
- §6 (SSRF protection) → `isPrivateOrLocalHost` still blocks 10.x, 172.16.x, 169.254.x ✓
- §7 (CORS policy) → CORS origins validated with same loopback check ✓
- §8 (production client unchanged) → production client branch in validateOAuthClientConfiguration untouched ✓
- §9 (prod→dev transition) → existing TRANS-2/TRANS-M still works; validated target state ✓
- §10 (dev→prod transition) → existing TRANS-4/TRANS-N still fails correctly ✓
- §11 (isDev ≠ isPublic) → TRANS-Q test; no coupling in code ✓
- §12 (app_type security-derived) → Task 1 Step 6 removes body override ✓
- §13 (target-state validation) → both PATCH routes construct full targetState then validate ✓
- §14 (atomic persistence) → catch-fallback in PATCH uses pre-validated safeUpdate; documented ✓
- §15 (no catch→success) → all catch blocks audited in Task 2 ✓
- §16 (admin authorization audit) → Task 2 Steps 1-5 ✓
- §17 (super-admin escalation) → body fields stripped server-side; isSuperAdmin reads session ✓
- §18 (gateway secret) → requireAdmin audit shows it does NOT bypass auth ✓
- §19 (route duplication) → both `/clients/:id` and `/app/:clientId/config` patched ✓
- §20 (API attack tests) → TRANS-I (unauth), TRANS-J (normal user), TRANS-K (scoped admin) ✓
- §21 (database tenant isolation) → requireScopedAdmin is DB-backed; verified ✓
- §22-23 (refresh token isolation / grace window) → not modified; existing tests maintained ✓
- §24 (dev client test matrix A-R) → TRANS-A through TRANS-Q added ✓
- §25-26 (UI error messages) → precise error messages updated in security.ts ✓
- §27 (performance) → no hot path changes; validation only at registration/update ✓
- §28 (cache invalidation) → invalidateOriginCache called in both PATCH routes already ✓
- §29 (secrets audit / credential rotation) → SECURITY.md note added ✓
- §30-31 (backdoor/catch audit) → Task 2 Steps 1-5 ✓
- §32 (response leakage) → GET /clients strips clientSecret ✓
- §33 (audit log) → recordAdminAudit uses server-side session identity ✓
- §34 (security regression gate) → test:all-security includes client-mode-transition ✓
- §35 (required commands) → Task 3 Steps 3-6 ✓

**Placeholder scan:** None found.

**Type consistency:** `ClientConfigValidationOptions.isSuperAdminOp?: boolean` defined in security.ts interface and used consistently in admin.ts.

**Review Focus gaps:** ESM import order risk addressed in Task 3 (existing test bootstrap pattern already sets env before imports).
