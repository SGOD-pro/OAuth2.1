# SWYRA OAuth 2.1 — Root-Cause Diagnosis & Master Fix Prompt

This guide contains:
1. **Root-Cause Diagnosis** of the exact bugs in your `OAuth2.1` repository causing post-deployment authentication failures, admin lockouts, dev/prod testing friction, and configuration bloat.
2. **Immediate Database Recovery Commands** to un-brick your Main Admin account right now if it is currently showing `Access denied`.
3. **Copy-Paste Master Prompt** to feed directly into your AI coding agent (Cursor, Windsurf, Claude Code, or GitHub Copilot) to fix all four issues across the repository.

---

## Part 1: Root-Cause Diagnosis (Why These Issues Happen in Your Codebase)

| Issue Reported | Exact Root Cause in Codebase | Affected Files & Lines |
| :--- | :--- | :--- |
| **1. Works right after `git push`, but fails after a few days with `Authentication error` / `Access denied`** | **A. Cold-Start Super-Admin Hijack (`selfHealAppAdmins`):** Every time AWS Lambda cold-starts, `ensureTtlIndexes()` runs `selfHealAppAdmins(db)`. That function loops over every row in `app_admins` and calls `syncAppAdminIdentity()`, which **unconditionally overwrites** `user.scopedClientId = clientId` and overwrites the password in `account` for any matching email. If you ever added your main admin email as a consumer App Admin, the next Lambda cold start silently demotes your Super Admin (`scopedClientId: null`) into a Scoped Admin (`scopedClientId: "<clientId>"`). When you visit `/admin/login`, `AdminRoute.tsx` and `AdminLogin.tsx` see `scopedClientId !== null`, immediately sign you out, and throw `Access denied`.<br><br>**B. Untracked `vercel.json` Gateway Secret Loss:** `deploy.yml` generates an untracked `vercel.json` (which injects `x-gateway-secret`) and deletes it after deploy (`prepare-vercel-config.mjs --clean`). If Vercel's native Git integration auto-deploys, or someone triggers a redeploy from the Vercel UI, `vercel.json` is missing—causing every `/api/admin/*` request to fail with `403 Forbidden (gateway authentication required)`.<br><br>**C. 15-Minute Access Token Expiry & Refresh Token Family Cascade Revocation:** Access tokens expire in 15 minutes (`auth.ts`), while consumer app cookies last 1–24 hours without automatic refresh-token rotation. Worse, if two refresh requests arrive >2 seconds apart with the same token (e.g., due to a dropped response or RSC render), `verifyAndRotateTokenFamily()` in `state.ts` treats it as theft and **revokes the entire token family**, returning `401 invalid_grant` until cookies are cleared.<br><br>**D. JWKS Key Lookup & Mongo Cold Reconnect:** `getIdpPublicKey()` (`admin-auth.ts`) and `getIdpSigningKey()` (`auth.ts`) only fetch the newest `jwks` doc without matching `kid`. If `symmetricDecrypt` fails or keys rotate, `mintJwtAccessToken()` returns `null` and silently falls back to opaque tokens, which then fail RS256 verification with `401 invalid_token`. Also, `mongo.ts` caches `db` without handling dropped connections on idle MongoDB Atlas M0 clusters. | `backend/src/db/state.ts` (L95–100)<br>`backend/src/utils/admin-sync.ts` (L43–64, L161–179)<br>`frontend/pages/admin/AdminLogin.tsx` (L58–66, L117–123)<br>`scripts/prepare-vercel-config.mjs`<br>`.github/workflows/deploy.yml` (L294–308)<br>`backend/src/routes/auth.ts` (L33–85, L755–988)<br>`backend/src/db/mongo.ts` (L10–39) |
| **2. App Isolation & Main Admin vs. Consumer App Admin Conflict** | Both Main IdP Super Admins and Consumer App Admins share the global `user` collection and the same `better-auth.session_token` cookie on the IdP domain. Because scoping is stored as a single scalar `user.scopedClientId` field on `user`:<br>• One user **cannot** be both Main Super Admin and a Consumer App Admin.<br>• One user **cannot** be an App Admin for two different consumer apps (App B overwrites App A's `scopedClientId` on every cold start).<br>• If you log into a consumer app as a scoped admin, your browser's IdP session cookie blocks you from opening `/admin/login` on the Main IdP Console. | `backend/src/utils/admin-sync.ts` (L24–133)<br>`backend/src/middleware/admin-auth.ts` (L160–203, L350–498)<br>`backend/src/routes/auth.ts` (L87–134)<br>`frontend/components/AdminRoute.tsx` (L16–38) |
| **3. Cannot Test in Dev Env Without Deploying Every Time** | **A. Broken `.env.example`:** Sets `NODE_ENV=production` alongside `http://localhost` URLs (which immediately crashes `envSchema` in `schema.ts`) and omits `INTERNAL_GATEWAY_SECRET`.<br><br>**B. Broken `start-all.sh`:** Points to `HONO_DIR="$ROOT_DIR/hono"` instead of `backend`, failing immediately.<br><br>**C. Strict Dev vs. Prod URI Exclusivity:** `validateOAuthClientConfiguration()` in `security.ts` forbids a client from having both `http://localhost:*` (for local testing) and `https://prod-domain.com` (for production) redirect URIs at the same time. To test locally against the deployed IdP, you are forced to toggle `isDev` and overwrite URIs or redeploy.<br><br>**D. Gateway Guard in Local Dev:** `verifyGatewaySecret()` in `admin-auth.ts` fails closed with `403 Forbidden` even in `NODE_ENV=development` if `INTERNAL_GATEWAY_SECRET` is not set in `backend/.env` and injected by the proxy. | `.env.example`<br>`start-all.sh` (L18)<br>`backend/src/config/schema.ts` (L39–77)<br>`backend/src/utils/security.ts` (L156–295)<br>`backend/src/middleware/admin-auth.ts` (L241–273) |
| **4. Overly Complex Application Configuration** | • Admins must manually enter both `Redirect URIs` and `Allowed CORS Origins` separately in `RegisterAppModal.tsx` / `EditAppModal.tsx`, even though CORS origins can be auto-derived from each redirect URI's origin (`new URL(uri).origin`).<br>• Client documents store duplicate `camelCase` and `snake_case` fields (`redirectUris` + `redirect_uris`, `allowedOrigins` + `allowed_origins`, `isDev` + `is_dev`, `isPublic` + `is_public`, `metadata.*`), requiring 40+ lines of manual mapping in every route.<br>• Hardcoded URLs (`oauth21.vercel.app`, Lambda Function URL) are duplicated across 6 files. | `frontend/pages/admin/RegisterAppModal.tsx`<br>`frontend/pages/admin/EditAppModal.tsx`<br>`backend/src/routes/admin.ts` (L42–80, L172–194, L538–553) |

---

## Part 2: Immediate 1-Minute Fix for Your Locked Admin Account

If your Main Admin account is currently showing **`Access denied`** or **`Invalid administrator credentials`** on your deployed app right now, run this from your `backend/` folder against your production `MONGO_URI`:

```bash
cd backend
npx tsx --env-file=.env scripts/create-admin.ts your-admin-email@example.com "YourStrongPassword@123!"
```

And if that same email was also added to `app_admins` (which causes Lambda cold starts to demote it back to a scoped admin after a few hours/days), remove the duplicate entry from `app_admins` or apply the full prompt below so `selfHealAppAdmins` never overwrites a Super Admin again.

---

## Part 3: Copy-Paste Master Prompt for Your AI Coding Agent

Copy the prompt below and paste it directly into **Cursor**, **Claude Code**, **Windsurf**, or **GitHub Copilot**:

```markdown
You are a staff security and full-stack TypeScript engineer working on the SWYRA OAuth 2.1 / OIDC Identity Provider repository (`backend/`, `frontend/`, `test/`, `scripts/`).

We need to fix 4 critical architectural and operational issues while preserving all OAuth 2.1 security invariants (PKCE S256, state validation, RS256 JWKS verification, CSRF protection, and tenant isolation):

1. **Fix "Works After Git Push, Fails After a Few Days with Auth Error / Access Denied"**:
   - Prevent `selfHealAppAdmins` / `syncAppAdminIdentity` from overwriting Super Admin accounts or clobbering multi-app admins on Lambda cold starts.
   - Ensure Vercel builds always generate `vercel.json` with `x-gateway-secret` even on native Vercel Git deploys/redeploys, and ensure `backend/deploy.sh` passes `InternalGatewaySecret`.
   - Harden MongoDB connection recovery (`backend/src/db/mongo.ts`) and JWKS key resolution by `kid` (`backend/src/routes/auth.ts` and `backend/src/middleware/admin-auth.ts`).
   - Prevent false-positive refresh token family cascade revocations on network retries and add automatic token refresh to consumer apps.
2. **Fix App Isolation & Separate Main IdP Admin Login vs. Consumer App Admin Login**:
   - Separate Global Super Admin status (`user.role === "admin" && user.scopedClientId === null`) from per-application Consumer Admin assignments (`app_admins` / `user_app_registrations`).
   - Allow a user to be a Global Super Admin or an App Admin for one or multiple consumer apps without mutating/corrupting their global `user.scopedClientId` when they are a Super Admin.
   - Resolve per-client admin claims (`role` and `scoped_client_id`) dynamically at OAuth token minting (`/oauth2/token`), `/oauth2/userinfo`, and `/oauth2/introspect` based on the target `clientId`.
   - Fix `/admin/login` session handling so an active consumer-app session does not trap a Super Admin in an `access_denied_scoped` loop without a clean account switch / re-login flow.
3. **Fix Dev vs. Prod Isolation & Enable Zero-Deploy Local Testing**:
   - Fix `.env.example`, `start-all.sh`, `backend/check_users.mjs`, and `backend/test_signup.mjs` (update stale `hono` paths to `backend`, set working local defaults in `.env.example`).
   - Allow local development (`NODE_ENV=development` on loopback) to work seamlessly with `/api/admin/*` when `INTERNAL_GATEWAY_SECRET` is unset, while keeping `NODE_ENV=production` (and explicit test secrets) strictly fail-closed.
   - Allow OAuth clients with `isDev: true` to register both loopback (`http://localhost:*`, `http://127.0.0.1:*`) AND `https://` redirect URIs/origins so developers can test local consumer apps against the deployed IdP (or staging/prod) without having to redeploy or toggle client modes every time.
4. **Simplify Application Configuration**:
   - Auto-derive `allowedOrigins` from `redirectUris` (`new URL(uri).origin`) on both backend (`POST /api/admin/clients`, `PATCH /api/admin/clients/:id`) and frontend (`RegisterAppModal.tsx`, `EditAppModal.tsx`) so admins only need to enter Redirect URIs once (while still allowing extra custom CORS origins if desired).
   - Centralize OAuth client field normalization (`camelCase` / `snake_case`) into a single helper in `backend/src/utils/security.ts`.

Execute the following exact changes step by step:

---

### STEP 1: Fix Admin Identity Sync & Decouple Main Admin from Consumer App Admin (`backend/src/utils/admin-sync.ts`, `backend/scripts/create-admin.ts`, `backend/scripts/migrate-app-admins.ts`)

1. In `backend/src/utils/admin-sync.ts`:
   - In `syncAppAdminIdentity(database, params)`:
     - Check if the existing `user` document in `database.collection("user")` is ALREADY a Global Super Admin (`user.role === "admin" && user.scopedClientId === null`).
     - **CRITICAL INVARIANT:** If `user` is already a Global Super Admin (`user.role === "admin" && user.scopedClientId === null`), NEVER overwrite `user.scopedClientId` with `clientId`, NEVER overwrite their global `account` password with the app-admin password, and NEVER set `banned: true` on the Super Admin user! Simply ensure they are registered in `user_app_registrations` for `clientId` with `appRole: "admin"`.
     - For non-Super-Admin users:
       - If the user has no `scopedClientId` (or `scopedClientId === clientId`), set `role: "admin"` and `scopedClientId: clientId`.
       - If the user is already scoped to another client (`user.scopedClientId && user.scopedClientId !== clientId`), keep their primary `scopedClientId` intact and store per-client admin membership in `user_app_registrations` (`{ userId: userIdStr, clientId, appRole: "admin", registeredAt }`) and `app_admins`.
     - Always upsert `{ userId: userIdStr, clientId, appRole: "admin" }` in `user_app_registrations`.
   - In `removeAppAdminIdentity(database, params)`:
     - Never demote a Global Super Admin (`user.scopedClientId === null`).
     - If removing an app admin who still has active `app_admins` records for another `clientId`, update their `user.scopedClientId` to that remaining `clientId` instead of resetting `role: "user"`. Only reset `role: "user"` and `scopedClientId: null` if they are not a Super Admin and have zero remaining `app_admins` records.
2. In `backend/scripts/create-admin.ts`:
   - When promoting/creating a Global Super Admin (`scopedClientId: null`), also check `db.collection("app_admins").find({ email: email.toLowerCase().trim() })` and print a clear notice (or optionally pass `--clean-scoped` to remove conflicting `app_admins` entries) so `selfHealAppAdmins` never conflicts with the Super Admin.
3. In `backend/scripts/migrate-app-admins.ts`:
   - Apply the exact same Super Admin guard (`if (user.role === "admin" && user.scopedClientId === null)`) so running the migration script never demotes a Global Super Admin into a scoped client admin.

---

### STEP 2: Resolve Per-App Admin Role Dynamically in OAuth Tokens & UserInfo (`backend/src/routes/auth.ts`, `backend/src/middleware/admin-auth.ts`)

1. In `backend/src/routes/auth.ts`:
   - Create a helper function `resolveUserRoleForClient(database: Db, userDoc: any, clientId: string): Promise<{ role: string; scopedClientId: string | null }>`:
     - If `!userDoc`, return `{ role: "user", scopedClientId: null }`.
     - If `userDoc.role === "admin" && userDoc.scopedClientId === null` (Global Super Admin), return `{ role: "admin", scopedClientId: null }`.
     - If `userDoc.role === "admin" && userDoc.scopedClientId === clientId`, return `{ role: "admin", scopedClientId: clientId }`.
     - Check `database.collection("app_admins").findOne({ clientId, email: userDoc.email?.toLowerCase().trim(), isActive: { $ne: false } })`:
       - If found, return `{ role: "admin", scopedClientId: clientId }`.
     - Otherwise, even if `userDoc.role === "admin"` for some *other* client (`userDoc.scopedClientId !== clientId`), for THIS `clientId` return `{ role: "user", scopedClientId: userDoc.scopedClientId || null }`! (This prevents an App Admin of App A from getting `role: "admin"` inside App B!)
   - Use `resolveUserRoleForClient(database, userDoc, params.clientId)` inside:
     - `mintJwtAccessToken()`
     - `GET /oauth2/userinfo` (when resolving claims for a Bearer token with `client_id` / `aud`)
     - `POST /oauth2/introspect`
     - `hasAppAccessBypass(user, canonicalClientId)` (also allow bypass if the user is an active `app_admins` member for `canonicalClientId`).

---

### STEP 3: Harden MongoDB Reconnection, JWKS `kid` Resolution, and Refresh Token Resilience (`backend/src/db/mongo.ts`, `backend/src/routes/auth.ts`, `backend/src/middleware/admin-auth.ts`, `backend/src/db/state.ts`)

1. In `backend/src/db/mongo.ts`:
   - Configure `MongoClient` with production-resilient timeouts: `maxPoolSize: 10`, `minPoolSize: 1`, `serverSelectionTimeoutMS: 10000`, `socketTimeoutMS: 30000`, `maxIdleTimeMS: 60000`.
   - Fix the initial background connection `.catch()` handler: do NOT return `database` on failure; set `db = null; connectPromise = null;` so subsequent calls to `getDb()` properly retry `client.connect()`.
   - Listen to `client.on("close", () => { db = null; connectPromise = null; })` and `client.on("topologyClosed", () => { db = null; connectPromise = null; })` so if MongoDB Atlas pauses or drops idle Lambda connections after a few days, the next request automatically reconnects instead of failing forever.
2. In `backend/src/middleware/admin-auth.ts` (`getIdpPublicKey`) and `backend/src/routes/auth.ts` (`getIdpSigningKey`):
   - Support an optional `kid?: string` parameter in `getIdpPublicKey(kid?: string)`.
   - Decode the JWT header (`decodeProtectedHeader(token)`) before verification to extract `header.kid`, and query `database.collection("jwks").findOne(kid ? { $or: [{ kid }, { id: kid }] } : {}, { sort: { createdAt: -1 } })` (falling back to the latest key if `kid` is not matched).
   - In `getIdpSigningKey()`, if `symmetricDecrypt` fails on the newest `jwks` record (e.g., due to secret rotation), log a warning and delete the unreadable `jwks` record or generate a fresh RS256 keypair so token signing self-heals instead of returning `null`.
3. In `backend/src/db/state.ts` (`verifyAndRotateTokenFamily`):
   - Keep the 2000ms grace window for deterministic tests (`nowMs` parameter when explicitly passed in tests), and ensure that if a token is within the grace window, the caller receives a clean `invalid_grant` without revoking the active family.

---

### STEP 4: Fix Vercel Gateway Config Persistence & Deployment Scripts (`scripts/prepare-vercel-config.mjs`, `frontend/package.json`, `backend/deploy.sh`)

1. In `scripts/prepare-vercel-config.mjs`:
   - Allow `LAMBDA_BACKEND_URL` env var to override the hardcoded Lambda URL (defaulting to `https://yu6fcg6yx4xmq5u4we5n6j3ywm0inmis.lambda-url.ap-south-1.on.aws`).
   - Add a `--if-present` flag: when run with `--if-present` (e.g., during `npm run build` in `frontend/`), if `INTERNAL_GATEWAY_SECRET` is present in `process.env` or `backend/.env`, automatically generate `vercel.json` and `frontend/vercel.json`; if not present (e.g., local UI build without secrets), skip cleanly with a warning instead of crashing.
2. In `frontend/package.json`:
   - Update `"build"` script to `"node ../scripts/prepare-vercel-config.mjs --if-present && tsc -b && vite build"` so that even if Vercel builds directly from a Git push or Vercel Dashboard redeploy (outside GitHub Actions), `vercel.json` with `x-gateway-secret` is ALWAYS generated!
3. In `backend/deploy.sh`:
   - Load `backend/.env` if present, verify `INTERNAL_GATEWAY_SECRET` is set ($\ge 32$ chars), and pass `--parameter-overrides ... InternalGatewaySecret="$INTERNAL_GATEWAY_SECRET"` to `sam deploy` so manual CLI deployments never wipe out the Lambda gateway secret.

---

### STEP 5: Fix Dev vs. Prod Isolation & Local Testing Workflow (`backend/src/utils/security.ts`, `backend/src/middleware/admin-auth.ts`, `.env.example`, `start-all.sh`, `package.json`)

1. In `backend/src/utils/security.ts` (`validateOAuthClientConfiguration` and `validateRedirectUri`):
   - Currently, in `serverEnv === "production"`, if `effectiveIsDev === true`, the validator rejects `https://` external redirect URIs/origins (`if (!isLoopback) return error`).
   - **Change this rule:** For a Development-Enabled client (`effectiveIsDev === true`), allow **both** strict loopback URIs (`http://localhost:*`, `http://127.0.0.1:*`, `http://[::1]:*`) **AND** valid public `https://` URIs/origins (while still strictly forbidding wildcards `*`, fragments `#`, userinfo, non-loopback `http://`, and private RFC1918 intranet IPs like `10.x`, `192.168.x`, `172.16-31.x`).
   - Update `isNewClient && serverEnv === "production" && effectiveIsDev`: if `options.isSuperAdminOp` is `true`, allow Super Admins to create/update `isDev: true` clients with loopback and/or valid `https://` URIs without requiring `ALLOW_DEV_CLIENTS_IN_PRODUCTION=true`.
   - Keep `effectiveIsDev === false` (Production Client) 100% strict: HTTPS only, zero loopback, zero private IPs.
2. In `backend/src/middleware/admin-auth.ts` (`verifyGatewaySecret`):
   - In `NODE_ENV === "production"`, ALWAYS require `config.internalGatewaySecret` ($\ge 32$ chars) and a matching `x-gateway-secret` header (fail-closed).
   - In `NODE_ENV !== "production"`:
     - If `config.internalGatewaySecret` IS configured (such as in automated security test suites or when set in `.env`), enforce the exact `x-gateway-secret` header check as normal (so all security tests in `test:all-security` continue to pass!).
     - If `config.internalGatewaySecret` is NOT configured (empty/undefined) AND `config.env === "development"`, check if the request `Host` is a loopback host (`localhost` / `127.0.0.1`) and allow it with a dev console warning, so local development works out of the box.
3. In `.env.example`:
   - Set `NODE_ENV=development` by default for local cloning (with a comment showing `NODE_ENV=production` for prod).
   - Add `INTERNAL_GATEWAY_SECRET=dev_internal_gateway_secret_minimum_32_characters_long` so Vite's proxy (`frontend/vite.config.ts`) and the Hono backend automatically share the exact same secret in local dev!
   - Add `ALLOW_DEV_CLIENTS_IN_PRODUCTION=false`.
4. In `start-all.sh`, `backend/check_users.mjs`, and `backend/test_signup.mjs`:
   - Fix `HONO_DIR="$ROOT_DIR/hono"` -> `BACKEND_DIR="$ROOT_DIR/backend"` in `start-all.sh`.
   - Fix `path: "hono/.env"` -> `path: ".env"` in `backend/check_users.mjs` and `backend/test_signup.mjs`.
   - In root `package.json`, add convenience scripts:
     - `"dev": "bash ./start-all.sh"`
     - `"dev:backend": "npm --prefix backend run dev"`
     - `"dev:frontend": "npm --prefix frontend run dev"`
     - `"admin:create": "npm --prefix backend run admin:create --"`

---

### STEP 6: Simplify App Configuration & Improve Admin Login UX (`backend/src/routes/admin.ts`, `frontend/pages/admin/RegisterAppModal.tsx`, `frontend/pages/admin/EditAppModal.tsx`, `frontend/pages/admin/AdminLogin.tsx`)

1. **Auto-Derive Allowed CORS Origins from Redirect URIs:**
   - In `backend/src/routes/admin.ts` (`POST /clients` and `PATCH /clients/:id`):
     - If `allowed_origins` / `allowedOrigins` is empty or omitted, automatically derive it from `redirectUris` by extracting `new URL(uri).origin` (deduplicated). Even if `allowedOrigins` is provided, merge or provide a clean helper so admins never get `"At least one allowed origin is required"` when they already provided valid `redirect_uris`.
   - In `frontend/pages/admin/RegisterAppModal.tsx` and `frontend/pages/admin/EditAppModal.tsx`:
     - When a user adds a Redirect URI (e.g., `https://myapp.com/api/auth/callback` or `http://localhost:3001/api/auth/callback`), automatically add its origin (`https://myapp.com` or `http://localhost:3001`) to `allowedOrigins` if not already present!
     - Make the Allowed CORS Origins field optional in the UI (showing "Auto-filled from Redirect URIs — add extra origins only if your frontend domain differs from your callback domain").
2. **Improve `/admin/login` Session Switching (`frontend/pages/admin/AdminLogin.tsx`):**
   - When a user visits `/admin/login` while holding a non-Super-Admin session (`role !== 'admin' || user.scopedClientId !== null`), instead of blocking the login form behind an "Access Restricted" card that forces an extra click, automatically sign out the non-Super-Admin session or show the login form directly with a banner ("Signed out of consumer/scoped account — please sign in with your Global Super Admin credentials").

---

### STEP 7: Verification Gate

After applying all changes, run and verify:
1. `cd backend && npm run build` (must compile with 0 errors)
2. `cd frontend && npm run lint && npm run build` (must pass ESLint and Vite build with 0 errors)
3. `cd backend && npm run test:all-security` (all security suites must pass, updating any test expectations in `test-client-mode-transition.ts` or `production-vs-development-suite.ts` only if they specifically asserted that `isDev: true` clients could not include `https://` URIs alongside loopback URIs)
4. `npm run security:integration-check` and `npm run security:docs-check`
```

---

## Part 4: How to Test Locally Without Deploying Every Time

Once the prompt above is applied, you have **two fast ways** to test any consumer application locally without deploying to AWS Lambda or Vercel:

### Workflow A: Test Local Consumer App Against Your Live Deployed IdP (`https://oauth21.vercel.app`)
You do **not** need to redeploy the IdP or your consumer app to test OAuth 2.1 login:
1. Open your deployed Admin Console (`https://oauth21.vercel.app/admin/clients`).
2. Click **Create application** (or **Edit** your existing app) and enable **Development Mode (`Dev`)**.
3. Add your local callback URL to **Redirect URIs** (for example, `http://localhost:3001/api/auth/callback` or `http://localhost:4000/auth/callback`).
4. In your local consumer app's `.env.local`, point `AUTH_ISSUER=https://oauth21.vercel.app` and `AUTH_CALLBACK_URL=http://localhost:3001/api/auth/callback`.
5. Run your consumer app locally (`npm run dev`). It will redirect to `https://oauth21.vercel.app`, authenticate, and redirect right back to `http://localhost:3001/api/auth/callback`!

### Workflow B: Run the Entire IdP + Consumer Stack 100% Locally
1. Copy `.env.example` to `backend/.env` and set your `MONGO_URI` (use a separate database name like `.../oauth_dev` so local testing never touches production data).
2. Seed the demo apps and create your local Super Admin:
   ```bash
   cd backend
   npm run db:setup
   npm run db:seed
   npm run admin:create -- admin@local.dev "AdminPassword@123!"
   ```
3. From the repo root, start all 5 local servers with one command:
   ```bash
   ./start-all.sh
   ```
   - **IdP Backend API:** `http://localhost:3000`
   - **IdP Frontend & Admin Console:** `http://localhost:5174/admin`
   - **Next.js Test Consumer App:** `http://localhost:3001`
   - **Express + React Test Consumer App:** `http://localhost:5175` (Backend on `:4000`)
