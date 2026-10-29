# Verify: Dev isolation and dual mode client URIs · spec 0004 · updated 2026-10-14
_Steps derived from spec 0004 acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## UI / manual
- [x] Set `targetState.isDev = true` with dual redirect URIs (`http://localhost:3000/callback` and `https://preview.swyra.com/callback`) in admin console or API -> client validates as native application type with both URIs accepted -> AC-1
- [x] Set `targetState.isDev = false` with loopback redirect URI (`http://localhost:3000/callback`) in admin console or API -> validation fails closed with error requiring development mode or HTTPS -> AC-2
- [x] Set `targetState.isDev = true` with RFC1918 private IP (`https://192.168.1.1/callback`) -> validation fails with private IP rejection -> AC-1
- [x] Create development client in production as verified Super Admin (`isSuperAdminOp = true`) -> client registration succeeds without global flag -> AC-3
- [x] Create development client in production without Super Admin privileges (`isSuperAdminOp = false`) -> client registration fails closed -> AC-3
- [x] Send request to management endpoint in development mode with unconfigured gateway secret and Host header `localhost:5174` -> request permitted with warning log -> AC-5
- [x] Send request to management endpoint in development mode with unconfigured gateway secret and Host header `api.external.com` -> request rejected with 403 Forbidden -> AC-5
- [x] Send request to management endpoint in production mode with unconfigured gateway secret and Host header `localhost:3000` -> request rejected with 403 Forbidden -> AC-4

## Commands
- [x] `npm --prefix backend run test:dev-isolation` -> passes all 18 unit and security assertions -> AC-1, AC-2, AC-3, AC-4, AC-5, AC-6, AC-7
- [x] `npm --prefix backend run test:admin-scoping` -> passes all role scoping and identity decoupling tests -> AC-3
- [x] `npm --prefix backend run test:runtime-resilience` -> passes resilient socket recovery and key resolution tests
- [x] `npm --prefix backend run test:gateway-pipeline` -> passes gateway pipeline verification
- [x] `npm run security:integration-check` -> 0 violations verified against integration contract -> AC-1, AC-2
- [x] `npm run security:docs-check` -> 0 errors verified against documentation consistency
- [x] `npm --prefix frontend run build` -> builds production bundle cleanly with automated config prep
- [x] `npm --prefix backend run build` -> builds lambda bundle cleanly

## Acceptance-criteria coverage
- AC-1: covered by test:dev-isolation (dev client permits loopback and public HTTPS, rejects wildcards, fragments, userinfo, non loopback HTTP, private IPs)
- AC-2: covered by test:dev-isolation (production client strictly HTTPS only, zero loopback, zero private IPs)
- AC-3: covered by test:dev-isolation (Super Admin creates dev client in production without global flag)
- AC-4: covered by test:dev-isolation (production mode gateway secret verification strictly fails closed)
- AC-5: covered by test:dev-isolation (development mode permits loopback requests when secret is unconfigured, rejects non loopback)
- AC-6: covered by test:dev-isolation (monorepo root .env.example defaults to development and defines gateway secret)
- AC-7: covered by test:dev-isolation (start-all.sh, check_users.mjs, test_signup.mjs path fixes, root package.json convenience scripts)
