# Verify: Application configuration simplification · spec 0005 · updated 2026-10-15
_Steps derived from spec 0005 acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## UI / manual
- [x] In RegisterAppModal or EditAppModal, add redirect URI `https://app.example.com/auth/callback` -> Allowed CORS Origins automatically populates `https://app.example.com` -> AC-1, AC-6
- [x] In RegisterAppModal or EditAppModal, click "Auto derive from redirect URIs" with registered redirect URIs -> Allowed CORS Origins populates unique derived web origins -> AC-1, AC-6
- [x] Submit client creation without providing explicit allowed origins -> backend auto derives origins and client creation succeeds -> AC-2
- [x] Submit client update with new redirect URIs and empty allowed origins -> backend updates allowed origins from redirect URIs -> AC-2
- [x] Submit client creation with custom native mobile redirect URI (`myapp://oauth/callback`) -> derivation safely skips non web scheme -> AC-4
- [x] Retrieve client details via `GET /api/admin/clients` or `GET /api/admin/clients/:id` -> response includes both camelCase and snake_case properties consistently -> AC-5

## Commands
- [x] `npm --prefix backend run test:config-simplification` -> passes all 6 origin derivation and field normalization tests -> AC-1, AC-2, AC-3, AC-4, AC-5
- [x] `npm run test:unit` -> passes all 5 unit test suites across monorepo -> AC-1, AC-2, AC-3, AC-4, AC-5
- [x] `npm run security:integration-check` -> 0 violations verified against integration contract
- [x] `npm run security:docs-check` -> 0 errors verified against documentation consistency
- [x] `npm --prefix frontend run build` -> frontend builds cleanly
- [x] `npm --prefix backend run build` -> backend lambda bundle builds cleanly

## Acceptance-criteria coverage
- AC-1: covered by test:config-simplification (extracts unique web origins from valid HTTP and HTTPS redirect URIs)
- AC-2: covered by test:config-simplification (auto derives allowed origins when omitted or empty on creation or update)
- AC-3: covered by test:config-simplification (explicitly supplied allowed origins are preserved without unwanted overrides)
- AC-4: covered by test:config-simplification (non web schemes and malformed URIs safely skipped without throwing errors)
- AC-5: covered by test:config-simplification (centralized normalizeOAuthClientFields resolves camelCase and snake_case consistently)
- AC-6: covered by RegisterAppModal and EditAppModal auto derive button and onAdd origin synchronization
