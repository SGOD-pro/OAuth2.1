# Verify: Gateway secret persistence and deploy pipeline · spec 0003 · updated 2026-10-14
_Steps derived from feature acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## UI and manual
* [x] Run `npm --prefix frontend run build` without `INTERNAL_GATEWAY_SECRET` in environment → skips vercel.json generation with warning and completes build with zero errors → AC-1, AC-4
* [x] Run `node scripts/prepare-vercel-config.mjs --clean` → removes root `vercel.json` and `frontend/vercel.json` → AC-1

## Commands
* [x] `node scripts/prepare-vercel-config.mjs --if-present` → returns exit code 0 when secret is missing → AC-1
* [x] `node scripts/prepare-vercel-config.mjs` without secret → returns exit code 1 with fatal message → AC-2
* [x] `INTERNAL_GATEWAY_SECRET=short node scripts/prepare-vercel-config.mjs` → returns exit code 1 rejecting secret shorter than 32 characters → AC-2
* [x] `INTERNAL_GATEWAY_SECRET=test_gateway_secret_minimum_32_characters_valid_string LAMBDA_BACKEND_URL=https://custom.lambda.aws node scripts/prepare-vercel-config.mjs` → generates `vercel.json` containing secret and custom URL → AC-3
* [x] `npm --prefix backend run test:gateway-pipeline` → runs 8 automated assertions with 0 failures → AC-1, AC-2, AC-3, AC-4, AC-5
* [x] `npm run security:integration-check` → passes all isolation checks with 0 violations → AC-4

## Acceptance criteria coverage
* AC-1 covered by prepare vercel config if present command test and clean command test
* AC-2 covered by missing secret rejection test and short secret rejection test
* AC-3 covered by lambda backend url override test
* AC-4 covered by frontend build script inspection and live build verification
* AC-5 covered by backend deploy script parameter override inspection

