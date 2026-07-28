
# Rules

## Governing philosophy
This project is built under the "lazy senior developer" discipline: the smallest correct diff wins, nothing is abstracted that wasn't explicitly required, and root causes get fixed once at the shared function, not patched per call site. Every rule below exists to make that discipline checkable, not just aspirational.

## Before writing any code
1. Does it need to exist at all? (YAGNI — see `design.md` "Explicitly rejected in this design").
2. Does it already exist in this repo? Reuse `hono/src/config`, `hono/src/db/mongo.ts`, `hono/src/cache/origin-cache.ts` patterns.
3. Does the **Better Auth identity engine** already do this? Do not hand-roll anything OAuth/OIDC/crypto-adjacent — including TOTP/MFA provisioning. The logic is provided by the npm package.
4. Does a native platform feature cover it? (MongoDB TTL indexes for ephemeral state, Hono runtime adapters for multi-platform deploy).
5. Only then write new code, and write the minimum that works.

## Bug fixes
- Root cause, not symptom. If a bug is found in a shared function (e.g. `validateRedirectUri`), fix it once there and grep every caller.
- Every non-trivial fix leaves behind the smallest runnable check that fails if the bug returns.

## Coding standards
- TypeScript strict mode stays on (`hono/tsconfig.json`, `strict: true`) — never weakened.
- No `any` used to silence a type error introduced by new code.
- All environment access goes through `hono/src/config/index.ts` / `envSchema`. No direct `process.env` reads outside that composition root.
- All new cross-invocation state goes into MongoDB TTL collections (`rate_limits`, `origin_cache`). No second database (e.g., Redis, DynamoDB).
- `hono/src/app.ts` must contain zero platform-specific imports. Platform coupling belongs only in entry point files (`lambda.ts`, `vercel.ts`, etc.).
- **No external QR Code APIs**: TOTP QR codes must be generated locally in the browser (e.g., `qrcode.react`). Never leak `otpauth://` URIs to third-party servers.
- **Use `better-auth` npm dependency**: The package must appear in `hono/package.json`. Identity Engine: Better Auth v1.x via npm. Implements OAuth 2.1/OIDC, session management, and TOTP MFA.

## Linting / CI enforcement
- CI must run: typecheck (`tsc --noEmit`), lint, and the E2E security tests in `consumer-test/`.
- CI must fail if `hono/package.json` contains `better-auth` as a runtime dependency.
- CI must fail if `hono/src/app.ts` (or any route/middleware file) imports platform-specific adapters.
- No merge to the deployable branch without CI green.

## Documentation discipline
- Any change to a boundary, contract, or decision described in `boundaries.md`, `design.md`, or `decision.md` must update that file in the same change.
- `memory.md` is updated at the end of each work session, not retroactively reconstructed.
