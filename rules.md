# Rules

## Governing Philosophy

This project is built under the "lazy senior developer" discipline already codified in `AGENTS.md`: the smallest correct diff wins, nothing is abstracted that wasn't explicitly required, and root causes get fixed once at the shared function, not patched per call site. Every rule below exists to make that discipline checkable, not just aspirational.

## Before Writing Any Code

- Does it need to exist at all? `YAGNI` - see `design.md` "Explicitly Rejected in This Design" for examples of features considered and cut, like hand-rolled encryption or email OTP.
- Does it already exist in this repo? Reuse `hono/src/config`, `hono/src/db/mongo.ts`, and `hono/src/cache/origin-cache.ts` patterns before writing new infrastructure.
- Does Better Auth already do this? Do not hand-roll anything OAuth/OIDC/crypto-adjacent, including TOTP/MFA provisioning and verification. See `decision.md` ADR 001 and ADR 011.
- Does a native platform feature cover it? Use MongoDB TTL indexes for ephemeral state instead of a second database, Hono runtime adapters for multi-platform deploy, and reserved concurrency for connection caps. See `architecture.md`.
- Only then write new code, and write the minimum that works.

## Bug Fixes

- Root cause, not symptom. If a bug is found in a shared function such as `validateRedirectUri`, fix it once there and grep every caller. Do not patch only the call site the report happened to mention.
- Every non-trivial fix leaves behind the smallest runnable check that fails if the bug returns: an assert-based script or one small test file. No test framework is required for a one-off check. Trivial one-liners, such as a single import swap, are exempt.

## Coding Standards

- TypeScript strict mode stays on (`hono/tsconfig.json`, `strict: true`). Never weaken it to unblock a build.
- No `any` used to silence a type error introduced by new code. Existing `any` usage inherited from Better Auth's plugin typing gaps may remain, but it is not a pattern to extend.
- All environment access goes through `hono/src/config/index.ts` and `envSchema`. No direct `process.env` reads outside that composition root.
- All new cross-invocation state goes into MongoDB TTL collections (`rate_limits`, `origin_cache`) defined in `design.md`. No second database such as DynamoDB or Redis, and no reintroduction of in-memory `Map` or `LRUCache` for anything that must be correct across concurrent execution environments.
- `hono/src/app.ts` must contain zero platform-specific imports. Platform coupling belongs only in entry point files like `lambda.ts`, `vercel.ts`, and `node-server.ts`.
- Prettier config, repo-wide, is the formatting source of truth. No manual formatting debates and no local overrides.

## Linting and CI Enforcement

- `eslint.config.mjs` or the Hono-side equivalent runs on every push. `no-floating-promises` and `no-unsafe-argument` stay at warn minimum and must not be silently disabled per file without a comment explaining why.
- CI must run, at minimum: typecheck (`tsc --noEmit` or build), lint, and the self-check script or scripts left behind by non-trivial fixes per the rule above.
- CI must fail the build if `hono/src/lambda.ts` imports from `hono/lambda-edge`. This regression is cheap to catch mechanically and expensive to catch in production. A one-line grep-based CI step is sufficient.
- CI must fail if `hono/src/app.ts` or any route or middleware file imports platform-specific adapters such as `hono/aws-lambda` or `hono/vercel`. The core app must remain platform-agnostic.
- No merge to the deployable branch without CI green. No exceptions for "it's just a docs change" - docs changes don't touch code paths CI checks, so this costs nothing to enforce uniformly.

## Documentation Discipline

- Any change to a boundary, contract, or decision described in `boundaries.md`, `design.md`, or `decision.md` must update that file in the same change. Documentation drift is treated as a bug.
- `memory.md` is updated at the end of each work session, not retroactively reconstructed. See `memory.md` itself.
