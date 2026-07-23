# Engineering Rules

## Governing philosophy
This project is built under the "lazy senior developer" discipline already codified in `AGENTS.md`:
the smallest correct diff wins, nothing is abstracted that wasn't explicitly required, and root causes
get fixed once at the shared function, not patched per call site. Every rule below exists to make that
discipline checkable, not just aspirational.

## Before writing any code
1. Does it need to exist at all? (YAGNI — see `design.md` "Explicitly rejected in this design" for two
   live examples of features considered and cut.)
2. Does it already exist in this repo? Reuse `hono/src/config`, `hono/src/db/mongo.ts`,
   `hono/src/cache/origin-cache.ts` patterns before writing new infrastructure.
3. Does Better Auth already do this? Do not hand-roll anything OAuth/OIDC/crypto-adjacent — see
   `decision.md` ADR on rejecting "0 dependency."
4. Does a native AWS/platform feature cover it? (Reserved concurrency over a connection-pool rewrite is
   the canonical example in this project — see `architecture.md`.)
5. Only then write new code, and write the minimum that works.

## Bug fixes
- Root cause, not symptom. If a bug is found in a shared function (e.g. `validateRedirectUri`), fix it
  once there and grep every caller — do not patch the one call site the report happened to mention.
- Every non-trivial fix leaves behind the smallest runnable check that fails if the bug returns: an
  assert-based script or one small test file. No test framework required for a one-off check. Trivial
  one-liners (e.g. a single import swap) are exempt.

## Coding standards
- TypeScript strict mode stays on (`hono/tsconfig.json`, `strict: true`) — never weakened to unblock a build.
- No `any` used to silence a type error introduced by new code. Existing `any` usage inherited from Better
  Auth's plugin typing gaps (e.g. `admin-auth.ts`) may remain but is not a pattern to extend.
- All environment access goes through `hono/src/config/index.ts` / `envSchema`. No direct `process.env`
  reads outside that composition root.
- All new cross-invocation state goes into the single DynamoDB table defined in `design.md`. No second
  ad-hoc table, no reintroduction of in-memory `Map`/`LRUCache` for anything that must be correct across
  concurrent Lambda execution environments.
- Prettier config (`backend/.prettierrc` equivalent applied repo-wide) is the formatting source of truth —
  no manual formatting debates, no local overrides.

## Linting / CI enforcement
- `eslint.config.mjs` (or the Hono-side equivalent) runs on every push; `no-floating-promises` and
  `no-unsafe-argument` stay at `warn` minimum, must not be silently disabled per-file without a comment
  explaining why.
- CI must run, at minimum: typecheck (`tsc --noEmit` or build), lint, and the self-check script(s) left
  behind by non-trivial fixes per the rule above.
- CI must fail the build if `hono/src/lambda.ts` imports from `hono/lambda-edge` — this specific
  regression is cheap to catch mechanically and expensive to catch in production (see `decision.md`).
  A one-line grep-based CI step is sufficient; do not build tooling beyond that.
- No merge to the deployable branch without CI green. No exceptions for "it's just a docs change" —
  docs changes don't touch code paths CI checks, so this costs nothing to enforce uniformly.

## Documentation discipline
- Any change to a boundary, contract, or decision described in `boundaries.md`, `design.md`, or
  `decision.md` must update that file in the same change. Documentation drift is treated as a bug.
- `memory.md` is updated at the end of each work session, not retroactively reconstructed — see `memory.md` itself.