# frontend/AGENTS.md

Rules for AI coding agents (Antigravity, Claude Code, Copilot, Cursor) working **inside `frontend/`** of M Auth by SWYRA.

Scope: **UI only.** The root `AGENTS.md` (IdP / consumer-integration contract), `rules.md` and `boundaries.md` still apply. This file adds frontend-specific rules and wins for anything under `frontend/`. The design source of truth is **`../ui-ux.md`**: read it before any UI task.

**Tradeoff:** these rules favor caution over speed. For a trivial one-line fix, use judgment.

---

## 1. Think before coding
- State assumptions. If uncertain, ask. If several interpretations exist, present them; don't pick silently.
- If a simpler approach exists, say so and push back.
- If something is unclear or touches a frozen item (Section 4), **stop and ask**.
- Read the file and trace the real flow before editing. A small diff you don't understand is a second bug.

## 2. Simplicity first
- Minimum code that solves the task. No speculative features, props, abstractions or "flexibility".
- Reuse before writing: existing component, `components/ui/*` primitive, token, hook, util. Then the platform/CSS. Then an installed dependency. Only then new code.
- **No new dependency** unless `../ui-ux.md` names it (currently only the font packages, and only after its Decision 9 is resolved). No motion library, chart library, command-palette library, icon pack.
- Deletion over addition. If 200 lines could be 50, rewrite.

## 3. Surgical changes
- Every changed line must trace to the task. Don't "improve" adjacent code, comments or formatting. Match existing style.
- Remove only the imports/variables **your** change orphaned. Mention unrelated dead code; don't delete it.
- **Never re-run `npx shadcn add ...` or regenerate `components/ui/*`**: it overwrites our edits. Edit those files in place.
- Don't hand-write `useMemo`/`useCallback` in new code: React Compiler is enabled (`vite.config.ts`). Don't strip existing ones either.

## 4. FROZEN: UI-only means these do not change
```text
backend/**                       (never touch from a frontend task)
API calls                        URLs, methods, headers, bodies, credentials: 'include'
lib/api.ts  lib/csrf.ts  lib/auth-client.ts  lib/security.ts  lib/role-predicates.ts
hooks/useOAuthParams.ts          components/AdminRoute.tsx logic (UX guard only; server requireAdmin is the gate)
OAuth flow                       client_id, redirect_uri, state, scope, code_challenge(_method), prompt, is_public,
                                 callbackURL handling, window.location.assign flows, /callback, /signout
Routes                           every path in src/App.tsx (nesting may change, URLs may not)
lib/adminStore.ts                fetch*/ *Local functions, CACHE_TTL, shapes (types may be extended ADDITIVELY only)
Forms                            react-hook-form + zod schemas, field names, validation meaning
Infra                            vite.config.ts proxy, vercel*.json, env vars, package.json scripts
```
You **may** change: `src/index.css`, markup/classNames in presentational components and pages, `components/ui/*` styling, page layout, copy text (never the meaning of an error), `index.html` title/meta, `main.tsx` theme default, `App.tsx` route nesting.

**Data honesty:** render only fields the API already returns. If a field is absent, hide the element or show an empty state. **Never mock, never invent numbers, no new endpoints.** (The server cannot report failed logins, outcome, per-app logins, key age or deltas.)

## 5. Repo facts you must respect
- Stack: Vite 8, React 19 + React Compiler, Tailwind v4 (`@tailwindcss/vite`), shadcn `radix-nova`, zustand, react-router 7, `better-auth` client, react-hook-form + zod, `sonner`, `next-themes`.
- Import alias `@` = the **`frontend/` root** (not `src/`): `@/components/...`, `@/lib/...`, `@/pages/...`.
- Dark mode = **`.dark` class** on `<html>` (`next-themes`, `attribute="class"`). There is no `data-theme`.
- Theming = CSS variables in `src/index.css` mapped through `@theme { --color-*: var(--*) }`. **Use tokens (`bg-card`, `text-muted-foreground`, `bg-primary`, `bg-motorsport-*`). No raw hex, no raw Tailwind palette colors (`emerald-500` etc.) in components.**
- Fonts are self-hosted through `@fontsource`. **Zero third-party requests** on auth pages. Never add Google Fonts or CDN assets.
- No inline `<style>`, inline `style=""` (except existing CSS-variable passthroughs), or inline scripts: use classes (CSP-safe).
- TOTP QR codes are generated locally (`qrcode.react`). Never send an `otpauth://` URI to a third party.
- **Build with `npm run build:ui`** (or `npx vite build`), **not `npm run build`**: the latter runs `prepare-vercel-config` and can rewrite deployment config.
- Dev server: `npm run dev` (port 5174, proxies `/api` and `/.well-known` to the backend on 3000).

## 6. Design rules (details in `../ui-ux.md`)
- Solid surfaces for content. Glass **only** on the sticky admin header. Never on cards, tables, forms, login/2FA/consent, dialogs, errors.
- Max **3** BMW-derived elements per screen. M red is for graphics only; danger **text** uses `--destructive`.
- Sentence case labels. No ALL-CAPS tracked labels. No jargon ("telemetry", "pilot", "engine").
- Every interactive component needs all states: default, hover, `focus-visible`, pressed, disabled, loading, error, success.
- Motion: CSS only, `transform`/`opacity` only, **no `transition-all`**, honor `prefers-reduced-motion`. Static (non-interactive) cards do not hover-lift.
- Status/meaning is never color-only (icon or text too). Targets >= 44 px. Keyboard parity for every hover reveal.
- Both themes must pass. Dark is the default theme; light is fully supported.

## 7. Performance rules (measured baseline in `../ui-ux.md` 0.5)
- Re-measure the baseline yourself before the first edit (`npm run build:ui`, gzip the entry + route chunks).
- **No route may grow > 5%** over baseline JS without a written reason in the PR. CSS <= 20 KB gz.
- No new request, no new route-level import of a heavy lib. Lazy-load only when measured to save >= 10 KB gz on that route.
- Auth routes must stay light: do not import chart/table/drawer/heavy code there.
- No unused fonts/CSS. No `backdrop-filter` outside the header. Never animate blur or layout properties.
- Use in-shell skeletons (after 150 ms) rather than full-screen loaders.

## 8. Goal-driven execution
Turn each task into verifiable steps before coding:
```
1. [Baseline] tests/lint/build + screenshots + network log -> saved before edit
2. [Change]   smallest diff for the task                  -> verify: lint + tsc + build:ui green
3. [Verify]   network log identical, both themes, keyboard -> verify: gate in Section 9
```
Frontend has no unit-test suite; the verification is the gate below plus the manual flows. If you add non-trivial logic, leave one small runnable check.

## 9. Gate: every PR must pass
- [ ] `npm run lint`, `npx tsc -b`, `npm run build:ui` green
- [ ] **Network log (HAR) diff vs baseline: same endpoints, methods, payload shapes, same request count** for sign in, wrong password, TOTP + backup code, Google, forgot/reset, consent, each admin page, create/edit/revoke app, enable/disable 2FA
- [ ] OAuth round trip with `../test/react-express-app` or `../test/next-app`: `state` + PKCE intact, redirect lands, token exchange works; private-app (`is_public=false`) still shows no sign-up
- [ ] Light + dark screenshots of every touched page/state
- [ ] Route-size table before/after (within 5%)
- [ ] Keyboard-only pass on touched flows; reduced-motion respected
- [ ] No frozen file changed (`git diff --stat` reviewed)

## 10. Workflow
- One concern per PR, following the order in `../ui-ux.md` Section 11 (PR 1 Foundation, 2 Shell, 3 Auth pages, 4 Admin pages, 5 Polish). Never mix a redesign with a logic change.
- Rollback = `git revert`. Do not add feature flags.
- Docs discipline (`../rules.md`): update `../CHANGELOG.md` per PR and `../memory.md` at the end of each session. If you change a documented decision, update that doc in the same change.

## 11. Report format (end of every task)
```
Changed:          files + one line each
Not changed:      things you were tempted to touch but left (and why)
Bundle table:     before -> after (per route touched)
Network log diff: identical / differences
Assumptions:      anything you decided without being told
Backend issues:   anything wrong you noticed in backend/ (reported, not fixed)
```

---
**These rules are working if:** diffs are small and every line traces to the task, the network log never changes, bundle sizes never grow unexplained, and questions come before mistakes.
