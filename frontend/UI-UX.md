# M Auth: UI/UX Redesign Spec (repo-aware)

**Version 2.0** | 31 Oct 2026 | Repo: `SGOD-pro/OAuth2.1` (commit `d5e7663`) | Replaces the repo's current `ui-ux.md` (same file, case differs: **overwrite `ui-ux.md` with this file**; a case-insensitive filesystem cannot hold both).

**Inputs merged:** Fernly reference, `pro-animation-skill.md`, `APPLE-GLASS-DESIGN.md`, Evergreen / Forest Stone brand sheets, BMW M touch, **and the actual codebase** (read: frontend, `admin.ts` stats/logs handlers, repo rules; built: `vite build`, measured).

> This version replaces v1.1, which was written without seeing your repo. Corrections are in 0.1. Everything below is mapped to your real files, real API fields and measured numbers.

---

## 0. Contract (read first)

### 0.1 What changed from v1.1 (honest corrections)
| v1.1 claimed | Reality in your repo | Consequence |
|---|---|---|
| Revoke has no confirmation | `AdminClients.tsx` already has a confirm dialog with consequences | Keep it. Typed confirmation is an optional upgrade, not a fix. |
| Audit log can show outcome / failures; Overview can show a sign-in success gauge | `/api/admin/logs` returns **successful sessions** (`user_sign_in`) + `admin_audit` entries only. Failed logins are never recorded. | **Gauge, success-rate, failed-sign-in KPI and outcome column are removed.** They would be fiction. |
| Auth-route JS budget <= 70 KB gz | Measured: **entry alone is 144.6 KB gz**; login total ~188 KB gz | Budget is now "no regression from measured baseline" (0.5). |
| Stack unknown, `data-theme`, new chart/motion libs | Vite 8 + React 19 + React Compiler + Tailwind v4 + shadcn (`radix-nova`) + zustand + react-router 7 + better-auth client; dark = `.dark` class via `next-themes` | Spec now edits `src/index.css` variables and existing shadcn files. No new libs. |
| Command bar, charts, live tail, request-access page | Not in repo; would need new deps/endpoints; register is already a tab in `SignIn.tsx` | Dropped (YAGNI, see `AGENT.md` / `rules.md`). |

### 0.2 Repo rules this spec obeys
- `AGENT.md` / `rules.md` "lazy senior dev": smallest correct diff, reuse existing code, **no new dependency unless unavoidable**, no abstraction nobody asked for, delete over add. Non-trivial logic leaves one runnable check.
- `boundaries.md`: **Frontend owns presentation and route orchestration only.** The admin route guard is UX, never security. Server `requireAdmin` is the gate. No frontend change may weaken or move that.
- `rules.md` documentation discipline: any change to a decision in `boundaries.md` / `design.md` / `decision.md` updates that file in the same change. `memory.md` updated at end of each session.
- **Superseded decisions** (so agents stop following stale rules): the old `ui-ux.md` palette (graphite + `#245DCF`), fonts (Space Grotesk / Geist), "no pill shapes", golden-ratio spacing scale and "8px radius" are **replaced by this file**.

### 0.3 FROZEN: do not change, rename, reorder or "clean up"
```text
Backend            everything under backend/ (this is a UI-only pass)
API calls          every URL, method, header, body, credentials: 'include' behavior
lib/api.ts         apiFetch / getApiUrl           lib/csrf.ts    csrf_token cookie -> x-csrf-token
lib/auth-client.ts better-auth client + twoFactorClient onTwoFactorRedirect handler
lib/security.ts    safeCallbackURL / isPublicSignupEnabled
lib/role-predicates.ts, components/AdminRoute.tsx logic (UX guard only)
hooks/useOAuthParams.ts, Layout.tsx InvalidRequest gating on /auth
OAuth flow         client_id, redirect_uri, state, scope, code_challenge(_method), prompt,
                   is_public, callbackURL handling in SignIn; window.location.assign flows;
                   /api/auth/oauth2/authorize continuation; /callback; /signout
Routes             every path in src/App.tsx (URLs must not change)
Store contract     lib/adminStore.ts: fetch*/ *Local functions, CACHE_TTL, shapes.
                   Types may be extended ADDITIVELY only (e.g. add activeSessions to Stats).
Forms              react-hook-form + zod schemas, field `name`s, validation messages' meaning
Infra              vite.config.ts proxy (/api, /.well-known, x-gateway-secret), vercel*.json
```
**You may change:** `src/index.css`, class names/markup inside presentational components, `components/ui/*` styling, page layout/markup, copy text (not meaning of errors), fonts, `index.html` title/meta, `main.tsx` theme default, `App.tsx` **route nesting only** (same paths).

### 0.4 Regression gate (every PR)
Baseline first, then after each PR:
- [ ] `npm run lint`, `tsc -b`, `vite build` green (frontend). Backend suites untouched: `backend/tests` (unit, security, e2e incl. `browser-e2e.test.ts`) still pass if they are run in CI.
- [ ] **Network log (HAR) diff vs baseline: same endpoints, methods, payload shapes, same request count** on: sign in, wrong password, TOTP, backup code, Google, forgot/reset, consent, every admin page, create/edit/revoke app, enable/disable 2FA.
- [ ] Manual OAuth round trip with a real consumer (`test/react-express-app` or `test/next-app`): `state` + PKCE intact, redirect lands, token exchange works, private-app `is_public=false` path still shows no sign-up.
- [ ] Screenshots of every page/state before vs after (light + dark).
- [ ] Rollback = `git revert` of the PR. No flag system (YAGNI). Keep PRs small (Section 11).
- [ ] **Stop and ask** if any change seems to require touching a frozen item.

### 0.5 Performance: measured baseline and budgets
Measured with a fresh `npx vite build` in a sandbox (your CI may differ slightly; remeasure before PR1 and use *your* numbers as the baseline).

| Load | JS gz (always-loaded entry + route) | Notes |
|---|---:|---|
| **Entry chunk set (every page)** | **144.6 KB** | `index` 95.2 + shared `card` chunk 44.3 + `dist` 10.5 |
| /auth (sign in) | **~188 KB** (+43.7) | includes react-hook-form/zod chunk 29.8 |
| /two-factor | ~148 KB (+3.2) | |
| /forgot-password | ~177 KB (+32.7) | |
| /consent | ~147 KB (+2.7) | |
| /admin/login | ~178 KB (+33.7) | |
| /admin (overview) | ~164 KB (+18.9) | |
| /admin/clients | **~202 KB (+57.6)** | heaviest |
| /admin/logs | ~165 KB (+20.3) | |
| /admin/security | ~172 KB (+27.6) | |
| CSS | 14.9 KB gz (92.3 KB raw) | |
| Fonts (latin only, today) | 51.7 KB | Geist 29.4 + Space Grotesk 22.3 (Figtree is imported but never used) |

**Budgets:** no route may grow > **5%** over baseline JS without a written reason in the PR. CSS <= 20 KB gz. Third-party requests on auth pages = **0** (already true: fonts are self-hosted via `@fontsource`; keep it). Targets to verify on **Slow 4G + 4x CPU + a real low-end Android**: LCP <= 2.5 s, CLS <= 0.1, INP <= 200 ms. These are targets, not measured results.

**Concrete wins found (each only if measured to help; each is optional):**
1. Delete unused deps `three`, `@react-three/fiber`, `@types/three`: **no source imports them** (zero bundle effect, faster installs/CI).
2. Remove `@fontsource-variable/figtree` import (dead `@font-face` CSS) and fix the `Geist Mono Variable` reference that is **never imported** (falls back to system mono today).
3. Replace the full-screen `RouteLoader` Suspense fallback with an in-shell skeleton (shell stays mounted; Section 6).
4. Entry candidates (measure before/after; keep only if >= 3 KB gz saved): `sonner` (~68 KB source, loaded because `<Toaster/>` is in `Layout`), tooltip/floating-ui (in `Layout`), `zod` + `react-hook-form` chunk (loaded on 4 pages).
5. Pause `/admin/logs` 30 s auto-refresh while the tab is hidden (`document.visibilityState`): tiny change, fewer requests.
6. Check caching with `curl -I` on a hashed `/assets/*` file: it should be `immutable` with a long max-age and brotli. This repo uses the legacy `routes` format in `vercel*.json`, so framework defaults may not apply. If it isn't, adding a `headers` rule is an infra change **outside this UI pass** (backlog).

### 0.6 Data honesty ledger (what the API really provides)
| UI element | Source | Status |
|---|---|---|
| Applications / Active / Users / Logins 24h | `GET /api/admin/stats` | exists |
| **Active sessions** | `stats.activeSessions` | **returned by API, unused by UI**: free KPI (add to `Stats` type additively) |
| **Recent activity (10)** with IP + user-agent token | `stats.recentActivity[]` | **returned, unused by UI**: free "Recent sign-ins" list |
| Audit rows: user, action, IP, time (<= 100) | `GET /api/admin/logs` | exists; successes + admin actions only |
| Per-client flags | `/api/admin/clients`: `disabled`, `is_dev`, `is_public`, `skip_consent`, `has_custom_admins`, `adminEmail`, `createdAt` | exists |
| Admin 2FA state | `session.user.twoFactorEnabled` (already used in `AdminSecurity.tsx`) | exists, **no API needed** |
| Failed sign-ins, success rate, per-app logins, key age, 7-day deltas, outcome/app/user-agent columns | not in API | **do not render. Backlog (0.7).** |

### 0.7 Backend backlog (NOT in this pass; found while reading)
- `stats.recentLogins` is `last24h || activeSessions || 1`: the trailing `|| 1` **fabricates a number** when there is no data. `activeClients: n || totalClients` likewise. Fix server-side later.
- Logs fall back to IP `"127.0.0.1"` and `"Active Session"` when missing: looks real, isn't.
- To make a real security dashboard later: record failed sign-ins, outcome, client_id, user-agent; expose key age. Until then the UI shows only what exists.

---

## 1. Findings in the current UI (repo-verified)

| # | Finding | Sev | Fix (frontend-only unless noted) |
|---|---|---|---|
| 1 | **Admin shell remounts on every navigation.** Each admin page wraps itself in `<AdminLayout>`, and each admin route is its own `withSuspense(...)`. Sidebar, header and toasts re-create per page. | P1 | One parent route (`AdminRoute` + `AdminLayout` + `<Outlet/>`), same URLs (Section 5). Biggest "smoothness" win. |
| 2 | `RouteLoader` is a **full-screen splash** (animation runs 1.7 iterations) used as Suspense fallback and for `isPending`. Every lazy route feels like a reload. | P1 | In-shell skeleton after 150 ms; keep splash only for the very first auth check. |
| 3 | **"Remember this device" checkbox is dead.** `remember` is in the zod schema and rendered, but never passed to `signIn.email`. | P1 | Remove the checkbox (UI-only). Wiring it is a behavior/security decision: backlog. |
| 4 | Admin account 2FA nudge missing; `twoFactorEnabled` is known client-side. | P0 | Posture card when `twoFactorEnabled` is false (Section 7.1). |
| 5 | Overview stat cards have a filler row ("Status / Registered / Operational / Enrolled / Recent activity"). | P1 | Remove. Add real `activeSessions` + `recentActivity`. |
| 6 | Hard-coded hexes in components (`bg-[#0066B1]`, `hover:bg-[#1E4FB5]`, `active:bg-[#183F91]`, `dark:bg-[#16181D]`...) bypass tokens, so re-theming by variables alone would miss them. | P1 | Replace with tokens (Section 4.4). |
| 7 | Fonts: `Geist Mono Variable` is referenced but **never loaded**; Figtree is loaded but **never used**. | P2 | Fix in the font swap (Section 3.2). |
| 8 | Theme toggle runs a **1 s** circular View Transition and has no reduced-motion guard; no `prefers-reduced-motion` handling for the custom `animate-m-line-*` either. | P2 | <= 400 ms, skip under reduced motion (Section 6). |
| 9 | Copy: `InvalidRequest` says **"Telemetry Violation"** (the repo's own old doc banned "telemetry"); `index.html` title is "SWYRA AUTH SERVICE" while pages use `[Page] · M Auth`. | P2 | Plain copy; base title "M Auth". |
| 10 | Audit table shows local time without a timezone label; native `<select>` for the action filter is inconsistent with shadcn `Select`. | P2 | tz label + `Select`. |
| 11 | Table headers / labels use ALL-CAPS mono (template tell). | P2 | Sentence case (Section 3). |
| 12 | Logo mark is effectively the BMW M mark. | Risk | Decision 2 (Section 12). The logo is one component (`BrandMark.tsx`): swappable. |

**Not a finding (I checked):** Revoke confirmation exists; typed confirm is optional. TOTP input is already a single `<Input inputMode="numeric" autoComplete="one-time-code">` (good). Hugeicons is tree-shaken (the barrel is not in the entry chunk).

---

## 2. Direction: "Evergreen Cockpit"
Calm, matte, evergreen surfaces (brand) with precise M-style detailing (BMW touch). Trust first, sport second.

**From Fernly we take hierarchy and craft, not widgets:** floating rounded sidebar panel on a soft canvas, pill header, big tight page title + one-line subtitle, KPI cards with colored delta, segmented control with dark-green active pill, outline pill secondary button, colored category chips, dark-green card with contour pattern (becomes the security posture card), calm radii. **We do not copy:** mail/bell icons (dead UI), promo card, sparklines on 1-2 data points, donut for a single app.

Principles: content is the surface (solid); one memorable thing per screen; color is information; motion explains; same tokens on every page.

---

## 3. Typography and fonts

**Families (brand sheet [FIXED]):** Source Serif 4 (headlines), Manrope (UI), IBM Plex Mono (code). The logo lettering is fixed artwork (keep `BrandMark.tsx` text as is until Decision 1/2 resolve).

### 3.1 Measured cost (latin subset woff2)
| | Today | Proposed |
|---|---:|---:|
| UI | Geist 29.4 KB | **Manrope variable 24.8 KB** |
| Headings | Space Grotesk 22.3 KB | **Source Serif 4 `wght` 50.9 KB** (use the `wght` file; the `opsz` file is 122 KB: **do not use it**) |
| Mono | *(never loaded)* | **IBM Plex Mono 400 14.7 KB** (fetched only on pages that render mono text) |
| **Total** | **51.7 KB** | **90.4 KB (+38.7 KB)** |

Honest trade-off: the serif is the brand's "premium" signal and costs ~39 KB more than today. It does not block rendering (`font-display: swap`) and only headings/KPI numerals use it. **Default = Option A (brand fonts).** If slow-network performance is judged more important than brand fidelity: **Option B** keep Geist + Space Grotesk (0 KB change) and apply only color/shape/motion. Both are valid; decide in Section 12.

### 3.2 Implementation (Option A), in `src/index.css`
```css
/* remove: figtree, space-grotesk, geist imports */
@import "@fontsource-variable/manrope/wght.css";
@import "@fontsource-variable/source-serif-4/wght.css";   /* NOT the opsz/full index */
@import "@fontsource/ibm-plex-mono/400.css";

@theme {
  --font-sans:    "Manrope Variable", system-ui, sans-serif;
  --font-heading: "Source Serif 4 Variable", Georgia, serif;
  --font-mono:    "IBM Plex Mono", ui-monospace, monospace;
}
```
Packages: add `@fontsource-variable/manrope`, `@fontsource-variable/source-serif-4`, `@fontsource/ibm-plex-mono`; remove `@fontsource-variable/{figtree,geist,space-grotesk}`. Net dependency count unchanged. Keep self-hosted (CSP-safe, zero third-party requests). Add `<link rel="preload" as="font" type="font/woff2" crossorigin>` for **Manrope latin only** (hashed filename from the build; automate or skip). Do not preload the serif or mono.

### 3.3 Scale (map to existing utility classes; no new scale object)
| Role | Class today | New |
|---|---|---|
| Auth hero headline | `font-heading text-[55px] leading-none` | keep size, serif, 600, `tracking-[-0.02em]`; mobile 34 |
| Page title (admin) | `font-heading text-[34px] font-semibold` | **keep 34/40**, serif 600 (brand allows 32-48; 48 would burn vertical space on table pages) |
| Section/card title | `font-heading text-base/lg` | `font-heading text-lg font-semibold` |
| Body / table cell | `font-sans text-sm` | `font-sans text-sm` (14/20) |
| Caption / label | `font-mono text-[10-11px] uppercase tracking-[0.2em]` | **`font-sans text-xs font-medium` sentence case** (remove all-caps tracked labels and `uppercase` on table heads/labels) |
| KPI numeral | `font-heading text-[34px]` | `text-[40px] tabular-nums` serif (verify Source Serif tabular figures; fall back to `font-mono` if widths jump) |
| IDs, timestamps, IPs | `font-mono text-xs` | unchanged class, now actually Plex Mono |

---

## 4. Tokens

### 4.1 How theming works here (do not invent a new system)
`next-themes` toggles the **`.dark` class** on `<html>` (`attribute="class"`); `@custom-variant dark` is already declared; shadcn components read `--background`, `--card`, `--primary`, … through `@theme { --color-*: var(--*) }`. **Re-theming = replace the variable values in `src/index.css`.** Almost every component restyles with zero code edits. The only code edits are the hard-coded hexes (4.4).

`src/main.tsx`: change `defaultTheme="system"` to **`defaultTheme="dark"`** (owner decision: dark default, light supported). Keep `enableSystem`. next-themes already prevents the wrong-theme flash.

### 4.2 Variables (replace the `:root` and `.dark` blocks)
```css
:root {                                  /* Light: Forest Stone */
  --background:#EEECE5;  --foreground:#111A17;
  --card:#F7F7F2;        --card-foreground:#111A17;
  --popover:#FFFFFF;     --popover-foreground:#111A17;
  --primary:#102D25;     --primary-foreground:#FFFFFF;      /* 14.75:1 */
  --secondary:#E8EAE2;   --secondary-foreground:#111A17;
  --muted:#E8EAE2;       --muted-foreground:#59665F;        /* 5.6:1 on card */
  --accent:#1C69D4;      --accent-foreground:#FFFFFF;       /* M blue: links, focus, info (5.22:1) */
  --destructive:#C8102E; --destructive-foreground:#FFFFFF;  /* 5.88:1 */
  --border:#D9D5C8;      --input:#7C877F;                   /* input edge 3.47:1 */
  --ring:#1C69D4;                                           /* 4.42:1 on canvas */
  --success:#1F7A4D; --warning:#9A5B00; --info:#0653B6;
  --sidebar:#F7F7F2; --sidebar-foreground:#111A17;
  --sidebar-primary:#102D25; --sidebar-primary-foreground:#FFFFFF;
  --sidebar-accent:#E1EAE0;  --sidebar-accent-foreground:#111A17;
  --sidebar-border:#D9D5C8;  --sidebar-ring:#1C69D4;
  --shadow-float:0 8px 24px rgb(16 45 37 / .12);            /* evergreen-tinted, not grey */
}
.dark {                                  /* Evergreen Night (proposal, approved by delegation) */
  --background:#0A1310;  --foreground:#EEECE5;
  --card:#0F1C17;        --card-foreground:#EEECE5;
  --popover:#14261F;     --popover-foreground:#EEECE5;
  --primary:#B7C9AD;     --primary-foreground:#0A1310;      /* Sage button, 10.75:1 (Evergreen is ~1.3:1 on dark) */
  --secondary:#14261F;   --secondary-foreground:#EEECE5;
  --muted:#14261F;       --muted-foreground:#9AA89F;        /* 7.07:1 */
  --accent:#81C4FF;      --accent-foreground:#0A1310;       /* 10.12:1 */
  --destructive:#FF8089; --destructive-foreground:#0A1310;  /* 7.81:1 */
  --border:rgb(183 201 173 / .14); --input:#6B7A72;         /* input edge 3.88:1 */
  --ring:#81C4FF;
  --success:#5BD08F; --warning:#F2B24C; --info:#81C4FF;
  --sidebar:#0F1C17; --sidebar-foreground:#EEECE5;
  --sidebar-primary:#B7C9AD; --sidebar-primary-foreground:#0A1310;
  --sidebar-accent:#1B3A31;  --sidebar-accent-foreground:#EEECE5;
  --sidebar-border:rgb(183 201 173 / .14); --sidebar-ring:#81C4FF;
  --shadow-float:0 8px 24px rgb(0 0 0 / .40);
}
@theme {  /* add next to the existing --color-* lines */
  --color-success:var(--success); --color-warning:var(--warning); --color-info:var(--info);
  --radius-sm:8px; --radius-md:12px; --radius-lg:20px; --radius-xl:24px; --radius-2xl:28px;
  /* --radius-pill and --color-motorsport-* stay as they are */
}
```
Rules: **never use `--color-motorsport-red` / `#E22718` as text** (4.2:1 fails); danger text uses `--destructive`. `.dark` borders are low-contrast hairlines on purpose; **input edges use `--input` (>= 3:1)**. Re-run contrast if any value changes.

### 4.3 Radius and depth
Radii (bigger than today; Fernly/brand feel): inputs/selects `md` 12, cards/tables `lg` 20, dialogs `xl` 24, shell panels `2xl` 28, **buttons and chips pill**. Depth order: canvas -> panel -> card -> interactive row -> floating (sticky header, popovers) -> dialog/drawer. Static cards: hairline or `shadow-xs`, **never a big shadow**. Floating layers: `--shadow-float`.

### 4.4 Hard-coded values to replace with tokens (found in the build/CSS)
| Where | Now | Replace with |
|---|---|---|
| `components/ui/button.tsx` primary | `bg-[#245DCF] hover:bg-[#1E4FB5] active:bg-[#183F91]` | `bg-primary text-primary-foreground hover:bg-primary/90 active:bg-primary/80`; base `rounded-md` -> `rounded-pill` |
| `components/ui/input.tsx` / Card dark fills | `dark:bg-[#16181D]`, `dark:bg-[#191C21]` | `bg-card` / `bg-secondary` |
| `components/ui/card.tsx` | `rounded-[12px]`, `bg-[#0066B1]/[#1C69D4]/[#E22718]` | `rounded-lg`, `bg-motorsport-light/dark/red` |
| `BrandMark.tsx`, `RouteLoader.tsx` | same three hexes | `bg-motorsport-*` (logo artwork otherwise untouched) |
| `components/ui/checkbox.tsx` | checked `bg-accent` (blue) | `data-checked:bg-primary data-checked:text-primary-foreground` (brand check) |
| `dialog.tsx`, `sheet.tsx`, `sidebar.tsx` | `rounded-[14px]` etc. | `rounded-xl` / token radii |
| Badge / chips in pages | `emerald-500`, `amber-500`, `sky-500`, `purple-500` raw palette | `success` / `warning` / `info` tokens (`bg-success/10 text-success border-success/20`); drop `purple` |
| `::selection` | `bg-accent text-accent-foreground` | keep (both themes pass) |

---

## 5. App shell (admin)

**5.1 Make the shell persistent (the smoothness fix).** Today each page renders `<AdminLayout>` and each route has its own Suspense. Change to **one parent route**, same URLs:
```tsx
// App.tsx (route nesting only; paths unchanged)
{ path: '/admin', element: <AdminRoute><AdminLayout/></AdminRoute>,   // AdminLayout renders <Suspense fallback={<ContentSkeleton/>}><Outlet/></Suspense>
  children: [
    { index: true,        element: <AdminDashboard/> },
    { path: 'clients',    element: <AdminClients/> },
    { path: 'logs',       element: <AdminLogs/> },
    { path: 'security',   element: <AdminSecurity/> },
  ] },
// /admin/login and /admin/two-factor stay outside (unguarded), exactly as now
```
`AdminLayout` takes `<Outlet/>` instead of `children`; remove the `<AdminLayout>` wrapper lines from the 4 pages (a deletion). Keep `AdminRoute`'s redirects, `ErrorBoundary`, `useSession` logic **verbatim**.

**5.2 Look (shadcn already supports it).** `<Sidebar variant="inset">` + `<SidebarInset>` give the Fernly "floating panel on a canvas" with existing classes (`peer-data-[variant=inset]:m-2 rounded-xl shadow-sm`). Spec: canvas `--background`; sidebar panel `--sidebar` r=28; content paper `--card` r=28; sidebar width 264; header = **solid**, sticky, becomes glass only when content scrolls under it (7).
- Sidebar items: height 44, icon 20, label 14/20 500; hover `bg-sidebar-accent/60`; **active = `bg-sidebar-accent` + 4x20 `bg-primary` indicator** (replace today's `border-l-[3px]` + `pl-[9px]` hack). Group label "Menu" (sentence case) if you add groups.
- Header: breadcrumb (keep), theme toggle (keep, 5.4), user name/email, sign-out (keep). **No bell/mail.**
- **Security posture card** at sidebar bottom (7.1).

**5.3 Skeleton instead of splash.** `RouteLoader` stays only for `AdminRoute`'s first `isPending`. Inside the shell, `Suspense` fallback = `ContentSkeleton` built from existing `components/ui/skeleton.tsx`, **shown after 150 ms** (avoid flash), shape-matched to the page (title + 4 KPI blocks / table rows).

**5.4 Theme toggle.** Keep the control and `startViewTransition`, but: duration 1 s -> **<= 400 ms** (`::view-transition-new(root)` animation), and **skip the transition when `prefers-reduced-motion: reduce`** (call `switchTheme()` directly).

---

## 6. Motion (CSS only, no new library: `rules.md` + animation skill)
Ceiling: level 2 (responsive). Existing `tw-animate-css` + `transition-colors` cover almost everything. **No `transition-all`** (found in the build CSS: replace with `transition-colors`/`transition-transform` where touched).

```css
:root{ --ease-standard:cubic-bezier(.2,0,0,1); --ease-enter:cubic-bezier(.16,1,.3,1); --ease-exit:cubic-bezier(.4,0,1,1); }
@media (prefers-reduced-motion: reduce){
  *,*::before,*::after{ animation-duration:.01ms !important; animation-iteration-count:1 !important;
                        transition-duration:.01ms !important; scroll-behavior:auto !important; }
  ::view-transition-group(*),::view-transition-old(*),::view-transition-new(*){ animation:none !important; }
}
```
| Element | Motion | Duration |
|---|---|---|
| Button / link / icon button | color + 1px lift on hover; `scale(.99)` pressed | 140 / 90 ms |
| Sidebar active indicator | CSS transition on the 4x20 bar's `transform` between items (single element positioned by active index) or simple fade swap; no library | <= 220 ms |
| Route content | enter only: opacity 0->1, `translateY(4px)->0` (`animate-in fade-in slide-in-from-bottom-1`) | 200 ms |
| Skeleton | after 150 ms delay; `animate-pulse`; disappears instantly on data | n/a |
| Dialog / Sheet / Popover / Tooltip | already `data-open` animations; set 170-220 ms enter, 120-150 ms exit | tw-animate |
| Toast (sonner) | library default | n/a |
| Copy-ID button | icon swap copy -> check, revert after 1.6 s | 160 ms |
| Input error | border-color 120 ms; reserve message height (no layout shift) | 120 ms |
| OTP wrong code | one 4px horizontal shake (non-essential; none under reduced motion) | 240 ms |
| Sign-in success | optional: the 3 `motorsport` bars sweep once on `AuthCallback` (already the transit page) | <= 420 ms, non-blocking |
| `animate-m-line-*` (RouteLoader) | **iteration count 1.7 -> 1**, 1 s -> 600 ms | |
Static KPI cards **do not** hover-lift. Never animate `blur()` or layout properties. Realtime/live-tail: not in scope.

---

## 7. BMW touch and glass (budgets)

### 7.1 BMW touch: max 3 elements per screen
| Element | Where | Job |
|---|---|---|
| Flat 3-segment stripe (`accent="motorsport"` on `Card`, already exists) | **one** hero card per page; Consent card; sign-in success sweep | emphasis / confirmation |
| M colors as meaning: blue = interactive/info/focus (`--accent`), red = destructive/failure (`--destructive` for text, motorsport-red for graphics only), Evergreen = brand/safe | everywhere via tokens | meaning |
| Brand lockup (`BrandMark`) | sidebar header, auth panel | identity |
| **Security posture card** (evergreen `#102D25` bg, topographic contour SVG <= 3 KB at 6-8% opacity, static) | sidebar bottom while `!session.user.twoFactorEnabled` | actionable nudge replacing Fernly's promo card |
Matte, not glossy: no gradient sheen, no chrome, no motorsport puns in copy. Trademark note: the current slanted `///` + "M" lockup is the BMW M logo language; fine privately, a risk for an agency product (Decision 2). The UI's own stripes are flat and horizontal.

Posture card copy: **"Two-factor is off. This account can change credentials for every application."** + button "Turn on two-factor" -> `/admin/security`. Disappears when `twoFactorEnabled` is true. If the field is absent, **hide the card** (never guess).

### 7.2 Glass (from the Apple-glass guide): functional only
| Surface | Material |
|---|---|
| Sticky admin header while content scrolls beneath | glass (already `bg-background/95 backdrop-blur-md`: tune to the pattern below, small area only) |
| Popovers / selects / tooltips | solid `--popover` (short-lived, readable) |
| Sidebar, cards, tables, forms, login/TOTP/consent cards, dialogs, errors, destructive anything | **solid** |
```css
.glass{ background:var(--card); border-bottom:1px solid var(--border); }                 /* opaque FIRST */
@supports (backdrop-filter: blur(1px)){ .glass{ background:color-mix(in oklab,var(--card) 72%,transparent);
  -webkit-backdrop-filter:blur(16px) saturate(1.15); backdrop-filter:blur(16px) saturate(1.15);} }
@media (prefers-reduced-transparency:reduce),(prefers-contrast:more){ .glass{background:var(--card);backdrop-filter:none;-webkit-backdrop-filter:none;} }
@media (forced-colors:active){ .glass{background:Canvas;backdrop-filter:none;} }
```
No glass on glass, no animated blur, blur only on the header. **Not yet tested on a real iPhone Safari: on the QA list.**

---

## 8. Component change map (existing files only)
| File | Change (styling/markup only) |
|---|---|
| `src/index.css` | tokens (4.2), fonts (3.2), radii, reduced-motion block (6), `animate-m-line-*` 1 iteration, theme-transition <= 400 ms, glass util (7.2) |
| `src/main.tsx` | `defaultTheme="dark"` |
| `index.html` | `<title>M Auth</title>`, `<meta name="theme-color">` (dark `#0A1310`) |
| `components/ui/button.tsx` | tokens instead of hexes, pill radius; sizes: default `h-11`, `sm h-9`; loading = existing disabled + spinner inside fixed width |
| `components/ui/input.tsx` | `h-11 rounded-md bg-card border-input`; focus `ring-2 ring-ring`; error `aria-invalid` styles already present |
| `components/ui/card.tsx` | `rounded-lg`, token stripe, `shadow-xs` |
| `components/ui/badge.tsx` | pill; variants map to success/warning/info/destructive/secondary tokens (sentence case text) |
| `components/ui/table.tsx` | header `text-xs font-medium text-muted-foreground` (no uppercase), row `h-14`, hover `bg-secondary`, `tabular-nums` helper for numeric cols |
| `components/ui/{dialog,sheet,popover,select,tooltip}.tsx` | token radii, solid surfaces, animation durations (6) |
| `components/ui/checkbox.tsx` | checked uses `primary` |
| `components/ui/sidebar.tsx` | no logic change; width via existing `--sidebar-width` (set 264px in `AdminLayout`) |
| `components/app-sidebar.tsx` | active style (5.2), posture card slot |
| `pages/admin/AdminLayout.tsx` | `<Outlet/>`, `variant="inset"`, header glass-on-scroll, skeleton Suspense |
| `components/RouteLoader.tsx` | splash only for first auth check; iteration 1 |
| `components/ThemeToggle.tsx` | reduced-motion guard (5.4) |
| `components/InvalidRequest.tsx`, `pages/NotFound.tsx`, `ErrorBoundary.tsx` | shared error template (9.1), copy fix |
| `BrandMark.tsx` | **logo artwork unchanged**; swappable per Decision 1/2 |

Do not create new abstractions (no design-system package, no motion lib, no chart lib, no command-palette lib).

---

## 9. Pages (mapped to real routes and fields)

### 9.1 Auth pages (all inside `Layout`; logic untouched)
**Shell:** keep the existing two-panel structure of `SignIn.tsx` (brand panel + form). Brand panel = Evergreen `#102D25` in **both** themes, white serif headline (keep current headline copy), static contour SVG, flat stripe, protocol facts. Form panel = `--background`; form card = `--card`, `rounded-xl`, solid, `shadow-xs`. Mobile: brand panel collapses to a 96 px header.

| Route | Spec |
|---|---|
| `/auth` `SignIn` | Tabs sign in / create account (sign-up tab only when existing `signupEnabled`; private app `is_public=false` = **no sign-up**, unchanged). Primary "Sign in", full width, 44 px. Google = secondary outline pill (existing `handleGoogleSignIn`). Show/hide password buttons keep. **Remove the dead "Remember this device" checkbox** (finding 3). Error: existing inline message + toast, restyled (icon + text, `role="alert"`, never color alone). Server error text is shown as returned (API decides wording; see backlog). |
| `/two-factor`, `/admin/two-factor` | Keep the **single** `<Input inputMode="numeric" autoComplete="one-time-code">` (already correct). Style: centered, `font-mono text-2xl tracking-[0.4em]`, no six-box component (YAGNI). Keep existing backup-code mode, `failedAttempts`, timeouts. Wrong code: 4 px shake once. |
| `/forgot-password`, `/reset-password` | Restyle only. Keep the existing success/neutral messaging. |
| `/consent` | `Card accent="motorsport"` (already). Scopes list from existing `scopeDescriptions` with icon + sentence; **Allow (primary) and Deny (secondary) same size**; show only data the page already receives (app/client name, scopes). Consent appears only when the client's `skip_consent` is false (decided by better-auth server-side; UI unchanged). |
| `/callback`, `/signout` | Transit pages: minimal centered brand + skeleton line; no new requests. Optional stripe sweep (6). |
| Errors | One template for `InvalidRequest` (`missing_params`, `invalid_client`, `invalid_redirect`), `NotFound`, `ErrorBoundary`: icon, title, one-sentence cause + next step, primary action. Red = 3 px top stripe + icon + text. **Never echo or follow an unvalidated redirect URI** (current component doesn't; keep). Copy: replace "Telemetry Violation" with the plain title; invalid_redirect message: "The redirect URI doesn't match what is registered for this application." |

### 9.2 Admin Overview (`/admin`)
- Title (serif 34) + subtitle + **manual Refresh** (existing). No auto-refresh.
- KPI row (4 cards, **static, no hover lift**): Applications (`totalClients`; helper "{activeClients} active"), Users (`totalUsers`), Logins 24h (`recentLogins`), **Active sessions** (`activeSessions`, new KPI from an already-returned field). Delete the "Status: Registered/Operational/Enrolled/Recent activity" filler rows. First card keeps `accent="motorsport"` (the one stripe on this page).
- **Recent sign-ins** card from `stats.recentActivity`: IP (mono), user-agent token, relative time with absolute in `title`. Empty state: "No recent sign-ins."
- Protocol and Keys cards: keep content, restyle as label/value lists. They are **static claims hard-coded in the UI** (backlog: source from OIDC discovery).
- Security posture card (7.1) in the sidebar.
- **No charts, no gauge** (no data to support them; 0.6).

### 9.3 Applications (`/admin/clients`)
Existing flows (register, edit, provision admin, revoke) untouched in logic. Restyle:
- Row status = dot + label from `disabled`; chips (max 2 visible, rest in tooltip):
  | Field | Chip |
  |---|---|
  | `disabled` | `Active` (success dot) / `Disabled` (destructive) |
  | `is_dev`/`isDev` | `Development` (warning tint) / `Production` (neutral) |
  | `is_public`/`isPublic` | `Public` / `Private` (neutral outline) |
  | `has_custom_admins`/`hasCustomAdmins` | `Custom admins` (tooltip: this app has its own administrator account) |
- `client_id`: mono, middle-truncated, copy button (icon morph, toast "Client ID copied"). Created: local date + time **with timezone label**.
- Revoke dialog: **already confirms with consequences: keep**. (Typed confirmation = optional hardening, not required.) Danger button label names the action ("Revoke {client_name}").
- Client secret is shown only at creation (store comment in `adminStore.ts`): keep the existing one-time display; style the secret block mono with Copy.
- Heaviest route (~202 KB gz): lazy-load the three modals (`RegisterAppModal`, `EditAppModal`, `ProvisionAdminModal`) with `lazy()` **only if** measured to cut >= 10 KB gz from this route.

### 9.4 Audit logs (`/admin/logs`)
Real columns only: **Timestamp (local + tz label; UTC in `title`)**, **Subject** (`userEmail`; system actors like "Security Engine" get a gear avatar), **Action** (existing `getActionVariant`/`formatActionLabel`: only failure/revoke-type actions get a semantic tint; the rest neutral), **IP** (mono). Keep client-side filter (action) + 20/page pagination + 30 s refresh (pause when tab hidden). Replace native `<select>` with `ui/select`. Empty: "No events match this filter." **No outcome / app / user-agent columns** (not in API).

### 9.5 Security (`/admin/security`)
Existing TOTP enable/disable/backup-code flow untouched. Restyle; status chip with icon (`Off` warning tint / `On` success tint) read from the existing `isTwoFactorEnabled`. QR stays local (`qrcode.react`, per `rules.md`: never an external QR API).

### 9.6 Admin login (`/admin/login`)
Same card as sign-in; keep error handling for `access_denied` / `access_denied_scoped` query values from `AdminRoute`.

---

## 10. Cross-cutting rules
**Microcopy:** sentence case; plain verbs; buttons name the action; errors say cause + next step; no humor/puns/exclamation marks; no "telemetry/pilot/engine" jargon; timestamps carry a timezone; IDs mono; secrets masked unless freshly created.

**Accessibility (WCAG 2.2 AA):** contrast table in 4.2 (computed); visible `focus-visible` ring (`ring-2 ring-ring`, 2 px offset) in both themes; targets >= 44 px (min 24); semantic `button`/`a`/`table`; `aria-live` for async errors; chips/status never color-only; skip link to `<main>`; one `h1` per page; reduced motion / transparency / contrast / forced-colors honored; password-manager friendly (`autoComplete` already set).

**Responsive:** breakpoints 480/768/1024/1280. Sidebar = shadcn offcanvas (Sheet) < 768 (existing `use-mobile`); tables scroll inside their card (`overflow-x-auto`), never the page; touch targets 44 px; `min-h-dvh` kept; respect safe-area insets on fixed bars.

**Performance rules for every PR:** no new request, no new dependency, no new route-level import of heavy libs; animate `transform`/`opacity` only; `backdrop-filter` only on the header; no unused CSS/fonts; check the route table in 0.5 after each PR and paste before/after numbers in the PR.

---

## 11. Rollout (small PRs, each independently revertible)
| PR | Scope | Files | Exit |
|---|---|---|---|
| **1 Foundation** | tokens, fonts, dark default, radii, reduced-motion, hard-coded hex -> tokens, remove unused deps/imports | `index.css`, `main.tsx`, `index.html`, `ui/{button,input,card,badge,checkbox,dialog,sheet}.tsx`, `BrandMark`/`RouteLoader` hexes, `package.json` | whole app re-themed, **zero logic diff**, gate 0.4 green, bundle table within 5% |
| **2 Shell** | persistent admin layout, inset panels, sidebar active style, header, skeleton, posture card, theme-toggle timing | `App.tsx` (nesting), `AdminLayout`, `app-sidebar`, 4 admin pages (remove wrapper), `ThemeToggle`, `RouteLoader` | navigation never re-mounts sidebar/header; same URLs; HAR identical |
| **3 Auth pages** | brand panel, cards, OTP styling, consent, error template, remove dead checkbox | `SignIn`, `TwoFactor`, `AdminTwoFactor`, `ForgotPassword`, `ResetPassword`, `Consent`, `InvalidRequest`, `NotFound`, `AdminLogin` | OAuth round trip + 2FA + Google verified; private-app isolation unchanged |
| **4 Admin pages** | Overview (+activeSessions, recentActivity), Applications chips, Logs tz/select, Security restyle | `AdminDashboard`, `AdminClients`, `AdminLogs`, `AdminSecurity`, `adminStore.ts` (additive type only) | no new endpoints; empty states instead of fake data |
| **5 Polish** | motion pass, a11y pass, perf pass, optional stripe sweep, docs | styles + docs | Section 14 checklist |

**Agent kickoff prompt (copy into Antigravity / Claude Code):**
> Read `ui-ux.md`, `AGENT.md`, `rules.md`, `boundaries.md`. This is a **UI-only** redesign. Do **PR 1 only**. First record the baseline from 0.4/0.5 (tests, build sizes, screenshots, HAR). Do not touch anything listed under FROZEN (0.3). Smallest correct diff; no new dependencies except the three font packages in 3.2. After the change, report: files changed, bundle-size table before/after, HAR diff result, and anything you were tempted to change but didn't. Stop and ask if you need a frozen file.

---

## 12. Decisions
| # | Topic | Status |
|---|---|---|
| 1 | Wordmark | **SWYRA** ("M Auth by SWYRA"). `BrandMark.tsx` is the single swappable logo component. |
| 2 | BMW mark | Interpreted as: keep the current mark for private/internal use now; redraw before any external/commercial launch. **Tell me if you meant "redraw now"**: it does not block anything. UI stripes are flat/horizontal regardless. |
| 3 | `Custom admins` chip | You said "both" (admin-only + admin-managed). **The code has one field, `has_custom_admins`** (app has its own admin account). No field exists for "admin-only access". The chip is therefore `Custom admins`. If "admin-only" is a real concept, it needs a backend field first. |
| 4 | Default theme | Dark default, light supported (4.1). |
| 5 | Consent | Governed by each client's existing `skip_consent`; UI unchanged in behavior. |
| 6 | Missing backend fields | UI shows only what the API returns; backlog in 0.7. |
| 7 | Brand clearance | Forest Stone sheet is marked "clearance pending"; tokens live in one file (`index.css`), so a later change is one edit. |
| 8 | Dark theme | Evergreen Night with Sage primary (approved by delegation). |
| **9 (open)** | **Fonts: Option A (brand fonts, +38.7 KB) or Option B (keep Geist/Space Grotesk, 0 KB)** | **Your call. Default A.** |

---

## 13. Repo docs to update (per `rules.md` documentation discipline)
1. **Replace `ui-ux.md` with this file.** (Old palette/fonts/"no pill" rules are superseded: 0.2.)
2. **`AGENTS.md`:** add under the Golden Rules a short "UI work" note: *"For any UI change read `ui-ux.md`. UI work is presentation-only: never change API calls, OAuth params, routes, stores or `backend/`. Keep the bundle table in `ui-ux.md` 0.5 within 5%."*
3. **`CHANGELOG.md`:** one entry per PR (1-5).
4. **`memory.md`:** update at the end of each session (rules.md).
5. `DESIGN-cohere.md` stays as a reference analysis only (not normative).
6. `ISSUES.md`/`FIX.MD`: add the 0.7 backend backlog items (fabricated `|| 1` fallbacks, `127.0.0.1` IP fallback, missing failed-login telemetry, dead `remember` option).

---

## 14. QA checklist
**Non-regression:** gate 0.4 complete; OAuth round trip with `test/react-express-app` and `test/next-app`; private-app login isolation; 2FA enroll/verify/backup; admin scoped-role redirects (`access_denied_scoped`) still work; revoke still invalidates.
**Visual:** every page/state in light and dark; no leftover blue primary; no all-caps tracked labels; <= 3 BMW elements per screen; static KPI cards don't lift.
**Interaction:** all states (default/hover/focus-visible/pressed/disabled/loading/error/success); shell never re-mounts on admin navigation; skeleton appears only after 150 ms.
**Accessibility:** keyboard-only run (sign in -> 2FA -> create app -> revoke -> logs filter); screen-reader pass on login + 2FA + table + dialog; reduced motion / transparency / contrast / forced colors; 200% zoom.
**Performance:** re-measure the 0.5 table (before/after in PR); Slow 4G + 4x CPU run; **one real low-end Android**; zero third-party requests on auth pages; **real iPhone Safari check for the glass header (not yet done)**; record what was *not* tested.

*If any rule here conflicts with the product's security or accessibility behavior, security and accessibility win.*
