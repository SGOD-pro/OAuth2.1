# Security Assessment Report — SWYRA OAuth 2.1 / Centralized Auth

Scope: Static review of /mnt/d/OAuth2.1 (Hono API + React frontend + SAM/Docker)
Method: Anthropic Cybersecurity Skills — OAuth2, JWT, API auth, CORS, open redirect, access control, sensitive data, OWASP API Top 10
Mode: Report only — no code was changed
Date: 2026-07-24 (re-audit)

Verdict: Critical CORS/redirect/DCR/mass-assignment gaps from the prior pass are closed in the working tree. Remaining work before production: spoofable admin rate-limit IP, weak/open password & signup, missing Compose TLS, JWT PII, cookie hardening, and several medium operational gaps.

────────────────────────────────────────

## Open findings (fix required)

### High

**H2 — Admin rate limit trusts client-controlled IP headers**  
ID: API-AUTH-001 · Location: `hono/src/middleware/rate-limit.ts`  
Uses raw `x-forwarded-for` / `x-real-ip`. Attackers can rotate forged IPs and bypass the 30 req/min admin limit.  
Fix: Trust forwarding headers only from a known proxy; prefer platform source IP; if using XFF, take the rightmost trusted hop.

**H4 — Weak password policy**  
ID: API-AUTH-003 · Location: `hono/src/utils/auth.ts` + sign-up/reset UI  
Better Auth default `minPasswordLength: 8`; UI `minLength={8}`; no complexity, breach check, or lockout.  
Fix: Server-side policy (length ≥12–14 + complexity or breached-password check), rate limits on sign-in/sign-up/reset, lockout/backoff, MFA for admins.

**H5 — Open self-registration on a centralized IdP**  
ID: API-AUTH-004 · Location: Sign-up UI + `emailAndPassword.enabled: true`  
Attackers can create accounts and probe OAuth/consent paths.  
Fix: Invite-only or disable public sign-up in prod; restrict by email domain if needed.

**H7 — Post-login `callbackURL` from query string (residual)**  
ID: WEB-REDIR-001 · Location: `frontend/pages/SignIn.tsx`  
UI still passes raw `searchParams.get('callbackURL')`. Better Auth `trustedOrigins` mitigates absolute evil URLs; defense-in-depth on the client is missing.  
Fix: Pass only relative paths or an exact allowlist before calling Better Auth.

**H8 — Missing TLS / Nginx path in Compose**  
ID: OPS-TLS-001 · Location: `docker-compose.yml`  
Mounts `./nginx/...` but `nginx/` does not exist. Easy misdeploy without TLS.  
Fix: Add real Nginx/Caddy TLS config, or remove Compose Nginx and document CloudFront/API Gateway as the only TLS edge.

### Medium

**M2 — Session / auth CSRF cookie flags not explicit**  
ID: API-AUTH-005 · Location: `hono/src/utils/auth.ts`  
Admin CSRF is present; Better Auth session cookie `secure` / `httpOnly` / `sameSite` are not set explicitly (library defaults only).  
Fix: Set `advanced.defaultCookieAttributes` (or equivalent) explicitly per env.

**M3 — Verbose errors leak internals**  
ID: API-ERR-001 · Location: `hono/src/routes/admin.ts` (`/stats`, `/logs`)  
500 bodies include `String(error)`.  
Fix: Generic client error; log details server-side only.

**M4 — Auth handler logs IP / UA / path**  
ID: API-LOG-001 · Location: `hono/src/routes/auth.ts`  
Unstructured request logging near the auth handler.  
Fix: Structured audit log; never log tokens, codes, or secrets.

**M5 — JWT access-token payload includes email PII**  
ID: API-JWT-001 · Location: `hono/src/utils/auth.ts` `definePayload`  
Emits `email` and `name` in access tokens.  
Fix: Minimal claims (`sub`, optional `role`); put profile in UserInfo.

**M6 — Refresh token TTL 30 days; rotation/reuse not configured**  
ID: API-TOKEN-001 · Location: `hono/src/utils/auth.ts`  
`refreshTokenExpiresIn: 2592000`; no in-app rotation / reuse detection.  
Fix: Enable refresh rotation + reuse detection; shorten TTL for high-risk deployments.

**M7 — Origin allow cache TTL 5 minutes**  
ID: API-CORS-002 · Location: `hono/src/db/dynamo.ts`  
Cache invalidated on client CRUD, but denied/allowed entries can linger up to 300s otherwise.  
Fix: Shorter TTL or write-through deny on revoke paths (invalidation already present).

**M8 — CSP `style-src 'unsafe-inline'`**  
ID: WEB-CSP-001 · Location: `hono/src/app.ts`  
Fix: Nonces/hashes; tighten `connect-src` to real API/OIDC hosts.

**M9 — No email verification**  
ID: API-AUTH-006 · Location: Better Auth config  
Fix: Require verified email before OAuth consent / sensitive actions.

**M10 — Admin promotion via DB script**  
ID: OPS-ADMIN-001 · Location: ops / CONFIG  
Fix: Break-glass only; MFA for admins; no standing Mongo admin from app host.

**M11 — Frontend URI validation is `startsWith('http')` only**  
ID: WEB-VAL-001 · Location: admin modals  
Fix: Mirror server validator in UI; server remains source of truth.

**N2 — Admin create allows empty redirect/origin lists**  
ID: API-OAUTH-005 · Location: `hono/src/routes/admin.ts` POST `/clients`  
`validateRedirectUris([])` is a no-op; UI requires ≥1 but API does not.  
Fix: Reject create when `redirect_uris.length === 0` (and optionally require ≥1 `allowed_origins`).

### Low / informational

**N1 — Rate-limit window reset still racy**  
ID: API-AUTH-002b · Location: `hono/src/db/dynamo.ts` `incrementRateLimit`  
After expired window, unconditional `putRateLimit` can under-count under concurrency.  
Fix: Conditional put/update only when `resetAt <= :now`.

**N4 — No regression tests for security helpers**  
ID: QA-SEC-001 · Location: `hono/src/utils/security.ts`  
Fix: Small assert-based self-check or unit tests for prefix bypass, userinfo, private IP, HTTP-in-prod.

**L1** — Health `GET /` is public — fine; do not expose stack/version.  
**L2** — Lambda Function URL `AuthType: NONE` — put WAF + rate limits in front.  
**L3** — Frontend `AdminRoute` is UX-only; server `requireAdmin` is the real gate.

────────────────────────────────────────

## Counts

| Severity | Open |
| --- | --- |
| Critical | 0 |
| High | 5 |
| Medium | 11 |
| Low / Info | 5 |

────────────────────────────────────────

## Priority order

**P0**
1. Fix rate-limit IP trust (H2) and harden window reset (N1)
2. Require non-empty redirect URIs on admin create (N2)
3. Real TLS edge or remove broken Compose Nginx (H8)

**P1**
4. Server password policy + auth rate limits + admin MFA (H4)
5. Disable/gate public sign-up in prod (H5)
6. Explicit session cookie flags (M2 / N3)
7. Refresh-token rotation / reuse detection (M6)
8. Email verification before high-risk actions (M9)
9. Strip email/name from JWT; use UserInfo (M5)
10. Generic 500s + structured auth audit logs (M3, M4)
11. WAF in front of Function URL (L2)

**P2**
12. Client-side `callbackURL` allowlist (H7 residual)
13. Security helper regression tests (N4)
14. Tighten CSP; mirror redirect validation in admin UI (M8, M11)
15. Ops: admin break-glass + MFA (M10)

────────────────────────────────────────

## Verification checklist

1. Forged `X-Forwarded-For` does not bypass admin rate limit
2. Passwords shorter than policy / common breached passwords rejected server-side
3. Public sign-up disabled or invite-only in prod
4. `callbackURL=https://evil.com` rejected; relative allowlisted paths still work
5. Compose/prod edge serves HTTPS (or Nginx mount removed and documented)
6. Admin POST `redirect_uris: []` → 400
7. Access token JWT has no email/name claims
8. `/stats` / `/logs` 500 responses are generic
9. PKCE missing/wrong verifier fails; `response_type=token` rejected
10. Non-admin → `/api/admin/*` → 401/403
