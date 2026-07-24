# Security Assessment Report — SWYRA OAuth 2.1 / Centralized Auth

Scope: Static review of /mnt/d/OAuth2.1 (Hono API + React frontend + SAM/Docker)
Method: Anthropic Cybersecurity Skills — OAuth2, JWT, API auth, CORS, open redirect, access control, sensitive data, OWASP API Top 10
Mode: Re-audit after implementation
Date: 2026-07-24 (re-audit #2)

Verdict: The audited application defects are fixed. Public signup policy now covers email and Google, sign-in remains available when signup is disabled, proxy headers are ignored without an explicit trusted-proxy list, and OAuth client URI invariants are enforced on create and update. Email verification remains explicitly disabled until a real mailer is configured; enable `AUTH_EMAIL_VERIFICATION_ENABLED` only with that mailer in place. Remaining items are operational hardening: WAF, admin MFA, CSP, cache TTL, and break-glass administration.

────────────────────────────────────────

## Open findings (fix required)

### High

**M9b — Email verification required in prod without a mailer**  
ID: API-AUTH-006b · Location: `hono/src/utils/auth.ts`  
Email verification is now opt-in via `AUTH_EMAIL_VERIFICATION_ENABLED` because no mailer is configured in this repository. Do not enable it until `sendVerificationEmail` is wired to a real delivery provider.

### Medium

**M10 — Admin promotion via DB script**  
ID: OPS-ADMIN-001 · Location: ops / CONFIG  
Fix: Break-glass only; MFA for admins.

**H4b — No breached-password check / admin MFA**  
ID: API-AUTH-003b · Location: auth policy  
Length+complexity and rate limits are in place; no HIBP/breach list; no MFA for `role=admin`.  
Fix: Optional breach check; MFA for admin role.

### Low / informational

**L2** — Lambda Function URL `AuthType: NONE` — put WAF + rate limits in front.  
**L3** — Frontend `AdminRoute` is UX-only; server `requireAdmin` is the real gate.  
**L4** — Frontend `validateUri` does not reject private IPs (server does in prod) — OK if server remains source of truth.  
**N4b** — Security self-check covers the trusted-proxy edge case and password/redirect helpers; route-level integration coverage remains limited.

────────────────────────────────────────

## Closed in this pass (do not re-open unless regressing)

H2 (trusted IP helper + CIDRs), H4 core (min 12 + complexity + auth rate limits), H5 email and Google signup gates, H7 `safeCallbackURL`, H8 Compose Nginx removal + TLS note, M2 cookie flags, M3 generic 500s, M4 privacy-safe auth logs, M5 JWT PII stripped, M6 provider refresh rotation/reuse detection, M7 short origin cache TTL, M8 strict CSP, N1 atomic window reset, N2/N6 URI invariants, N4 security self-check, M11 admin and reset-password validators mirrored.

────────────────────────────────────────

## Counts

| Severity | Open |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 3 |
| Low / Info | 4 |

────────────────────────────────────────

## Priority order

**P0**
1. Keep public signup disabled unless intentionally enabled
2. Keep `TRUSTED_PROXY_CIDRS` accurate when deploying behind a proxy
3. Wire email verification before enabling `AUTH_EMAIL_VERIFICATION_ENABLED`

**P1**
4. Admin MFA + optional breach check (H4b)
5. WAF in front of Function URL (L2)

**P2**
10. Ops admin break-glass (M10)
11. Add route-level integration tests (N4b)

────────────────────────────────────────

## Verification checklist

1. With `AUTH_PUBLIC_SIGNUP_ENABLED=false`, email **sign-in** works; email **sign-up** fails; Google new-user signup fails
2. With empty `TRUSTED_PROXY_CIDRS`, forged `x-real-ip` alone does not create a unique rate-limit bucket
3. PATCH `/api/admin/clients/:id` with `redirect_uris: []` → 400
4. Strong password (12+ mixed) accepted; `Password1` / 8-char rejected on sign-up and reset
5. Access token JWT has `sub` (+ optional `role`) only — no email/name
6. `callbackURL=https://evil.com` ignored; `/relative` accepted
7. `npx tsx hono/scripts/security-self-check.ts` passes (extend for new cases)
