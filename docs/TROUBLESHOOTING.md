# Troubleshooting and error contract

**Authority:** Current diagnostic guide plus planned V2 errors. Updated 2026-11-22.
V2 identity routes/pages do not exist just because they are documented. First record deployed source SHA, schema version and enabled slice. See [PHASES.md](PHASES.md) and [CONFIGURATION.md](CONFIGURATION.md).

## 1. Protocol errors, existing contract

| Error | HTTP/redirect behavior | Check |
|---|---|---|
| `invalid_request` | 400 or error redirect only to a validated callback | PKCE/state/redirect/body format and prompt combinations |
| `invalid_client` | 400/401 per client authentication method | Registered client, enabled status, credentials/method; never reveal secret |
| `unauthorized_client` | Protocol denial | Allowed grant/type/client policy, dynamic registration disabled |
| `access_denied` | Validated callback error or controlled 403 | Consent refusal, private membership, disabled/ineligible account |
| `invalid_grant` | 400/401 in current implementation; V2 protocol tests pin exact cases | Expired/replayed code/refresh, verifier mismatch, revocation fence |
| `invalid_token` | 401, Bearer error where applicable | Signature/issuer/audience/expiry/account/family state |
| `too_many_requests` | 429 plus Retry-After | IP/target/global budget or sensitive quota-store outage |
| `registration_disabled` | Current controlled 403 | Private-context legacy signup; V2 has separate verified enrollment |

An unknown/unregistered redirect URI must never receive a redirect containing error or code. Show the IdP error page. Errors never include tokens, mailbox, stack traces, database queries or key/provider internals.

## 2. Administrative codes to preserve

`ERR_GATEWAY_FORBIDDEN`, `ERR_SUPER_ADMIN_REQUIRED`, `ERR_CROSS_TENANT_FORBIDDEN`, `ERR_ROLE_FORBIDDEN`, `ERR_IDENTITY_CONFLICT`, `ERR_AUDIENCE_FORBIDDEN`, `ERR_PASSWORD_CHANGE_REQUIRED`, `ERR_MFA_REQUIRED` and `ERR_MFA_STEP_UP_REQUIRED` remain meaningful boundaries. A 403 before an admin action can be correct; do not change an expected successful integration fixture to 403 to make a suite pass.

- Password success alone is not an admin session. Complete real enrollment and TOTP challenge; setup-only contexts cannot read dashboard data.
- Confirm account role/assignment, token audience and purpose. A super-admin platform token cannot enter consumer admin routes.
- Do not modify emailVerified/MFA flags directly to repair login. Use verified enrollment/recovery and supported migrations.

## 3. Proposed V2 UI API codes

These codes are target contracts, not present runtime promises. They appear only in same-origin identity APIs, not as unregistered OAuth error types. OIDC uses its own standard errors.

| Proposed code | Status | Safe client action |
|---|---|---|
| `ERR_VERIFICATION_INVALID` | 400 | Invalid/expired generic code feedback; no account created |
| `ERR_VERIFICATION_EXHAUSTED` | 429 | Stop guessing; respect Retry-After/restart budget |
| `ERR_REGISTRATION_EXPIRED` | 410 | Restart budgeted intent; discard stale proof/password form |
| `ERR_USERNAME_UNAVAILABLE` | 409 | Ask verified intent owner for another normalized username |
| `ERR_DELIVERY_UNAVAILABLE` | 503 | Bounded user retry; do not claim delivered or create account |
| `ERR_CONTEXT_EXPIRED` | 401 | Rechoose/reauthenticate account; do not substitute another session |
| `ERR_SELECTION_STALE` | 409 | Reload transaction-bound chooser; no browser-global fallback |
| `ERR_ACCOUNT_INELIGIBLE` | 403 | Show owner-safe denial; no account existence enumeration |
| `ERR_RECENT_AUTH_REQUIRED` | 403 | Reauthenticate same subject for bound action |
| `ERR_KEY_UNAVAILABLE` | 503 | Protected data unavailable; no plaintext fallback |
| `ERR_DELETION_PENDING` | 409 | Read narrow job status, never reactivate account |
| `ERR_SCOPE_NOT_GRANTED` | 403 | Respect refusal/missing optional fields; re-consent only explicitly |

Public registration start/reset responses remain generic even for existing/suppressed accounts. A detailed internal reason cannot become a mailbox-enumeration response.

## 4. Symptom-to-owner map

| Symptom | Likely boundary | Correct action |
|---|---|---|
| `/account` rejects missing OAuth params | Layout treats all identity pages as consumer login | Implement standalone route classification in P3/P5, never invent callback |
| Wrong OTP still creates user | Old engine signup called before proof | Stop rollout; close signup/provisioning bypass and finalization transaction |
| Newest email code fails | Resend generation/late queue message or expiry | Inspect generation/job deadline without logging code; only current code works |
| 'Sent' but no mailbox message | Accepted job versus provider delivery/bounce | Inspect queue/provider/suppression metrics, DNS and sender status |
| Two tabs issue same account | Ambient active cookie/global frontend state used | Bind explicit selected session to each transaction/context; deterministic browser repro |
| Logout A logs out B | Global engine signout/session-set replacement | Implement account-scoped operation and preserve other entries |
| Choosing valid account asks password | Expiry, prompt=login/max_age, required assurance or risk | Show correct reason; chooser presence alone is not authority |
| Open-app user denied without membership | Legacy access check still authoritative | Audit policy migration at authorize/exchange/refresh/online validation; retain private tests |
| Private app opens for any platform account | isPublic/clientType confusion or missing membership check | Disable rollout; restore explicit accessPolicy guard |
| Admin sees full email despite masked UI | API/log/export serialization leak | Fix server projection; remove leaked fields from caches/log pipelines |
| Deleted user works after restore | Ledger/key state not replayed before traffic | Quarantine, replay denial, reconcile keys/jobs before reopening |
| Deleted user token works offline | Offline JWT or consumer-local session lifetime | Online introspection/short local sessions; no false immediate-erasure promise |
| Delete remains pending | Key provider delay/failed replica/worker lease | Reconcile receipts/inventory; retry forward only |
| 'Unknown device' on normal login | Cleared cookie/VPN/browser update/coarse signal change | Password/TOTP as needed; no fingerprint-only ban |
| Auth 429 during quota-store failure | Intended fail-closed behavior | Restore stores and admission capacity; never toggle local auth fallback |
| Filter says absent but DB says present | Stale snapshot/false result misuse | Database uniqueness wins; filter bypasses disabled |

## 5. Safe diagnostics

Collect request ID, deployed/schema/policy versions, endpoint category, HTTP/code, pseudonymous owner/client/session refs and worker/job category. Do not collect request cookies, Authorization headers, OTP/proof/reset values, full emails, TOTP seeds, DEKs or exported data in issue reports.

Run existing commands at the relevant runtime SHA: `npm run security:docs-check`, `npm run security:integration-check`, affected suites and full security tests. A docs linter cannot prove service security; a function mock cannot prove real mail delivery or multi-process behavior. Check actual CI job logs instead of copied agent summaries.

For future slices use synthetic disposable fixtures and explicit deterministic barriers. Never 'fix' a production user's state by reusing a deleted ID/key, marking email verified, disabling MFA or restoring revoked token records.
