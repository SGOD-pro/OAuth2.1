# 0008 verification plan and evidence ledger

**Status:** Planned. No V2 runtime scenario has been executed by this documentation change.
Baseline security evidence is separate: [CI at 66738b0](https://github.com/SGOD-pro/OAuth2.1/actions/runs/44947156668). Later report wording correction does not add separate-worker execution evidence.

## Docs-only verification

Record actual commands/results in the documentation PR: relative links/anchors, required canonical contract checks, diagram syntax, requirement-to-slice mapping and docs-only diff. A documentation check cannot mark the runtime matrix below complete.

## Runtime evidence, initially all pending

| Scenario | AC IDs | Required category | Status |
|---|---|---|---|
| Engine transaction rollback and writer inventory | 01-03,16 | Real engine + Mongo replica-set transaction | Pending |
| OTP start/verify/resend/finalize and wrong-code zero writes | 02-04,15 | Real API + disposable DB/mail sink; concurrency workers | Pending |
| New user/profile/key/session and lost response recovery | 03,16 | Real engine finalization + idempotency | Pending |
| Client-policy backfill and open/private matrix | 05-06,14 | Old/new schema and real consumer fixtures | Pending |
| Browser A/B login, tab interleave, expiry/logout, admin purpose | 07-09,21 | Real browser plus separate backend workers | Pending |
| Account-list CORS/CSRF/fixation/context misuse | 08 | Browser and direct HTTP negatives | Pending |
| Genuine user/admin MFA, recovery/promotion/step-up/plugin paths | 10-11 | Real password/TOTP/backup protocol | Pending |
| Dashboard A/B ownership, claims/privacy and admin serializers | 12-14 | Direct API + browser/cache/consumer tests | Pending |
| Mail signed callbacks, late jobs, crash/timeouts, bounce/suppression | 15,18 | Real sink/queue; controlled provider separately | Pending |
| Key backend/AAD/rotation/writers and old plaintext copies | 16 | Real key service and migration inventory | Pending |
| Delete/refresh race, lease recovery, receipts and snapshot restore | 17 | Separate workers + key service + pre-deletion restore | Pending |
| Fleet quotas, failover/outage, edge and cost saturation | 18 | Multi-process + staging load under explicit limits | Pending |
| Device spoof/missing/VPN/false-positive step-up | 19 | Controlled browser/risk fixtures | Pending |
| Cache invalidation and optional filter snapshots/fallback | 20 | Real cache/process tests; filter benchmark if selected | Pending |
| Page accessibility/expired/error/denied states | 21 | Browser keyboard/accessibility and backend outcomes | Pending |
| Fresh self-host install, upgrade, recovery/disclosure/provenance | 22 | Release drill and independent review | Pending |

## Required record format

For each implementing slice record commit SHA, source diff scope, worktree status, exact commands, dependency/service versions, case IDs, pass/fail/blocked/skipped counts, log references and limitations. Label mocks and two app instances in one process honestly. Real multi-worker claims require distinct processes/connections with deterministic barriers. Mail provider acceptance is not delivery; a scheduled key deletion is not destruction; notification is not consumer erasure.

## Gate behavior

A failed security invariant blocks affected rollout; do not skip/relax it for a green count. An unavailable dependency is blocked, not pass. Docs edits do not authorize deployment, destructive live tests or production data access. Proofs, keys, PII and tokens never appear in evidence artifacts.
