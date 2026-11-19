# V2 delivery phases

**Status:** Planned. Updated 2026-11-19. No V2 runtime work is complete.
**Specification:** [0008](specs/0008-multi-account-identity-platform/index.md).
**Baseline security review:** [2026-11-19](reviews/2026-11-19-identity-platform-baseline.md).

Build one bounded vertical slice at a time. Each row requires implementation, targeted
adversarial tests, compatibility evidence, review, and documentation before completion.
Do not infer completion from this plan or existing green suite summaries.

| Order | Slice | Dependencies | Exit evidence |
|---|---|---|---|
| 0 | Current account/token eligibility hardening | Baseline review | Real-route code/refresh/UserInfo/introspection denial for missing, banned, disabled, unverified, deleting accounts; revocation race and client isolation tests |
| 1 | Split client type from open/private access | 0 | Audited backfill, explicit ambiguity report, compatible old clients; open access without membership; private negative tests; no unintended secret/callback changes |
| 2 | Verified enrollment and usernames | 0, 1 | No account/credential/session writes on invalid OTP; atomic finalization races; delivery failure and abuse budgets; verified admin invitation claiming |
| 3 | Mandatory administrative TOTP | 0, 2 | Setup-only sessions for unenrolled admins; every admin API and plugin path protected; recovery/reset/promotion bypass tests |
| 4 | Multiple account sessions and chooser | 0 to 3 | Two real browser accounts, independent logout/expiry, multi-tab subject binding, OIDC prompt/max_age tests, admin-purpose isolation |
| 5 | Privacy dashboard and API projections | 2 to 4 | Own-account checks, consent/scope controls, no full emails in ordinary admin API/search/export/logs; exports and recent-auth checks |
| 6 | Account key service and encrypted data | 0, 2, 5; key-service decision | Cost/latency and engine compatibility proof; nonce/AAD/key rotation tests; complete field inventory and protected write coverage |
| 7 | Deletion, cleanup, and backup restore | 0, 4 to 6 | Idempotent deletion jobs; immediate online denial; refresh/delete races; independently witnessed key destruction; pre-deletion snapshot restore denies resurrection |
| 8 | Distributed abuse and availability validation | Incrementally from 0, before open rollout | OTP/mail/IP/account/client quotas, multi-process failure tests, edge/load budgets, queue deadlines; no fingerprint-only controls |
| 9 | Open-source release readiness | 0 to 8 | License/provenance, vulnerability reporting, clean secret history response, pinned dependencies/SBOM, self-host guide, release checks and external security review |

## First implementation slice

Phase 0 is the next runtime task. Preserve the current public/private policy while
adding a shared account eligibility guard to minting and every token validation path.
Use real disposable MongoDB integration tests and account-state transitions. Prove
both plugin-active and custom JWT introspection branches obey the guard. Do not add
OTP, chooser, encryption, or membership-policy migration in the same implementation.

Initially record unverified-account compatibility explicitly. If rejecting existing
unverified accounts affects deployments, require an audited re-verification rollout
rather than silently turning a stored false flag into verified status. The new public
identity release cannot waive verified enrollment.

## Migration and rollback gates

1. Inventory real schema, collection names, plugin-managed writes, existing account
   verification provenance, legacy role exceptions, and consumer token expectations.
2. Use additive versioned schemas, dry-run counts, duplicate/collision reports, bounded
   backfills and checkpoints. Stop on ambiguous identities; never auto-promote roles.
3. Keep existing client IDs and endpoints stable. Separate ordinary open-app connection
   history from private membership and app-admin authority before removing a gate.
4. Test the previous client contract and new contract together. Existing sessions may
   be reauthenticated rather than silently imported with elevated assurance.
5. Encrypt only after adapter/plugin compatibility and key-service recovery boundaries
   are proven. Inventory every plaintext copy before making erasure claims.
6. Roll back using compatible readers and feature disablement. Never undo a tombstone,
   revive a token family, or restore a destroyed account key. Reapply deletion ledger
   before any restored system becomes reachable.

## Release acceptance matrix

| Category | Required scenarios |
|---|---|
| Enrollment | Wrong/expired/replayed OTP, resend, mailbox flooding, duplicate email/username, concurrent finalization, queued delivery failure, no secret logging |
| Accounts | Add two accounts, remove one, expire one, revoke remotely, chooser CSRF/fixation/ID guessing, tab A vs tab B selection races |
| OAuth/OIDC | PKCE/state/nonce binding, all prompt values and invalid combinations, max_age, consent expansion/revocation, code replay, refresh replay, incorrect audience/client |
| Administration | App vs platform isolation, mandatory MFA enrollment and freshness, social-login bypass, bearer/cookie bypass, backup-code replay, promotion/demotion, plugin admin routes |
| Privacy | Owner vs another subject, chosen username vs email label, server-side projections, scope filtering, exports, admin logs, no account-list CORS/cache leakage |
| Data lifecycle | Encryption migration, old/new key versions, wrong AAD, nonce misuse prevention, key outage, decrypt after tombstone, key-cache purge, delayed destruction, recovery from worker crash |
| Deletion | Concurrent refresh/code exchange, lost worker, partial key failure, repeated requests, unrelated account survival, username/email reuse, third-party residual data disclosure |
| Resilience | Real Mongo replica-set transactions, real disposable Redis, cold starts, multiple processes, quota-store loss, queue backlog, mail cost ceiling, timeout and load shedding |
| Release | Dependency and license audit, vulnerability reporting route, fresh secrets, clean install, migrations, recovery drills, no unsupported security/conformance claims |

Bloom filters are deferred until measurements justify them. Require an explicit design
for sizing, false-positive rate, rebuild/versioning, saturation, invalidation, and
safe storage fallback. A filter must never override an authorization result.

## Evidence format

Each verification records commit SHA, clean/dirty worktree, exact commands, infrastructure
versions, observed counts, failures, skipped and blocked scenarios. Separate source
inspection, mocked function probes, real service integration, browser tests, and live
deployment evidence. Docs-only changes run documentation/integration/link checks;
they do not imply all security suites ran.
