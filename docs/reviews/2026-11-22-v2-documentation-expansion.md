# V2 documentation expansion review

**Date:** 2026-11-22. **Scope:** Documentation only on `docs/identity-platform-v2`.
**Prior documentation HEAD:** `ec0c0d8e4b956738f6c7b678f527a532668c9df7`.
**Inspected runtime references:** main `161ad99ca4ba0de88cff1267b33807db61da306c`; reviewed hardening `66738b0198b0fdb1342dec210394ac5e09041a77`; report correction `0a5727e96a24d947a744ee8c865af35fd5c4ccb5`.
This is a documentation consistency/coverage review, not a new runtime security audit or independent reviewer approval.

## Changes

Reworked canonical architecture, security, integration, configuration, deployment, troubleshooting, phases and data lifecycle. Added owned contracts for authentication/API flows, independent browser/account sessions, page/dashboard states, mail service, abuse/device/filter/cache controls and a concrete implementation map. Reconciled specification 0008, rationale, prospective verification ledger, scope and root contributor/README navigation.

The plan now maps 22 acceptance criteria to P0-P9, explains existing versus proposed modules/collections/endpoints/settings, preserves reviewed hardening and identifies real engine integration, key custody, recovery, retention, cost and provider gates. Historical review records remain unchanged. No V2 runtime feature, secret, deployment, migration or future executable route/suite manifest was added.

## Validation performed

| Check | Result |
|---|---|
| Documentation consistency script | 6 checks passed, 0 errors |
| Integration contract script | 5 checks passed, 0 violations |
| Relative file links and heading anchors in changed docs | Passed |
| Mermaid parse | 10 diagrams passed using Mermaid 11.17.2 with jsdom 31.0.1 |
| Whitespace and docs-only source boundary | Passed |
| Requirement/slice/page/data/security consistency inspection | Completed; unresolved deployment decisions remain explicit gates |

The npm wrappers initially could not start the tsx CLI IPC listener (`EPERM`). The exact underlying scripts were then successfully executed without that CLI listener:

```bash
# Working directory: backend
node --import tsx scripts/check-security-doc-consistency.ts
node --import tsx ../scripts/security/check-integration-contract.ts
```

Diagram parsing used a temporary external validation installation, not a repository dependency or runtime change. It validates Mermaid syntax, not visual browser rendering. Link/anchor and docs-boundary inspection were separate read-only checks.

No runtime security/unit/browser/cloud-key/provider/load tests were rerun for this docs-only update. The old CI workflow filters exclude docs-only PR changes; do not call a missing new runtime CI run a pass. Historical exact-commit hardening results are recorded in PHASES, separate from this review.

## Remaining implementation decisions

P0 must prove transactional engine creation and request-local selected-session use. P6 must select and measure real account key custody, including delayed deletion/replicas/backups and supported self-host capabilities. Mail sender/provider readiness, admin recovery custody, deployment quota/SLO values and final retention require implementation-stage evidence. None is marked implemented or silently assumed secure.
