# 0008. Verified multi-account identity platform

**Status:** Proposed, documentation-only. Updated 2026-11-22.
**Baseline:** main `161ad99`; integrate security PR #2 reviewed at `66738b0` plus report correction `0a5727e` before runtime implementation.
**Scope:** Full V2 product/architecture plan, delivered as bounded vertical slices. No runtime, deployment or data migration in this change.

## Problem

The current single ambient browser session and app-coupled registration do not satisfy independent multi-account login. Verification after identity creation does not satisfy zero-account-on-invalid-OTP. A user needs an own-account dashboard, meaningful privacy, safe enrollment, scoped consumer access and a deletion lifecycle that avoids large synchronous cascades without false erasure claims.

## Target and boundaries

A person may own multiple accounts with distinct verified mailboxes. Each account has a stable subject, chosen username, independent credentials/session/assurance and data keys. A browser chooser can reuse valid sessions for a registered consumer without another password when policy allows. Open apps need no ordinary member list; private membership, registered clients, consent, client authentication and app/platform admin isolation remain.

Keep the installed credential/OAuth engine. Preserve issuer, subject IDs and existing protocol endpoints. New identity APIs are IdP-only. Do not add dynamic public client registration, a second credential system, fingerprint-based authentication, custom crypto or claims of Google/NIST/conformance equivalence.

## Canonical design documents

[Architecture](../../ARCHITECTURE.md), [flows and API contracts](../../AUTHENTICATION_FLOWS.md), [session model](../../SESSION_MODEL.md), [pages](../../USER_EXPERIENCE.md), [mail](../../MAIL_SERVICE.md), [security](../../SECURITY.md), [abuse/caches/filters](../../ABUSE_DEFENSE.md), [data lifecycle](../../DATA_LIFECYCLE.md), [implementation map](../../IMPLEMENTATION_MAP.md), [phases](../../PHASES.md), [integration](../../INTEGRATION.md), [configuration](../../CONFIGURATION.md), [deployment](../../DEPLOYMENT.md) and [diagnostics](../../TROUBLESHOOTING.md).

This spec owns requirement IDs and acceptance, not duplicate API/schema text. [Rationale](rationale.md) records tradeoffs; [verify.md](verify.md) is the prospective evidence ledger.

## Acceptance criteria and traceability

| ID | Requirement and observable acceptance | Slice | Primary contract |
|---|---|---|---|
| AC-01 | Existing hardening preserved across code/refresh/UserInfo/introspection/admin/plugin paths; no token resurrection | Prerequisite, all slices | SECURITY, SESSION_MODEL |
| AC-02 | Wrong/expired/exhausted/replayed/superseded email OTP creates zero user/account/session/membership/consent records | P2 | AUTHENTICATION_FLOWS |
| AC-03 | Concurrent verified completion creates exactly one account; duplicate username/email handled by unique transaction and one-use proof | P0, P2 | DATA_LIFECYCLE |
| AC-04 | New accounts choose normalized unique usernames; same local part across domains never conflates identities | P2 | ARCHITECTURE |
| AC-05 | Public/confidential client type, open/private policy and isDev independent; legacy migration rejects ambiguity | P1 | INTEGRATION, IMPLEMENTATION_MAP |
| AC-06 | Eligible user enters open app without membership; private unassigned user denied through authorize/exchange/refresh/online validation | P1 | AUTHENTICATION_FLOWS |
| AC-07 | Two accounts coexist in browser; selecting A/B in separate tabs yields respective subjects, independent expiry/logout | P3 | SESSION_MODEL |
| AC-08 | Browser account list private to IdP, no raw session-token export; selector/context guessing, CSRF and fixation denied | P3 | SESSION_MODEL, SECURITY |
| AC-09 | prompt/max_age/nonce/consent semantics tested; active chooser presence does not bypass policy or freshness | P3 | AUTHENTICATION_FLOWS, INTEGRATION |
| AC-10 | Both admin roles require completed TOTP and recent MFA, setup-only enrollment, one-use recovery and no plugin/social/bearer bypass | P4 | SECURITY, AUTHENTICATION_FLOWS |
| AC-11 | Ordinary users can enable TOTP; password/contact/reset/recovery flows preserve factor policy and revoke stale authority | P4, P5 | AUTHENTICATION_FLOWS |
| AC-12 | Own dashboard profile/privacy/grants/sessions/export/deletion enforce account context and object ownership | P5, P7 | USER_EXPERIENCE |
| AC-13 | Admin lists/search/log/export omit full email; username/local-part plus opaque ID only; owner and scoped consumer sharing separate | P5 | SECURITY, USER_EXPERIENCE |
| AC-14 | Existing consumer protocol/data APIs remain available with scopes/consent/privacy; no generic decrypt endpoint or direct DB | P1, P5 | INTEGRATION |
| AC-15 | Email transport authenticated/bounded, code delivery never creates/verifies account, real send/error/suppression/deadline tests | P2 | MAIL_SERVICE |
| AC-16 | Account PII encrypted through every engine/custom writer under account keys with AAD/version; no shared-key erasure claim | P6 | DATA_LIFECYCLE |
| AC-17 | Deletion commits immediate denial, idempotent forward-only work, final key receipts, residual cleanup and safe pre-deletion restore | P7 | DATA_LIFECYCLE |
| AC-18 | Distributed budgets/edge admission bound auth/mail/hash costs across workers; store outage fails closed for sensitive work | P2, P8 | ABUSE_DEFENSE |
| AC-19 | Device risk uses resettable coarse signals; spoof/missing/VPN drift not sole allow/ban; step-up and owner notification tested | P8 | ABUSE_DEFENSE |
| AC-20 | Cache hits/filter results never bypass authority; optional Bloom/XOR require measured snapshot/fallback semantics | P8 | ABUSE_DEFENSE |
| AC-21 | Pages include expired/denied/loading/retry/accessibility states and standalone account entry; no fake API/security states | P2-P7 | USER_EXPERIENCE |
| AC-22 | Self-host/upgrade, retention, admin recovery, provenance/license/disclosure and release evidence complete | P9 | DEPLOYMENT |

## Build plan

- [ ] Integrate reviewed security baseline, reconcile this docs branch without runtime downgrade.
- [ ] P0: transaction-aware engine creation and request-local session compatibility proof.
- [ ] P1: additive client-policy migration and open access without membership.
- [ ] P2a: mail budgets/outbox, intent/OTP/proof and verification pages.
- [ ] P2b: username/password finalization transaction and all provisioning bypass closure.
- [ ] P3: session registry, transaction/dashboard contexts, chooser and independent logout.
- [ ] P4: verified invitation, MFA lifecycle, step-up and recovery custody.
- [ ] P5: owner dashboard, minimized privacy/claims/admin views and export preparation.
- [ ] P6a: key provider choice, real destruction/restore/cost/latency proof.
- [ ] P6b: protected adapter, blind indexes and bounded plaintext migration.
- [ ] P7: deletion denial/ledger, export/deletion workers and quarantine restore.
- [ ] P8: risk rules, fleet abuse/load/cost evidence and optional measured filters.
- [ ] P9: open-source/public release readiness and independent review.

Exact file-level work and migration behavior: IMPLEMENTATION_MAP. Dependencies/exit gates: PHASES. New scripts/routes enter executable manifests only with implementing code.

## Decisions to ratify in the affected slice

Key backend and per-account economics/backup guarantees; mail provider credentials/domain readiness; deployed quota/concurrency/SLO sizing; existing email verification provenance/collisions; admin offline recovery custody; exact retention/reuse policy; optional consumer deletion-event protocol. These are explicit deployment gates, not excuses to leave basic signup/session semantics unspecified.

## Completion rule

Unchecked means not implemented. A slice is complete only with behavior, migration, UI/API contract, adversarial/compatibility tests, exact-commit evidence and updated docs. No aggregate test count alone closes all criteria. Preserve separate evidence for real services, browser tabs, processes, provider delivery, key destruction and restore.
