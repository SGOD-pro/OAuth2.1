# 0008 rationale and rejected shortcuts

**Status:** Design decisions for review. Updated 2026-11-22.

| Decision | Reason | Rejected shortcut and consequence |
|---|---|---|
| Keep Better Auth and add narrow adapters | One credential/protocol authority; existing hardening preserved | Duplicate auth framework creates competing sessions, recovery and token policy |
| Verify mailbox before engine identity creation | Wrong code must leave zero durable accounts | Post-signup verification violates required behavior even if login is blocked |
| Distinct emails, independent subjects | Multiple accounts without implicit identity linking | Shared fingerprint/local part cannot establish common ownership |
| Chosen username separate from sub | Useful label/login alias without breaking consumers | Username/email change as subject would orphan business data or enable reassignment |
| Three client dimensions | Open access is different from secret custody and callback environment | isPublic used for all three removes secrets/private boundaries incorrectly |
| Explicit per-transaction and per-tab contexts | Ambient account switch is unsafe under concurrent tabs | Set-active cookie followed by later engine call can issue for the wrong subject |
| Mandatory admin TOTP, optional user TOTP | Preserve hardening and extend recovery/promotion assurance | Email OTP or remembered device alone is not administrative MFA |
| Server-side privacy projections | Admin UI cannot receive full PII then merely hide it | Browser caches/log exports leak hidden fields |
| Per-account AEAD plus independent key custody | Narrow encrypted data and meaningful deletion | Delete a wrapped-key row while its backup and shared KEK survive is recoverable |
| Immediate denial then async cleanup | Safe token/authority cutoff without huge synchronous cascade | Destroy key alone does not revoke sessions/credentials or clean identifying indexes |
| Edge + distributed budgets | Availability/cost control survives workers and rotating attackers | Fingerprint-only DDoS defense is spoofable and arrives after traffic cost |
| Optional measured Bloom/XOR | Useful for selected snapshots when an exact-store baseline justifies it | Approximate membership is not identity, uniqueness, revocation or encryption |
| Explainable risk rules first | Debuggable false positives and no training data dependency | Unvalidated ML threat score adds opaque denial without evidence |
| Separate source/runtime/evidence status | Honest planning and reproducible release | Green docs or old CI is not proof of new runtime, cloud keys or delivery |

References and exact contracts are in [the architecture](../../ARCHITECTURE.md) and its owned documents. Revisit a decision only with a concrete incompatibility, measurement or security defect, and update the affected acceptance criteria without weakening the user goal.
