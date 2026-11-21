# Deployment, migration and operating V2

**Status:** Current deployment references plus planned V2 runbook. Updated 2026-11-22.
V2 is not implemented by this docs change. Security PR #2 is integrated into main `828acc5` and this branch; deployment is a separate operation. [PHASES.md](PHASES.md) owns rollout gates; [CONFIGURATION.md](CONFIGURATION.md) distinguishes implemented from proposed variables.

## 1. Deployment profiles

| Component | Reference cloud | Self-host profile |
|---|---|---|
| UI/edge | Vercel SPA/gateway plus explicitly configured edge abuse controls | TLS reverse proxy plus configured edge/DDoS service |
| API | Hono on Node.js 24 or AWS Lambda | Same standalone Node entrypoint behind private/authenticated proxy |
| State | MongoDB replica set/Atlas, isolated database credentials | Replica set with transactions, backups and lease/fence tests |
| Distributed quota/cache | Supported Redis REST deployment | Compatible supported transport; raw TCP needs explicit adapter proof |
| Mail | SES behind durable outbox/worker | Approved SMTP/webhook adapter, same budgets/authentication |
| Account keys | Separate account-scoped key authority, reference KMS | Vault profile only if key destruction/restore capabilities proven |
| Jobs | Narrow worker entrypoints, e.g. queue-triggered compute | Managed worker processes with leases and bounded concurrency |

The cloud choices are reference designs, not new resources created by these docs. Do not claim low-cost/free operation without measuring provider, per-account key and mail costs. Missing self-host crypto-erasure capability must be surfaced as a limitation.

## 2. Existing build and deployment commands

Build from the intended runtime SHA with dependencies from lockfiles:

```bash
npm --prefix backend ci
npm --prefix frontend ci
npm run security:integration-check
npm run security:docs-check
npm --prefix backend run build
npm --prefix backend run build:node
npm --prefix frontend run build:ui
```

Lambda and Node builds currently write the same output path. Build/package each artifact separately; do not deploy the Node bundle as Lambda by running both in one release directory. Existing SAM workflow uses the Lambda artifact and `sam validate --lint`; inspect checked-out scripts before invoking a deployment.

Use explicit approved `LAMBDA_BACKEND_URL` and fresh gateway secret for generated Vercel rewrites. `build:ui` avoids the gateway-generation hook; actual gateway release runs its own generation stage. No secret-bearing generated `vercel.json` or `.env` is tracked. Configure trusted proxy ranges from observed deployment peers, not a guessed broad range.

## 3. Prerequisite security integration

1. Record actual main/security/docs refs, PR checks and deployed SHA. Security PR #2 is merged at main `828acc5`. Security at `66738b0` passed CI; later wording correction `0a5727e` and the merge do not mean deployed. Release through normal authorization, not as a side effect of editing docs.
2. Rotate secrets ever exposed in repository history in actual services. Editing git files does not rotate credentials. Audit dependency lockfiles, licenses and source provenance.
3. Verify real TLS, direct-origin rejection, issuer/discovery/JWKS URLs, callback rules, mandatory admin MFA and current revoke/refresh behavior in staging.
4. Keep V2 docs and runtime work synchronized with the integrated security baseline without overwriting fixes. Keep earlier reports as historical evidence.

## 4. Safe schema and feature rollout

For each P0-P9 slice: pin schema/reader/writer versions; dry-run counts and collisions; apply additive indexes/fields; deploy compatible readers; enable new writers for a controlled cohort; observe and verify; remove old reads only after backfill and rollback window. Exact migration CLIs ship with implementation, not as fictitious commands here.

- Do not enable verified signup before real mail provider, durable cost budgets, proof keys, unique indexes and transaction-aware engine writes are ready.
- Close old/public engine signup, provider auto-create and admin-create bypasses before enabling the new form.
- Migrate client policy without changing registered secrets/callbacks or opening private access.
- Add browser sessions only after cookie/header limits, independent account contexts and real A/B browser tests pass. Reauthenticate unsupported old sessions; never import MFA assurance by guess.
- Enforce privacy at serialization and claims boundaries before exposing dashboard switches. UI hiding alone is not a migration.
- Enable protected writes only after key provider/writer inventory proof. Backfill in bounded batches and measure remaining plaintext copies.
- Enable deletion only when independent ledger, key-destruction receipts, cleanup jobs and quarantine restore are tested.

Cohort rollback disables new feature entry while preserving security, compatible reads, existing account data and denial fences. It cannot revive consumed proofs, revoked grants, deleting accounts or destroyed keys.

## 5. Mail readiness

The integrated security runtime supports these existing settings, independently of future V2 mail configuration:

```env
AUTH_EMAIL_VERIFICATION_ENABLED=true
EMAIL_DELIVERY_WEBHOOK_URL=https://mail-transport.example.com/deliver
AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE=enforce_new
AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER=2026-06-01T00:00:00Z
```

Use your approved authenticated transport, not the example endpoint. Verification enabled without a delivery URL fails closed at startup. Production requires HTTPS/non-loopback. The explicit-zone cutoff is required for `enforce_new`; use `enforce_all` when migration is complete. This transport does not implement V2 proof-before-account signup.


Configure verified sending domain, DKIM/SPF/DMARC alignment, provider production access, bounce/complaint suppression, signed callbacks, queue and worker IAM, send deadline and global cost cap. Use controlled test recipients before public access. Confirm no plaintext OTP/reset payload in application/provider diagnostics.

Exercise worker crash after send, late superseded generation, timeout after provider acceptance, duplicate callback and queue backlog. Alert on oldest usable job age before it exceeds OTP lifetime. Delivery outages suspend new send-dependent actions without disabling independent sign-in policy.

## 6. MFA and bootstrap custody

Bootstrap operator provisions a verified super-admin invitation through a controlled procedure, owner proves mailbox, sets password and enrolls TOTP. Do not distribute temporary passwords by email. Require at least two independently recoverable authorized custodians before normal operations depend on one admin.

Record emergency recovery custody, offline backup location, access approval/audit, notification/delay and mandatory credential/session revocation. No static env switch or email-only endpoint disables admin MFA. Drill lost-factor recovery and last-super-admin responsibility transfer before public release.

## 7. Secret and key rotation

Gateway secret rotation retains existing supported bounded overlap: configure old+new on origin, switch gateway to new, verify, then retire old. JWT signing rotation publishes new public key with overlapping old verification until valid issued tokens expire; never rotate by fallback to opaque/unsigned tokens.

V2 OTP verifier/mail/lookup/account key rotations use separate versions and bounded overlap. Old OTP proofs expire/invalidate; lookup rotation retains global uniqueness; DEK rotation re-encrypts with version/AAD and inventories all old versions. Key destruction is distinct from routine rotation. Never delete a shared signing/client secret as a user's data-erasure action.

## 8. Backup, recovery and deletion restore

Maintain application snapshots separately from append-only denial ledger/destruction receipts. Key-service backup/replica policy must not restore erased account keys. Operator access is least-privilege and audited.

Restore drill: isolate restored network and outbound mail; restore data; replay ledger newer than snapshot; advance denial versions; reconcile key state and sessions/jobs; prove a pre-deletion account cannot log in, refresh or decrypt; ensure unaffected accounts work; then admit traffic. Do not use blind `mongorestore` as production rollback. Pending destruction stays pending after restore; never show erased based on missing local rows alone.

## 9. Operations and incident response

| Signal | Response |
|---|---|
| Distributed auth-budget stores down | Auth/OTP/reset/admin deny; restore stores, investigate load; never toggle local allow fallback |
| OTP/mail spend spike | Enforce global cap, pause new sends, inspect pseudonymous purpose/source metrics; preserve existing sessions |
| Queue backlog/dead letters | Stop expired jobs; recover leases with fences; do not send obsolete codes |
| Suspected account takeover | Revoke affected session/family/account version as warranted, notify owner safely, audited recovery |
| Key service unavailable | Deny protected reads, isolate dependency; no plaintext/cache bypass |
| Deletion pending too long | Reconcile inventory/provider receipts and lease; retry forward only, never reactivate |
| Origin bypass/WAF saturation | Block origin path, validate gateway/proxy chain and edge admission; measure before reopening |

Set measured latency/error/queue-age/cost SLOs and ownership before launch. No unsupported throughput/security percentage in release notes. Run drills on disposable/staging resources with explicit load scope.

## 10. Release evidence

Required: integration/docs checks, affected and full security suites, genuine browser/network flows, multi-process concurrency, real Redis/Mongo replica set, controlled mail delivery, key deletion/restore, migration from old schema, fresh self-host install, license/SBOM/secret review and private vulnerability disclosure process. Record exact SHA and blocked/skipped checks. Static checks and CI passing do not prove production secrets were rotated, DNS is configured, keys irrecoverable or live provider mail delivered.
