# V2 abuse prevention, device risk, filters and caching

**Status:** Target control design. Updated 2026-11-22.
[Security](SECURITY.md) defines invariants; [configuration](CONFIGURATION.md) defines policy defaults; [phases](PHASES.md) defines rollout evidence.

## 1. Layered DDoS and resource protection

Fingerprinting cannot stop volumetric DDoS: an attacker can omit/spoof it and traffic already reaches the edge. Protect bandwidth at the hosting/network layer and protect expensive work separately inside the application.

| Layer | Control | Failure behavior |
|---|---|---|
| Hosting edge | Managed DDoS absorption, WAF rules, path/method limits, origin isolation | Drop/challenge before origin cost; hosting capability must be measured/configured |
| Gateway | Authenticated origin path, trusted-proxy client IP resolution, body/header/connection caps | Unknown spoofed forwarding headers cannot choose quota bucket |
| Admission | Distributed IP/prefix/browser/account/client/global budgets, inflight semaphore | Sensitive operations deny if distributed limits cannot be enforced |
| Expensive compute | Password-hash concurrency budget, OTP/TOTP guess caps, bounded crypto work | Reject before expensive hashing/decryption or database scans |
| Persistence | Indexed reads, deadlines, capped pagination, bounded query patterns | Timeout/load-shed; no unbounded user/regex scans |
| Workers/provider | Queue capacity/age limits, send budgets, lease fences, account key quotas | Pause/retry with bounds, no synchronous job storm |

Reference deployment keeps Vercel gateway and Lambda/Node backend. Select/configure edge provider controls before public rollout; do not write 'WAF protected' because the app uses Vercel. If moving to an API Gateway/private origin or Cloudflare edge, prove the request's real peer and forwarded-IP chain before trusting it. Reserved Lambda concurrency and connection-pool caps bound cost and database load; choose measured per-environment values.

## 2. Distributed quota algorithm

Use atomic token buckets for burst admission and fixed/sliding windows for per-mailbox/target budgets where exact counts matter. Existing Redis/Mongo fallback stays supported. A Redis-to-Mongo transition must not grant a second full allowance: reserve critical mail costs in one durable authoritative ledger, or transfer conservatively under a documented epoch/fail-closed transition. Never sum independent unfenced worker counters and call it a global cap.

Keys are domain-separated, HMAC-pseudonymized targets, not raw emails or full IPs in logs. Enforce per-endpoint plus target plus source plus global limits; a malicious mailbox cannot consume another mailbox's budget merely by choosing its ID. Bound lockout duration and preserve a reviewed recovery path to reduce targeted denial of service. No process-local emergency fallback for auth, OTP, reset, MFA, admin or destructive account operations. Public cacheable metadata may degrade with a bounded local limiter.

### Initial policy defaults, require tuning before public release

| Operation | Source/target limit | Additional bound |
|---|---|---|
| Login | Existing general 20 requests/min/IP; target 15 failures/5 minutes | Password-hash fleet concurrency and progressive backoff |
| OTP send/resend | Mailbox 3/15 minutes, 10/day, 60-second cooldown | IP 10/15 minutes; browser 5/15 minutes; global daily budget |
| OTP verify | 5 guesses/generation plus 10/mailbox/30 minutes | Resend never resets aggregate guesses |
| TOTP/recovery | 5 failures/5 minutes per account/challenge | One-use accepted timestep/code and bounded account backoff |
| Username check | 20/min per verified intent/browser | No anonymous account existence API |
| Export | One active job/account, 3/day | Object size/deadline and worker concurrency |
| Deletion | One active operation/account | Idempotent repeat/status polling; no duplicate expensive jobs |

These values are starting policy, not a guarantee of attack resistance. Shared-NAT users, IPv6 rotation and accessibility must be tested. CAPTCHA/adaptive challenge can help after suspicious activity, but must be server-verified, transaction-bound, expiring and replay-resistant, with an accessible alternate path. Do not make third-party tracking a requirement for every login.

## 3. Device signals and suspicious activity

Proposed signals: first-party random browser ID, coarse browser/OS family, recent session history, coarse network changes, failure velocity and known-compromise indicators. Optional coarse locale/timezone may be collected with clear purpose. Do not collect canvas/audio entropy, installed fonts, hardware serials or persistent cross-app identifiers. Never expose a reusable fingerprint to consumers.

Store a server-keyed pseudonymous device-observation ID with version/retention, distinct from the credential-bearing browser cookie. Fingerprints are spoofable/resettable and must not be used as `sub`, account recovery proof, session secret or uniqueness constraint. Missing JS/signals do not bypass quotas and are not enough alone to ban a legitimate account.

| Risk class | Example reason combination | Action |
|---|---|---|
| Normal | Valid session, ordinary network/browser variation | Standard policy; no extra password merely for minor drift |
| Elevated | New browser plus unusual failure velocity or sensitive operation | Require recent password and TOTP if configured; security notification |
| High | Confirmed stolen/replayed credential or strong compromise evidence | Revoke affected session/family, deny attempt, audited owner recovery |
| Uncertain | Risk dependency unavailable or signal missing | Sensitive actions require fresh factors; no false 'trusted device' claim |

Begin with explainable rules and versioned reason codes, not an untrained ML score. IP change alone is not impossible travel; VPN/mobile routing is common. Measure false positives, step-up completion and support impact. Notification links lead to authenticated dashboard review, not one-click credential-free account locking. For phishing resistance consider passkeys in a later slice; email OTP and TOTP do not provide it.

## 4. Bloom, XOR and related filtering decisions

Use these structures only when measurements show a useful lookup/cost reduction. They are not encryption, uniqueness enforcement, user validation or a DDoS shield.

| Structure | Appropriate candidate use | Limits and V2 decision |
|---|---|---|
| Bloom filter | Immutable/versioned compromised-password corpus prefilter before exact check | False positives; deletion not directly supported; optional measured experiment |
| XOR filter | Compact static snapshot of the same corpus or immutable batch inventory | Rebuild for changed set; publish snapshot+version atomically; optional experiment |
| Cuckoo/counting filter | Dynamic analytics/dedup candidate where deletion is needed | Incorrect deletion/count handling can lose entries; not selected for auth state |
| Count-Min Sketch | Approximate aggregate abuse telemetry/heavy-hitter hints | Overestimates; only risk/measurement input, never sole account lock decision |
| Exact unique index/set | Email/username uniqueness, revocation, used proof/code state | Required authoritative security state |

A positive probabilistic result means maybe present and requires exact confirmation. A negative is safe only for the exact fully built source snapshot and supported semantics; stale snapshots can miss new entries. Thus neither result bypasses authoritative account, session, grant, membership, uniqueness or denial checks. No public endpoint exposes filter membership for emails/usernames.

For Bloom sizing, document expected `n`, desired false-positive `p`, `m = -n ln(p)/(ln 2)^2` bits and `k = (m/n) ln 2` hash functions. Example n=1,000,000, p=0.001 needs about 14.4 million bits (1.8 MB decimal), k about 10, before implementation overhead. Input-set fidelity, rebuild lag and memory costs matter more than the formula alone.

For any experiment record benchmark, exact-store baseline, source/version/checksum, saturation/rebuild policy, rollback and unavailable-filter fallback. Do not filter first and then skip the database uniqueness check even when the filter says absent. The normal production default is filters disabled until this evidence exists.

References: [Redis Bloom semantics](https://redis.io/docs/latest/develop/data-types/probabilistic/bloom-filter/) and [Graf/Lemire XOR-filter paper](https://arxiv.org/abs/1912.08258). These describe data structures, not proof of auth security.

## 5. Cache matrix

| Object | Cache/default | Authority and invalidation |
|---|---|---|
| Discovery/JWKS | Public bounded max-age/ETag; measured starting TTL 5 minutes | Key rotation overlap; refresh once on unknown kid; no attacker URL fetch |
| Client display metadata | Server bounded TTL 60 seconds, versioned | Enabled/access/callback policy revalidated at authority boundary |
| Origin allowlist | Existing Redis/Mongo generation/tombstone cache | Preserve monotonic invalidation, lease cleanup and stale-writer tests |
| Own profile labels/preferences | Account/context/version key, <=30 seconds | No cross-account cache key; no credentials; no-store HTTP response |
| Account/session/grant/family active state | No stale positive authorization cache | Authoritative read or consistent durable fence on protected decisions |
| OTP/proof/used recovery credential | No positive verifier-response cache | Atomic one-use durable consume and inline expiry |
| Browser account list/dashboard/export | No CDN/shared HTTP caching | IdP origin only, no-store; owner context validation |
| Plaintext account keys | Disabled initially | If introduced later, very short version-bound cache with pre-use deletion check and purge proof |
| Rate-limit counters | Distributed atomic store, not a normal read-through cache | Critical budgets survive failover; outage denies sensitive work |
| Negative account lookup | Avoid externally visible timing/oracle cache | No cross-tenant/session existence leak; exact-store auth still authoritative |

Use bounded singleflight for safe metadata misses, jittered TTL and bounded negative-kid caching to prevent JWKS stampedes. Mongo/key-service/queue deadlines and circuit breakers prevent dependency saturation. A circuit breaker cannot turn authorization failure into allow. Never log raw cache keys containing tokens, emails or device fingerprints.

## 6. Load and release evidence

Run authorized disposable/staging tests only: baseline and saturation p50/p95/p99 for authorize/login/OTP/refresh, maximum hashing/DB connections, multiple process quotas, store failover/outage, forged IP chain, cookie/header floods, expensive invalid tokens, queue backlog/cost ceiling and noisy-neighbor fairness. Define SLO/concurrency/send ceilings from these measurements; do not invent throughput claims.

Security telemetry records request ID, endpoint category, pseudonymous account/client/session reference, outcome, reason and policy version. Owner security notifications must not leak credentials. Operators alert on auth-deny spikes, exhausted global budget, stale deletion jobs, key/queue failures and unexpected sensitive-cache hits. Explain the response/recovery runbook in [DEPLOYMENT.md](DEPLOYMENT.md).
