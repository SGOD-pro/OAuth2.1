# V2 documentation index

**Updated 2026-11-22.** V2 is a planned implementation program. Read current status before treating proposed routes, settings or collections as available.

1. [Architecture and decisions](ARCHITECTURE.md): goal, baseline, components and client/identity policy.
2. [Authentication workflows](AUTHENTICATION_FLOWS.md): enrollment, OTP, username, login, MFA, OAuth and API contract.
3. [Session model](SESSION_MODEL.md): account chooser, per-tab subjects, cookies, logout and consistency.
4. [Pages and dashboard](USER_EXPERIENCE.md): exact page inventory and user/error states.
5. [Mail service](MAIL_SERVICE.md): provider, queue, delivery security and cost budgets.
6. [Security](SECURITY.md): threat/control/test matrix and algorithm/key-purpose choices.
7. [Abuse, devices, filters and caches](ABUSE_DEFENSE.md): DDoS layers, risk rules, Bloom/XOR decisions and cache authority.
8. [Data lifecycle](DATA_LIFECYCLE.md): schemas, protected adapter, account keys, deletion and restores.
9. [Implementation map](IMPLEMENTATION_MAP.md): existing files, proposed modules and migrations.
10. [Delivery phases](PHASES.md): P0-P9 dependencies, acceptance and rollout gates.
11. [Consumer integration](INTEGRATION.md): stable APIs, scopes, SSO, MFA and consumer responsibilities.
12. [Configuration](CONFIGURATION.md), [deployment](DEPLOYMENT.md), [troubleshooting](TROUBLESHOOTING.md): operator contracts.
13. [Specification 0008](specs/0008-multi-account-identity-platform/index.md), [rationale](specs/0008-multi-account-identity-platform/rationale.md) and [verification plan](specs/0008-multi-account-identity-platform/verify.md): requirement traceability and execution categories.
14. [Scope](scope/scope.md): active program rollup and preserved historical slices.

Proposed file paths are written as code until implementation creates them. Existing executable route/suite manifests under [security/](security/) remain current-runtime inventories; this planning change does not add future routes as if implemented.

P0 now has [locally verified engine compatibility evidence](specs/0008-multi-account-identity-platform/p0-evidence.md). This proves isolated transaction/session boundaries, not production signup, browser chooser or P1-P9 completion.
