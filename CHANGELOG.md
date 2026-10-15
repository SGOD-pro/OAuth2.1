# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
* Dynamic per client role resolution in OAuth token issuance, token introspection, and userinfo endpoints (see spec 0001)
* Multi application administration support allowing application admins to manage multiple consumer apps via user app registrations without privilege leakage
* Conflict detection and resolution in administrative provisioning scripts protecting Global Super Admin accounts from scoped client overrides
* Administrative login guard in console detecting non super admin sessions and displaying clean recovery actions with one click sign out
* Automated unit test suite verifying identity decoupling, Super Admin cold start preservation, removal resilience, and role isolation (`backend/tests/unit/admin-scoping.test.ts`)
* Automatic CORS origin derivation extracting unique valid web origins from redirect URIs when allowed origins are omitted or empty on client creation and updates (see spec 0005)
* Non web scheme tolerance during origin derivation safely skipping native mobile app schemes and URNs without runtime exceptions
* Dual casing field normalization across camelCase and snake_case properties through centralized helper normalizeOAuthClientFields
* One click auto derive action button and onAdd origin synchronization in admin console registration and edit dialogs
* Shared deriveOrigins utility in frontend security library deduplicating origin parsing across modal components
* Administrative audit logging for tenant role reassignments emitting structured audit records on sync, repointing, or demotion
* Unified test:unit script in backend and root package manifests executing all five unit test suites
* Automated unit test suite verifying origin derivation, cross tier parity, IPv6 loopbacks, custom ports, and field resilience (backend/tests/unit/config-simplification.test.ts)
* Dual mode redirect URI validation for development OAuth clients, permitting both strict loopback endpoints (`http://localhost:*`, `http://127.0.0.1:*`, `http://[::1]:*`, `*.localhost`) and public HTTPS preview endpoints under a single client profile (see spec 0004)
* Direct development client provisioning by verified Super Admins on production identity provider instances without requiring global environment bypass flags
* Automatic application type derivation resolving to native per RFC 8252 for clients with loopback URIs or development mode
* Unconfigured gateway loopback bypass for local development, enabling zero configuration onboarding on developer machines with informational security warnings
* Socket connection remote address verification in gateway middleware to defend against host header spoofing over local area networks
* IPv4 mapped IPv6 intranet address filtering (`::ffff:`) blocking private network addresses in dotted decimal and hex literal formats
* Automated unit test suite verifying dev client dual mode validation, lookalike rejection, Super Admin creation, and gateway secret handling (`backend/tests/unit/dev-isolation.test.ts`)
* Convenience developer scripts (`dev`, `dev:backend`, `dev:frontend`, `admin:create`) registered in root `package.json`
* Key identifier matching for public keys with in memory caching and graceful fallback to the newest key (see spec 0002)
* Self healing RS256 keypair generation when private key decryption fails, with fail closed protection against writing plaintext keys
* Dynamic database proxy forwarder ensuring initialized adapters never hold stale client references across reconnects
* Stale lock reclamation for token family rotation compare and swap queries after 15 seconds
* Automated edge rewrite configuration generation during frontend builds using `--if-present` flag, ensuring untracked `vercel.json` files exist on direct Git and dashboard deployments
* Dynamic backend URL overrides via `LAMBDA_BACKEND_URL` environment variable in `scripts/prepare-vercel-config.mjs`
* Automated unit test suite verifying gateway configuration generation, cleaning, length validation, and deployment overrides (`tests/unit/gateway-pipeline.test.ts`)

### Changed
* Background synchronization sweeps and cold start self healing routines respect Global Super Admin privileges without mutating scoped client bindings, passwords, or ban status
* Administrative middleware requireScopedAdmin and checkUserIsClientAdmin evaluate multi app memberships across registrations and assigned client records
* Scoped administrator removal deterministically re-points remaining application bindings or demotes to standard user status only when zero assignments remain
* Client registration and update endpoints automatically validate, persist, and invalidate CORS origin cache for derived web origins
* Client query endpoints return dual camelCase and snake_case properties ensuring backward compatibility with all API consumer conventions
* Root environment template `.env.example` defaults to `NODE_ENV=development` with documented production overrides, preconfigured shared gateway secret matching Vite proxy, and clear instructions for production deployments
* Unified startup script `start-all.sh` and administrative utility scripts (`check_users.mjs`, `test_signup.mjs`) reference `backend` instead of legacy directory paths
* MongoDB connection manager configures production timeouts with 10 second server selection, 30 second socket timeout, 60 second idle connection limits, and automatic reconnect event listeners
* Refresh token rotation permits concurrent in flight requests within a 2000 millisecond grace window without revoking active sessions or token families
* Backend deployment script `backend/deploy.sh` enforces minimum 32 character gateway secret presence and passes parameter overrides to AWS SAM CLI deployments

### Fixed
* Eliminated Global Super Admin lockouts where background sync sweeps inadvertently overwrote unscoped administrators with scoped client attributes
* Prevented cross application privilege escalation where application admins inherited administrative rights across unrelated consumer applications
* Resolved administrative console access loops where existing consumer app sessions blocked Global Super Admin sign in
* Eliminated client onboarding friction where omitting CORS origins led to browser cross origin token request failures
* Resolved duplicated frontend origin parsing logic between client creation and edit dialogs
* Eliminated local developer onboarding blockers caused by startup scripts referencing nonexistent legacy directories
* Prevented gateway verification crashes when `INTERNAL_GATEWAY_SECRET` is unset in development by introducing environment aware bypass handling
* Avoided configuration ambiguity by adding structured diagnostic error logs when production boots without a minimum 32 character gateway secret
* Eliminated permanent token family lockouts when worker executions freeze or terminate during refresh token exchange
* Prevented process memory exhaustion and cache pollution by bounding public key cache capacity to 50 entries and isolating non matching key identifiers
* Protected token rotation grace calculations against negative time deltas caused by host clock drift
* Prevented edge authentication failures (`403 Forbidden`) caused by missing `vercel.json` rewrite rules during Vercel automated deployments
* Protected configuration generation string replacement against dollar sign character substitution corruption using replacer functions

### Security
* Strict isolation of Global Super Admin credentials ensuring unscoped administrative identities cannot be tampered with or overwritten by consumer app metadata
* Dynamic role evaluation on token minting and introspection guarantees revoked application administrators immediately lose elevated access even if tokens contain stale claims
* Production OAuth clients remain strictly restricted to HTTPS only with zero loopback, zero plain HTTP, and zero private RFC1918 intranet addresses permitted
* Gateway secret verification in production strictly fails closed when the internal gateway secret is missing, short, or invalid, with support for comma separated secret rotation
* Preserved token family cascade revocation and active token deletion when consumed refresh tokens are presented outside the 2000 millisecond grace window to defend against replay theft
