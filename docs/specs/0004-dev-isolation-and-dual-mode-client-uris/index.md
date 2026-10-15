# 0004. Dev isolation and dual mode client URIs

**Date**: 2026-10-14
**Status**: Accepted

## Summary

This decision enables zero deploy local testing and developer velocity while strictly maintaining production security boundaries. It updates OAuth client redirect URI validation so development enabled clients can register both loopback URIs and valid public HTTPS URIs, allowing developers to test locally without breaking staging or preview deployments. It allows Super Admins to register development clients directly on production identity providers, and enables automatic gateway bypass for loopback requests in local development when no gateway secret is configured. It also updates environment templates and startup scripts to reference correct paths.

## Requirements

**User stories**:
* As a consumer application developer, I want my development OAuth client to accept both loopback URIs (such as `http://localhost:3000/callback`) and valid HTTPS preview URIs so that I can test my application locally and in preview environments using the same client credentials.
* As an identity provider administrator, I want to provision development mode clients on production identity providers without setting global bypass environment variables.
* As a new engineer setting up the identity provider repository, I want local startup scripts and environment templates to boot out of the box without requiring manual gateway secret configuration or path debugging.

**Acceptance criteria**:
* **AC-1**: Development enabled OAuth clients (`effectiveIsDev: true`) permit both strict loopback URIs (`http://localhost:*`, `http://127.0.0.1:*`, `http://[::1]:*`) and valid public `https://` URIs and allowed origins, while continuing to strictly reject wildcards, URL fragments, user credentials, non loopback HTTP, and private RFC1918 intranet IP addresses (`10.x`, `192.168.x`, `172.16-31.x`).
* **AC-2**: Production OAuth clients (`effectiveIsDev: false`) remain strictly constrained to HTTPS only with zero loopback, zero HTTP, and zero private IP addresses permitted.
* **AC-3**: Verified Super Admins (`isSuperAdminOp: true`) can create or update `isDev: true` clients with loopback or HTTPS URIs on production identity provider instances without requiring `ALLOW_DEV_CLIENTS_IN_PRODUCTION=true` globally.
* **AC-4**: In production mode (`NODE_ENV === "production"`), gateway secret verification strictly requires `config.internalGatewaySecret` (minimum 32 characters) and a matching `x-gateway-secret` header, failing closed on missing or mismatched values.
* **AC-5**: In development mode (`NODE_ENV !== "production"`), gateway secret verification enforces matching `x-gateway-secret` when `config.internalGatewaySecret` is configured; when unconfigured, it permits loopback requests (`localhost`, `127.0.0.1`, `[::1]`) with an informational console warning.
* **AC-6**: Monorepo root `.env.example` defaults to `NODE_ENV=development` with documented production override, provides default `INTERNAL_GATEWAY_SECRET` matching Vite proxy, and documents `ALLOW_DEV_CLIENTS_IN_PRODUCTION=false`.
* **AC-7**: Local scripts (`start-all.sh`, `backend/check_users.mjs`, `backend/test_signup.mjs`) correctly reference `backend` instead of legacy `hono` directories, and convenience scripts (`dev`, `dev:backend`, `dev:frontend`, `admin:create`) are registered in root `package.json`.

## Decision

**Chosen option**: Option 1: Dual mode client validation with environment aware gateway loopback bypass

We will update `validateOAuthClientConfiguration` and `validateRedirectUri` in `backend/src/utils/security.ts` to allow both loopback and valid HTTPS endpoints on development clients. We will allow Super Admins to provision dev clients without global environment variable overrides, permit unconfigured gateway loopback calls during local development in `backend/src/middleware/admin-auth.ts`, align environment templates, and fix directory paths in startup scripts.

**Implementation skills**: none

## Rationale

Reasoning and options: see [rationale.md](rationale.md).

## Feature design

**Redirect URI and Origin Validation Rules**:
* `effectiveIsDev === true`:
  * Allowed redirect URI schemes and hosts: `http://localhost:*`, `http://127.0.0.1:*`, `http://[::1]:*`, `http://*.localhost:*`, and any valid `https://<public-hostname>/*`.
  * Forbidden: Wildcards (`*`), URI fragments (`#`), user credentials (`user:pass@`), non loopback `http://` (e.g. `http://example.com`), and private intranet IP addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`).
* `effectiveIsDev === false`:
  * Allowed redirect URI schemes: `https://<public-hostname>/*` strictly.
  * Forbidden: All `http://` URIs including loopback, wildcards, fragments, user credentials, and private intranet IP addresses.

**Gateway Secret Verification Logic (`verifyGatewaySecret`)**:
1. Check `config.internalGatewaySecret`:
   * If configured (minimum 32 characters): strictly verify incoming `x-gateway-secret` header against allowed secrets with timing safe comparison across all environments.
   * If unconfigured or empty:
     * If `NODE_ENV === "production"`: return `false` (fail closed, 403 Forbidden).
     * If `NODE_ENV !== "production"` or `config.env === "development"`:
       * Extract request host header.
       * If host is a loopback host (`localhost`, `127.0.0.1`, `[::1]`): log dev warning and return `true`.
       * If host is not a loopback host: return `false` (403 Forbidden).

**Environment and Script Alignments**:
* Root `.env.example`: Set `NODE_ENV=development`, provide matching `INTERNAL_GATEWAY_SECRET`, add `ALLOW_DEV_CLIENTS_IN_PRODUCTION=false`.
* `start-all.sh`: Replace `HONO_DIR="$ROOT_DIR/hono"` with `BACKEND_DIR="$ROOT_DIR/backend"`.
* `backend/check_users.mjs` and `backend/test_signup.mjs`: Replace `path: "hono/.env"` with `path: ".env"`.
* Root `package.json`: Add convenience npm scripts (`dev`, `dev:backend`, `dev:frontend`, `admin:create`).

## Value sourcing

| Value | Source |
|---|---|
| Client dev mode | Target client `isDev` or `is_dev` boolean flag |
| Client redirect URIs | Target client `redirect_uris` or `redirectUris` array |
| Super Admin operation | Request context or caller flag `options.isSuperAdminOp` |
| Gateway secret | Process environment `INTERNAL_GATEWAY_SECRET` via `config.internalGatewaySecret` |
| Request host | Inbound HTTP `Host` or `X-Forwarded-Host` header parsed via URL |

## Build plan

* [x] Update `validateOAuthClientConfiguration` and `validateRedirectUri` in `backend/src/utils/security.ts` to allow both loopback and valid HTTPS endpoints on development clients (satisfies AC-1, AC-2)
* [x] Permit Super Admins to provision development clients in production without global flag (satisfies AC-3)
* [x] Implement environment aware loopback gateway bypass in `backend/src/middleware/admin-auth.ts` (satisfies AC-4, AC-5)
* [x] Update monorepo root `.env.example` with development defaults and shared gateway secret (satisfies AC-6)
* [x] Fix directory paths in `start-all.sh`, `backend/check_users.mjs`, and `backend/test_signup.mjs` (satisfies AC-7)
* [x] Register convenience developer scripts in root `package.json` (satisfies AC-7)
* [x] Add unit and security tests in `backend/tests/unit/dev-isolation.test.ts` to verify all acceptance criteria (satisfies AC-1 through AC-7)

## Consequences

* Development clients gain the flexibility to work across local machines and cloud preview environments without requiring separate OAuth registrations.
* Production clients remain completely protected against loopback or insecure redirects.
* Local onboarding friction is eliminated because developers cloning the repository can run startup commands without hunting down gateway secret configurations.
* Super Admins can safely test integrations on live staging environments without changing global server configuration.

## Follow-up

* Run `/develop dev isolation and dual mode client URIs` to implement the build plan.
