# Rationale: Dev isolation and dual mode client URIs · spec 0004

## Context

OAuth 2.1 mandates strict exact redirect URI matching and forbids wildcards to defend against authorization code interception attacks. In our existing implementation, when the server runs with `NODE_ENV=production`, the client validation logic enforced an all or nothing dichotomy: production clients (`isDev: false`) were strictly restricted to HTTPS URIs, while development clients (`isDev: true`) were restricted to loopback URIs only.

This created significant friction for development teams in two common scenarios:
1. Modern development workflows often utilize cloud preview URLs (such as Vercel preview URLs or staging environments) alongside local workstations (`http://localhost:3000`). Forcing development clients to only use loopback meant developers had to create duplicate client profiles or switch modes, risking accidental deployment of development clients to production.
2. When testing against a production identity provider, creating a development client was rejected unless the entire server had `ALLOW_DEV_CLIENTS_IN_PRODUCTION=true` enabled in its global environment.

Additionally, management endpoints required a valid `x-gateway-secret` header unconditionally. In local development environments where developers run the backend directly on `localhost:3000` without a reverse proxy, unconfigured gateway secrets caused all management requests to return `403 Forbidden`. Furthermore, outdated startup scripts referenced a legacy `hono` directory that no longer exists, breaking initial repository checkout onboarding.

## Options considered

### Option 1: Dual mode client validation with environment aware gateway loopback bypass (Chosen)

Allow development clients (`isDev: true`) to register both strict loopback URIs and valid public HTTPS URIs, while continuing to strictly forbid private intranet IP addresses, HTTP non loopback endpoints, wildcards, and fragments. Allow Super Admins to provision dev clients on production identity providers. In local development mode (`NODE_ENV !== "production"`), permit loopback management calls when no gateway secret is configured, while strictly enforcing secret validation in production. Fix startup script paths.

**Pros**:
* Eliminates onboarding friction and allows zero deploy local testing out of the box.
* Enables modern workflows where developers test against localhost and HTTPS preview deployments using a single development client.
* Preserves strict production security boundaries without degrading fail closed guarantees.

**Cons**:
* Requires nuanced validation branching between production and development clients.

### Option 2: Loosen production client restrictions to allow HTTP localhost

Allow any client in production to optionally include `localhost` redirect URIs.

**Pros**:
* Simpler validation logic with fewer mode checks.

**Cons**:
* Severe security vulnerability. Production clients with live user credentials should never be permitted to send tokens or authorization codes over unencrypted loopback connections. Violates OAuth 2.1 normative standards.

### Option 3: Mandatory mock gateway for all local development

Require developers to always run an intermediary reverse proxy or configure local gateway secrets before making any management API calls.

**Pros**:
* Keeps gateway verification logic completely identical across development and production.

**Cons**:
* High setup friction for new contributors, requiring manual secret synchronization between backend, frontend, and test tools before running local servers.

## Rationale

Option 1 provides the optimal balance of developer ergonomics and strict security guarantees. By allowing development enabled clients to register both loopback and valid HTTPS endpoints, developers can seamlessly test locally and in staging environments without compromising production client safety.

By keeping production clients (`isDev: false`) strictly bound to HTTPS only with zero loopback allowed, production user data remains fully protected. Relaxing the gateway secret check only in development mode when the secret is unconfigured and the incoming host is verified loopback ensures local testing runs smoothly while production environments fail closed without compromise.
