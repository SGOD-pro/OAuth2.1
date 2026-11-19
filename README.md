# SWYRA Auth: self-hosted OAuth / OIDC identity provider

> A centralized identity provider built with Hono, MongoDB and Better Auth. Hosting, email delivery, key management and abuse protection have operational costs.

Built with **Hono**, **MongoDB Atlas**, and the **Better Auth** identity engine. Features a modern Admin Console for managing OAuth 2.1 clients, dynamic CORS whitelists, private application tenant isolation, token family rotation with atomic CAS concurrency protection, and application-scoped administration.

---

## Planned next version

The V2 target adds verified email enrollment before account creation, chosen usernames,
multiple account sessions and an account chooser, mandatory administrative TOTP,
user privacy controls, per-account encryption and deletion workflows. Ordinary open-app
membership gates are removed; registered clients, private memberships, consent and
admin isolation remain.

**Status:** Documentation/design only. Current security findings must be addressed
before an open identity rollout. Read [the baseline review](docs/reviews/2026-11-19-identity-platform-baseline.md),
[the build phases](docs/PHASES.md), [the data lifecycle](docs/DATA_LIFECYCLE.md), and
[specification 0008](docs/specs/0008-multi-account-identity-platform/index.md).
No Google-equivalent security, formal conformance, or complete cryptographic erasure
is claimed by these plans.

## 🤖 For AI Coding Agents & Developers

If you are an AI coding agent (e.g., Google Antigravity, Claude Code, GitHub Copilot, Cursor, Devin) or a human developer integrating a consumer application with SWYRA Auth, **start here**:

👉 **[AGENTS.md](AGENTS.md)** (AI Agent Guidance & Fast Protocol Reference)  
👉 **[docs/INTEGRATION.md](docs/INTEGRATION.md)** (Normative Integration Specification & Framework Recipes)  

---

## 🏛️ System Architecture Overview

All consumer applications—regardless of public access or restricted enterprise multi-tenancy—authenticate users through **ONE centralized protocol**:  
**OAuth 2.1 Authorization Code Flow with PKCE (`S256`).**

```mermaid
flowchart TD
    subgraph Consumers["Consumer Applications"]
        NextApp["Next.js 14+ (BFF)<br/>Port: 3001"]
        ReactApp["React SPA (Public)<br/>Port: 5175"]
        ExpressApp["Express API Backend<br/>Port: 4000"]
        FastAPIApp["Python FastAPI Backend"]
    end

    subgraph Edge["SWYRA Auth Gateway (Vercel Edge)"]
        VercelEdge["Reverse Proxy & Header Injection<br/>x-gateway-secret"]
        AuthUI["Centralized Auth UI<br/>/auth, /admin, /consent"]
    end

    subgraph Core["Auth Core (AWS Lambda / Node.js 24)"]
        HonoApp["Hono HTTP Router"]
        OAuthBoundary["OAuth 2.1 Boundary Guard<br/>PKCE S256 & Exact Redirect Matching"]
        TenantGuard["Private Tenant Guard<br/>user_app_registrations"]
        TokenEngine["Token Family Rotation & CAS Guard"]
        JWKSEngine["OIDC Discovery & JWKS<br/>/.well-known/jwks.json"]
    end

    subgraph Persistence["Storage Layer"]
        MongoDB[("MongoDB Atlas<br/>user, oauthClient, registrations, token families")]
        Redis[("Upstash Redis Cache<br/>Rate Limiting")]
    end

    NextApp -- "1. OAuth 2.1 Code + PKCE" --> Edge
    ReactApp -- "1. OAuth 2.1 PKCE Flow" --> Edge
    Edge --> HonoApp
    HonoApp --> OAuthBoundary
    OAuthBoundary --> TenantGuard
    TenantGuard --> MongoDB
    HonoApp --> TokenEngine
    TokenEngine --> MongoDB
    HonoApp -.-> Redis
    ExpressApp -- "2. Offline RS256 Verification" --> JWKSEngine
    FastAPIApp -- "2. Offline RS256 Verification" --> JWKSEngine
    NextApp -- "2. Offline RS256 Verification" --> JWKSEngine
```

---

## 🛡️ Core Security Architecture & Guarantees

- **Zero In-App Password Handling**: Consumer applications NEVER collect, proxy, transmit, or store IdP user passwords. All credentials terminate at the centralized IdP.
- **Protocol controls, subject to verification**: Mandatory PKCE (`code_challenge_method=S256`), cryptographically random `state`, exact redirect URI matching, and single-use authorization codes.
- **Private Tenant Isolation (`isPublic = false`)**: Unauthenticated users are sent to the centralized IdP login with sign-up disabled. Authenticated users are verified against `user_app_registrations`. Unassigned users receive HTTP 302 `error=access_denied`.
- **Token Family Rotation with Atomic CAS**: Refresh tokens rotate atomically on every exchange. Replay attacks trigger immediate cascade revocation across the compromised token family.
- **Scoped vs Super Administration**: Application Administrators (`role: "admin"`, `scopedClientId: "<clientId>"`) can only manage their own client; platform operations require Super Admin (`scopedClientId: null`).
- **Gateway Trust Boundary**: Direct external invocation of backend management endpoints is blocked by `x-gateway-secret` perimeter validation.

---

## 📚 Canonical Documentation Hub

The documentation for SWYRA Auth is consolidated into the following canonical specifications in [`docs/`](docs/):

| Canonical Document | Description |
|---|---|
| 🔌 **[docs/INTEGRATION.md](docs/INTEGRATION.md)** | **Authoritative Integration Contract:** Current endpoints, independent client policy dimensions, zero password relay, secure framework contracts and planned account chooser behavior. |
| 🛡️ **[docs/SECURITY.md](docs/SECURITY.md)** | **Normative Security Architecture:** Trust model, P0 invariants, fail-closed design principles, cryptographic key pinning, and automated security test matrix. |
| 🏛️ **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | **System Design & Topology:** IdP infrastructure, OAuth 2.1 boundary, multi-tenant isolation, user identity vs app membership, and CAS token rotation engine. |
| ⚙️ **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** | **Configuration Reference:** Complete reference for IdP server variables, consumer client variables, public vs private flags, and fail-closed environment rules. |
| 🚀 **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** | **Production Deployment Guide:** Deploying AWS Lambda (SAM) and Vercel edge proxy, secret rotation runbooks, and pre-flight checklist. |
| 🔧 **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)** | **Diagnostics & Error Catalog:** Standard OAuth 2.1 machine-readable error codes, common symptoms, safe resolutions, and debugging rules. |

---

## ⚡ Quickstart (Local Development)

### 1. Prerequisites
- Node.js 20+ (Node 24 recommended)
- MongoDB Atlas instance or local replica set

### 2. Installation & Setup
```bash
# Clone repository
git clone https://github.com/SGOD-pro/OAuth2.1.git
cd OAuth2.1

# Install backend & frontend dependencies
cd backend && npm install
cd ../frontend && npm install
cd ..

# Configure backend environment
cp backend/.env.example backend/.env
# Edit backend/.env with your MONGO_URI and secrets
```

### 3. Running Test Suites
```bash
# Execute the security suites declared in the manifest
npm run test:all-security

# Execute documentation consistency linter
npm run security:docs-check

# Execute integration contract linter
npm run security:integration-check
```

---

## 📄 License

An explicit LICENSE file was not found in the inspected tracked tree. License selection, ownership and dependency provenance must be confirmed before an open-source release. Public visibility alone does not grant an explicit project license.
