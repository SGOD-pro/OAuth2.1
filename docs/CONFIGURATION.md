# SWYRA Auth -- Configuration Specification (CONFIGURATION.md)

**Authority:** Normative Environment and Configuration Reference for SWYRA Auth and Consumers  
**Target:** System Administrators, DevOps Engineers, and Integrating Applications  

---

## 1. Architectural Philosophy: Fail-Closed Configuration

Every configuration parameter across SWYRA Auth and consumer applications is governed by the **Fail-Closed Principle**:
- **Missing Required Settings:** If a mandatory environment variable is absent or empty, the application MUST crash at startup with a fatal log.
- **Forbidden Fallbacks:** Defaulting expressions such as `process.env.CLIENT_ID || "dev-client"` or `process.env.AUTH_CALLBACK_URL || "http://localhost:3000/callback"` are strictly forbidden.
- **Environment Isolation:** The runtime server environment (`NODE_ENV`) is strictly decoupled from client modes (`isDev`). A production IdP server (`NODE_ENV=production`) hosts both development clients (`isDev: true`) and production clients (`isDev: false`).

---

## 2. SWYRA Auth IdP Server Environment Variables

The IdP server runs on Node.js / AWS Lambda and requires the following configuration in `backend/.env` or runtime environment:

### 2.1 Core Server Settings

| Variable | Type | Required | Description | Example |
|---|---|---|---|---|
| `NODE_ENV` | String | **Yes** | Server execution environment. Allowed: `production`, `development`, `test`. | `production` |
| `PORT` | Number | No | HTTP listening port for node server. Defaults to `3000`. | `3000` |
| `MONGO_URI` | String | **Yes** | MongoDB Atlas connection string. Requires replica set for transactions. | `mongodb+srv://...` |
| `BETTER_AUTH_SECRET` | String | **Yes** | High-entropy cryptographic secret for Better-Auth signing (min 32 chars). | `<min-32-char-random-secret>` |
| `BETTER_AUTH_URL` | String (URL) | **Yes** | Canonical base URL of the IdP service (OIDC Issuer). | `https://oauth21.vercel.app` |
| `FRONTEND_URL` | String (URL) | **Yes** | Canonical base URL of the IdP frontend UI. | `https://oauth21.vercel.app` |

### 2.2 Security Perimeter & Gateway Settings

| Variable | Type | Required | Description | Example |
|---|---|---|---|---|
| `INTERNAL_GATEWAY_SECRET` | String | **Yes** | 64-hex-character secret verified between reverse proxy (Vercel) and Lambda. | `<64-hex-character-secret>` |
| `TRUSTED_PROXY_CIDRS` | String | **Yes (Prod)** | Comma-separated CIDR blocks of trusted proxies for `X-Forwarded-For` client IP resolution. | `127.0.0.1/32,10.0.0.0/8` |
| `ALLOW_DEV_CLIENTS_IN_PRODUCTION` | Boolean | No | Emergency switch. Defaults to `false`. When `false`, dev clients (`isDev: true`) cannot be created or run in production unless explicitly permitted. | `false` |

### 2.3 Feature Flags & Authentication Policies

| Variable | Type | Required | Description | Default |
|---|---|---|---|---|
| `AUTH_PUBLIC_SIGNUP_ENABLED` | Boolean | No | Enables self-registration globally on the IdP for public applications. | `true` |
| `AUTH_EMAIL_VERIFICATION_ENABLED` | Boolean | No | Enforces email verification before issuing OAuth authorization codes. | `false` |

### 2.4 Distributed Cache & Rate Limiting

| Variable | Type | Required | Description | Example |
|---|---|---|---|---|
| `UPSTASH_REDIS_REST_URL` | String (URL) | No | Upstash Redis REST endpoint for distributed rate limiting. | `https://<your-redis-instance>.upstash.io` |
| `UPSTASH_REDIS_REST_TOKEN` | String | No | Upstash Redis REST Bearer token. | `<upstash-token>` |

---

## 3. Client Registration Document Properties (MongoDB `oauthClient`)

Every client application registered in SWYRA Auth possesses a document in the `oauthClient` collection:

| Property | Type | Default | Description |
|---|---|---|---|
| `clientId` | String | Generated | Unique, URL-safe client identifier. Publicly visible. |
| `clientSecret` | String | Generated | SHA-256 base64url hash of client secret. Omitted for Public clients. |
| `name` | String | Required | Human-readable application name displayed on login/consent screens. |
| `redirectUris` | Array&lt;String&gt; | `[]` | Exact registered HTTPS callback URLs where authorization codes may be sent. |
| `allowedOrigins` | Array&lt;String&gt; | `[]` | Origins permitted for CORS requests to `/oauth2/token` and `/oauth2/userinfo`. |
| `isPublic` | Boolean | `true` | **Tenancy Mode:** `true` = open to all platform users; `false` = restricted to pre-assigned users. |
| `isDev` | Boolean | `false` | **Client Mode:** `true` = loopback (`http://localhost:*`) permitted; `false` = strict HTTPS only. |
| `disabled` | Boolean | `false` | Administrative kill-switch. When `true`, all authentication requests are blocked (403). |
| `skipConsent` | Boolean | `false` | When `true`, trusted first-party clients bypass the interactive consent prompt. |
| `adminUserId` | String | `null` | User ID of the designated Application Administrator. |
| `adminEmail` | String | `null` | Email of the designated Application Administrator. |

---

## 4. Consumer Application Environment Variables

Consumer applications integrate with SWYRA Auth using standard OAuth 2.1 environment variables:

### 4.1 Confidential Clients (Next.js BFF, Express, FastAPI, Django)

```env
# Canonical IdP Issuer Base URL (No trailing slash)
AUTH_ISSUER=https://oauth21.vercel.app

# Client Identifier issued by SWYRA Auth
CLIENT_ID=your-registered-client-id

# Confidential Client Secret (MUST NEVER BE EXPOSED TO BROWSER)
CLIENT_SECRET=your-registered-client-secret

# Exact registered callback URL matching an entry in IdP redirectUris
AUTH_CALLBACK_URL=https://your-consumer-app.com/api/auth/callback

# Consumer session encryption key (min 32 chars)
SESSION_SECRET=your-consumer-session-secret
```

### 4.2 Public Clients (React SPA, Vue, Mobile)

```env
# Public IdP Issuer Base URL
VITE_AUTH_ISSUER=https://oauth21.vercel.app

# Public Client Identifier
VITE_CLIENT_ID=your-public-client-id

# Registered Callback URL
VITE_AUTH_CALLBACK_URL=https://your-spa-domain.com/callback
```

> [!CAUTION]
> **Zero Client Secrets in Frontend Bundles:**  
> Never expose confidential secrets in client variables (such as `NEXT_PUBLIC_*`, `VITE_*`, or `REACT_APP_*`). Public clients authenticate using PKCE (`S256`) alone without client credentials.

---

## 5. Development vs Production Configuration Rules

### The Two Independent Dimensions
1. **Confidential vs Public:** Governs whether the client possesses a `clientSecret`.
2. **Development vs Production (`isDev`):** Governs whether loopback URIs (`http://localhost:*`, `http://127.0.0.1:*`) are permitted.

| Client State | `isDev` | Permitted Redirect URIs | Permitted Origins |
|---|---|---|---|
| **Production Client** | `false` | Strict HTTPS only. No IP literals, no localhost, no wildcards. | Strict HTTPS only. |
| **Development Client** | `true` | Loopback HTTP permitted (`http://localhost:*`, `http://127.0.0.1:*`, `http://[::1]:*`). | Loopback HTTP origins permitted. |

### Immutability Rules
- Scoped Application Administrators CANNOT modify `isDev` or `isPublic`. These trust boundary flags can only be configured by Global Super Administrators.
- A development client transitioning to production (`isDev: true` &rarr; `isDev: false`) must remove all localhost redirect URIs in the same atomic operation.
