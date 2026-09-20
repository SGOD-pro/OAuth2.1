# OAuth 2.1 Integration & Security Analysis Report

This document records the technical investigation, root cause analysis, live verification results, and remediation steps for two observed authentication behaviors in consumer applications integrated with the SWYRA OAuth 2.1 Identity Provider.

---

## Executive Summary

| Issue | Observed Symptom | Security Impact | Root Cause |
|---|---|---|---|
| **Issue 1: AWS Dashboard on Lambda** | App configured for `http://localhost:3000` logged in successfully when deployed on AWS Lambda without CORS or Redirect URI errors. | **No vulnerability.** OAuth provider validation is active and enforced. | Login used direct server-to-server Application Admin REST endpoints (`/api/auth/app-admin/login`), which bypass browser CORS and do not use OAuth redirect URIs. |
| **Issue 2: Unconfigured Client ID in Travel Agent** | App with unregistered `client_id=swena_travel_agent_client` displayed the login page (`/auth`) instead of an immediate invalid client error. | **No vulnerability.** Tokens and codes cannot be issued to unregistered clients. | The consumer application's login handler incorrectly targeted the frontend UI route (`/auth`) rather than the RFC-compliant OAuth authorization endpoint (`/api/auth/oauth2/authorize`). |

---

## Issue 1: AWS Dashboard Functioning with Localhost Configuration on AWS Lambda

### 1. Context & Setup
* **Application**: `AWS Dashboard`
* **Live Deployment URL**: `https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws/`
* **Admin Dashboard Configuration**:
  * **Redirect URIs**: `http://localhost:3000/auth/callback`
  * **Allowed CORS Origins**: `http://localhost:3000`
  * **Application URL**: `http://localhost:3000/`
  * **Configured Admin**: `swyra@aws.com` (21 successful logins recorded)

### 2. Root Cause Analysis

The application features two distinct authentication mechanisms:

```
[Browser Client]
       │
       ├─ (A) Admin Login (Email/Password Form)
       │       │
       │       ▼ (Same-Origin POST)
       │  [Next.js API Route /api/auth/login]
       │       │
       │       ▼ (Server-to-Server HTTPS Request — No Browser CORS)
       │  [OAuth Provider /api/auth/app-admin/login]
       │       └─ Verifies client_id + client_secret + email + password
       │       └─ Issues Admin Session Token (No redirect_uri used)
       │
       └─ (B) OAuth 2.1 SSO ("Continue with SWYRA SSO")
               │
               ▼ (Browser 302 Redirect)
          [OAuth Provider /api/auth/oauth2/authorize]
               └─ Validates redirect_uri against database
```

#### Why Admin Login Succeeded Without Errors:
1. **No Browser CORS Triggered**: The browser submits credentials to its own origin (`https://77gqzhgn4k3iaiticbaxdkndi40whzjp.../api/auth/login`). The Next.js server running in AWS Lambda then initiates a backend HTTP request using Node's `fetch` to `https://.../api/auth/app-admin/login`. CORS headers (`Access-Control-Allow-Origin`) are enforced solely by web browsers; server-side runtimes like AWS Lambda ignore them.
2. **Redirect URI Not Involved**: The `/api/auth/app-admin/login` endpoint is a direct REST API for app administrators. It authenticates the client via `client_id` + `client_secret` and the administrator via `email` + `password`. Because this flow does not generate an authorization code or redirect the browser, `redirect_uri` is never evaluated.

#### Live Verification of OAuth 2.1 Validation:
When the live OAuth provider authorization endpoint was tested with the Lambda Function URL as the `redirect_uri`:

```bash
curl -i "https://yu6fcg6yx4xmq5u4we5n6j3ywm0inmis.lambda-url.ap-south-1.on.aws/api/auth/oauth2/authorize?\
client_id=WpruQjczIYMHwzwcntshzKsdkMnkrvWS&\
redirect_uri=https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws/auth/callback&\
response_type=code&state=test"
```

**Response:**
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"error":"invalid_request","error_description":"The redirect_uri is not registered for this application"}
```

The OAuth provider strictly blocks unregistered redirect URIs.

### 3. Remediation Checklist for AWS Dashboard

To transition AWS Dashboard to a fully registered production state:

- [ ] **OAuth Provider Dashboard**:
  - Add Redirect URI: `https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws/auth/callback`
  - Add Allowed CORS Origin: `https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws`
  - Update Application URL: `https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws`
- [ ] **AWS Dashboard Lambda Environment Variables**:
  - Set `AUTH_CALLBACK_URL` = `https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws/auth/callback`

---

## Issue 2: Unconfigured Client ID Redirecting to Auth Sign-In Page

### 1. Context & Setup
* **Consumer Application**: `travel-agent`
* **Requested URL**:
  ```
  https://oauth21.vercel.app/auth?client_id=swena_travel_agent_client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fcallback&response_type=code&code_challenge=...&code_challenge_method=S256&scope=openid+profile+email&state=...
  ```
* **Observed Behavior**: The browser loaded the SWYRA login page (`/auth`) instead of showing an `invalid_client` error, despite `swena_travel_agent_client` not being registered in the database.

### 2. Root Cause Analysis

In `/home/swyra/projects/travel-agent/frontend/src/app/api/auth/login/route.ts` (line 22):

```typescript
// ❌ Current Implementation in travel-agent:
const authUrl = new URL(`${authIssuer}/auth`);
```

The consumer application constructed the authorization URL pointing to the **frontend UI route** (`/auth`) instead of the **OAuth 2.1 Authorization Endpoint** (`/api/auth/oauth2/authorize`).

#### Why the Login Page Loaded:
* The path `/auth` is a static React Single Page Application route (`frontend/pages/SignIn.tsx`).
* Navigating to `/auth` in a browser simply downloads and renders the frontend HTML and React components.
* The frontend page itself does not grant authorization codes or issue tokens.

#### Security Boundary Enforcement:
If a user submits credentials on `/auth`, the frontend executes the following logic ([SignIn.tsx](file:///home/swyra/projects/OAuth2.1/frontend/pages/SignIn.tsx#L50-L59)):

```typescript
const callbackURL = useMemo(() => {
  if (searchParams.get('client_id') && searchParams.get('redirect_uri')) {
    return `/api/auth/oauth2/authorize?${searchParams.toString()}`;
  }
  return undefined;
}, [searchParams]);
```

Upon successful user authentication, the browser is redirected to `callbackURL` (`/api/auth/oauth2/authorize`).

#### Live Verification of the Authorization Endpoint:
Testing the live OAuth authorization endpoint with the unregistered client ID:

```bash
curl -i "https://oauth21.vercel.app/api/auth/oauth2/authorize?\
client_id=swena_travel_agent_client&\
redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fcallback&\
response_type=code&code_challenge=i-e8Uo6Vk9DQdXXJR7JGDYCPuBEMDPUr8Q9SNWcZmCc&\
code_challenge_method=S256&scope=openid+profile+email&state=891f493e049a945d8d47646123fa44e2"
```

**Response:**
```http
HTTP/2 401 Unauthorized
Content-Type: application/json

{"error":"invalid_client","error_description":"Client application not found"}
```

The authorization server terminates the flow with **HTTP 401**. The unregistered client never receives an authorization code, token, or user profile data.

### 3. Remediation Checklist for Travel Agent

#### A. Correct the Authorization Endpoint in `travel-agent`
In `travel-agent/frontend/src/app/api/auth/login/route.ts`:

```diff
- const authUrl = new URL(`${authIssuer}/auth`);
+ const authUrl = new URL(`${authIssuer}/api/auth/oauth2/authorize`);
```

With this change, any request with an unregistered `client_id` will immediately fail with `401 Client application not found` before any login UI is displayed.

#### B. Register the Application in OAuth 2.1 Provider
1. Log into the OAuth 2.1 Admin Dashboard (`https://oauth21.vercel.app/admin/clients`).
2. Register a new client application:
   * **Name**: Travel Agent
   * **Client ID**: `swena_travel_agent_client` (or auto-generated ID)
   * **Redirect URIs**: `http://localhost:3000/api/auth/callback` (and any production callback URLs)
   * **Allowed CORS Origins**: `http://localhost:3000`
3. Update `CLIENT_ID` and `CLIENT_SECRET` in `travel-agent/backend/.env` and `travel-agent/frontend/.env.local`.
