# SWYRA M Auth — Test Consumer Applications

This directory contains two standalone, fully functional client applications built to test and verify the **SWYRA M Auth** (OAuth 2.1 / OIDC) Identity Provider:

1. **`next-app/`** — Modern Next.js (App Router) client with server-side PKCE OAuth 2.1 authorization code flow, protected `/dashboard`, auto-refresh coordination, and a secure `/api/secure-data` route.
2. **`react-express-app/`** — Full-stack consumer with an Express backend (`:4000`) and a React (Vite) frontend (`:5175`) demonstrating RFC 7662 token introspection / JWKS offline verification, concurrent refresh coordination mutex, and secure telemetry endpoints.

---

## 📋 Quick Setup & Prerequisites

Before launching the test apps or running automated multi process and browser test suites, ensure consumer dependencies and builds are prepared:
* Next.js consumer: run `npm ci && npm run build` in `test/next-app`
* Express consumer: run `npm ci && npm run build` in `test/react-express-app/backend`
* IdP frontend: run `npm ci && npm run build:ui` in `frontend`

Next, register your test clients in your **SWYRA M Admin Console** (`/admin/clients`):

### 1. Register Next.js App in Admin Dashboard
- **Application Name:** `Next.js Test App`
- **Redirect URIs:** `http://localhost:3001/api/auth/callback`
- **Allowed CORS Origins:** `http://localhost:3001`
- **Copy Credentials:** Note the generated **Client ID** and **Client Secret**.

### 2. Register React + Express App in Admin Dashboard
- **Application Name:** `React Express Test App`
- **Redirect URIs:** `http://localhost:4000/auth/callback`
- **Allowed CORS Origins:** `http://localhost:5175`, `http://localhost:4000`
- **Copy Credentials:** Note the generated **Client ID** and **Client Secret**.

---

## 🏎️ Running the Next.js Consumer App (`:3001`)

### 1. Configure Environment Variables
Copy the template and configure:
```bash
cd test/next-app
cp .env.example .env.local
```
Edit `.env.local` with your Client ID and Secret:
```env
AUTH_ISSUER=http://localhost:3000
CLIENT_ID=your-nextjs-client-id
CLIENT_SECRET=your-nextjs-client-secret
AUTH_CALLBACK_URL=http://localhost:3001/api/auth/callback
```

### 2. Install & Start
```bash
cd test/next-app
npm install
npm run dev
```
Open **[http://localhost:3001](http://localhost:3001)** in your browser.

---

## ⚡ Running the React + Express Consumer App (`:4000` & `:5175`)

### 1. Configure Express Backend Environment Variables
Copy the template and configure:
```bash
cd test/react-express-app/backend
cp .env.example .env
```
Edit `.env` with your Client ID and Secret:
```env
PORT=4000
CLIENT_ORIGIN=http://localhost:5175
AUTH_ISSUER=http://localhost:3000
CLIENT_ID=your-express-client-id
CLIENT_SECRET=your-express-client-secret
AUTH_CALLBACK_URL=http://localhost:4000/auth/callback
```

### 2. Start Express Backend
```bash
cd test/react-express-app/backend
npm install
npm run dev
```

### 3. Start React Vite Frontend
In a new terminal:
```bash
cd test/react-express-app/frontend
npm install
npm run dev
```
Open **[http://localhost:5175](http://localhost:5175)** in your browser.

---

## 🧪 Testing What Happens Under the Hood

| Flow / Feature | How to Test | Expected Behavior |
| :--- | :--- | :--- |
| **PKCE Authorization** | Click **"Sign In with SWYRA M Auth"** | Redirects to IdP with `code_challenge_method=S256` and one-time `state` nonce |
| **User Authentication** | Enter pilot credentials on IdP login card | Issues authorization code, redirects back to consumer callback |
| **Token Exchange** | Handshake at `/api/auth/oauth2/token` | Exchanges authorization code + `code_verifier` for `access_token`, `id_token`, and `refresh_token` |
| **Secure API Route** | View Dashboard telemetry widget | Backend queries protected route with Bearer token, returns mock vehicle telemetry |
| **Unauthorized Protection** | Query `/api/secure-data` without session | Returns `HTTP 401 Unauthorized` |
