# SWYRA M Auth — Decoupled Architecture Test Suite

This suite demonstrates the **Decoupled Architecture**:
1. **Frontend (Vite React SPA - Port 5175)**:
   - Performs browser-based **OAuth 2.1 PKCE (S256)** authentication directly with SWYRA M Auth (`https://oauth21.vercel.app`).
   - Requires **only the Public Client ID / App ID**.
   - Zero secrets stored on the client.
2. **Backend (Express API Resource Server - Port 4000)**:
   - Pure API server protecting endpoints via `requireAuth` middleware.
   - Verifies incoming `Authorization: Bearer <access_token>` offline using SWYRA's public **RS256 JWKS** (`https://oauth21.vercel.app/api/auth/jwks`).
   - No client secret or auth server roundtrips required for request authorization.

---

## 🚀 Quick Start

### 1. Register Client in SWYRA Console (`https://oauth21.vercel.app/admin/clients`)
- **Client Name**: `React Express Decoupled App`
- **Redirect URIs**: `http://localhost:5175`
- Copy your generated **Client ID** (`app_id`).

---

### 2. Start the Express API Backend (Port 4000)
```bash
cd test/react-express-app/backend
npm install
npm run dev
```
The server will start at `http://localhost:4000`.

---

### 3. Start the Vite React Frontend (Port 5175)
```bash
cd test/react-express-app/frontend
npm install
npm run dev
```
Open `http://localhost:5175` in your browser.

---

## 🧪 Testing the Decoupled Flow

1. Click **"Sign In with SWYRA M Auth (Browser PKCE)"**.
2. Complete authentication on SWYRA M Auth.
3. You will be redirected back to `http://localhost:5175` where your browser automatically completes the PKCE exchange and loads your JWT token.
4. Click **"📡 Call Express API with Bearer Token"** — the Express backend verifies the signature via RS256 JWKS and responds with authorized telemetry data.
