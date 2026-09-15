# Consumer Application Integration Guide

All consumer applications authenticate and authorize users through standard **OAuth 2.1 (PKCE + Authorization Code Flow)**.

---

## 1. Client Environment Variables Reference

| Variable | Description | Local Development | Production Example |
|---|---|---|---|
| `AUTH_ISSUER` | Base URL of the Auth Gateway | `http://localhost:5174` | `https://auth.yourdomain.com` |
| `JWKS_URL` | Public keys for offline RS256 JWT validation | `http://localhost:5174/.well-known/jwks.json` | `https://auth.yourdomain.com/.well-known/jwks.json` |
| `CLIENT_ID` | OAuth Client ID from Admin Dashboard | `your_client_id` | `your_client_id` |
| `CLIENT_SECRET` | Plaintext Client Secret (backend confidential clients only) | `your_plaintext_secret` | `your_plaintext_secret` |
| `REDIRECT_URI` | Whitelisted callback route | `http://localhost:3001/api/auth/callback` | `https://app.example.com/api/auth/callback` |

---

## 2. Integration Pattern 1: Full-Stack Next.js 14 (BFF Pattern)

*Example codebase available in `test/next-app/`*

### Step 1: Configure `.env`
```env
AUTH_ISSUER=http://localhost:5174
JWKS_URL=http://localhost:5174/.well-known/jwks.json
CLIENT_ID=qMoXkZwvWnZJRmFhpiTyzLMozZYrwvlF
CLIENT_SECRET=HQEFWhArRpYvjySBrzSbtBBlOpeZDpHY
REDIRECT_URI=http://localhost:3001/api/auth/callback
PORT=3001
```

### Step 2: Initiate OAuth Login
```typescript
// app/login/page.tsx
export function LoginButton() {
  const loginUrl = `${process.env.NEXT_PUBLIC_AUTH_ISSUER}/auth?client_id=${process.env.NEXT_PUBLIC_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.NEXT_PUBLIC_REDIRECT_URI!)}&response_type=code&scope=openid+profile+email`;

  return <a href={loginUrl}>Sign in with SWYRA Auth</a>;
}
```

### Step 3: Exchange Code in Route Handler
```typescript
// app/api/auth/callback/route.ts
import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');

  const tokenRes = await fetch(`${process.env.AUTH_ISSUER}/api/auth/oauth2/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${Buffer.from(`${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`).toString('base64')}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code!,
      redirect_uri: process.env.REDIRECT_URI!,
    }),
  });

  const tokens = await tokenRes.json();

  // Set secure HttpOnly session cookie
  const response = NextResponse.redirect(new URL('/dashboard', request.url));
  response.cookies.set('session', tokens.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  });
  return response;
}
```

---

## 3. Integration Pattern 2: Decoupled React SPA + Express Backend

*Example codebase available in `test/react-express-app/`*

### Step 1: Express Verification Middleware (`backend/auth.ts`)
Express verifies incoming Bearer tokens offline using `jose` without any database queries:

```typescript
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { Request, Response, NextFunction } from 'express';

const jwks = createRemoteJWKSet(new URL(process.env.JWKS_URL!));

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {
    const { payload } = await jwtVerify(token, jwks);

    // Enforce Audience & Client ID binding (Prevent cross-app token replay)
    const tokenClientId = (payload.client_id || payload.azp || payload.aud) as string;
    if (tokenClientId && tokenClientId !== process.env.CLIENT_ID) {
      return res.status(403).json({ error: 'forbidden', message: 'Token not issued for this client' });
    }

    (req as any).user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}
```

---

## 4. Integration Pattern 3: Standalone React SPA with PKCE

For purely client-side single-page applications without a custom backend:

1. **Generate PKCE Parameters**:
   - Generate random string `code_verifier`.
   - Calculate SHA-256 hash and base64url-encode to produce `code_challenge`.
2. **Authorize Redirect**:
   - Send user to `${AUTH_ISSUER}/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&code_challenge=${code_challenge}&code_challenge_method=S256&scope=openid+profile+email`.
3. **Token Exchange**:
   - Make `POST /api/auth/oauth2/token` with `code` and `code_verifier`.
   - Confidential client secrets are **not required** for public SPA PKCE clients.

---

## 5. Per-Application Administrator Authentication & Verification

Each registered OAuth application can have dedicated **Application Administrators** provisioned via the Super Admin Console (`/admin/clients`). Application administrators manage the **consumer application's own administrative portal** (e.g., product management, user moderation, order operations), completely separated from SWYRA Auth's platform administration.

SWYRA Auth exposes high-security, server-to-server endpoints allowing consumer applications to authenticate admins, verify active admin sessions, and revoke tokens.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as App Admin
    participant AppFront as Consumer Frontend
    participant AppBack as Consumer Backend / BFF
    participant IdP as SWYRA Auth API

    Admin->>AppFront: Enter email & password at /admin/login
    AppFront->>AppBack: POST /api/admin/login
    AppBack->>IdP: POST /api/auth/app-admin/login<br/>{ client_id, client_secret, email, password }
    Note over IdP: 1. Validate client credentials<br/>2. Rate limit check (IP + Target)<br/>3. Verify admin password (timing-safe)<br/>4. Generate HS256 JWT with JTI
    IdP-->>AppBack: 200 OK { token, redirectUrl, admin }
    AppBack-->>AppFront: Set HttpOnly session cookie & return { redirectUrl }
    AppFront-->>Admin: Redirect to redirectUrl (e.g., /admin/dashboard)

    Note over AppFront,AppBack: Protected Admin Operations
    Admin->>AppBack: GET /admin/api/data (with admin session)
    AppBack->>IdP: POST /api/auth/app-admin/verify<br/>{ client_id, client_secret, token }
    Note over IdP: 1. Verify token signature & JTI revocation<br/>2. Verify client ID match<br/>3. Verify admin active in DB
    IdP-->>AppBack: 200 OK { valid: true, admin }
    AppBack-->>Admin: Admin Data Response

    Note over AppFront,AppBack: Logout
    Admin->>AppBack: POST /admin/logout
    AppBack->>IdP: POST /api/auth/app-admin/logout<br/>{ client_id, client_secret, token }
    IdP-->>AppBack: 200 OK { success: true }
```

### 5.1 Endpoint Reference

| Endpoint | Method | Purpose | Auth Required |
|---|---|---|---|
| `/api/auth/app-admin/login` | `POST` | Authenticates an app admin with credentials | `client_id` + `client_secret` in body |
| `/api/auth/app-admin/verify` | `POST` | Verifies admin token signature, active status, and revocation | `client_id` + `client_secret` + Bearer token |
| `/api/auth/app-admin/logout` | `POST` | Revokes admin token and adds JTI to revocation list | `client_id` + `client_secret` + Bearer token |

---

### 5.2 Step 1: Administrator Login (`/api/auth/app-admin/login`)

When an administrator logs into your application's admin panel, your backend relays their credentials along with your confidential `client_id` and `client_secret`.

#### Request:
`POST /api/auth/app-admin/login`  
**Content-Type**: `application/json`

```json
{
  "client_id": "qMoXkZwvWnZJRmFhpiTyzLMozZYrwvlF",
  "client_secret": "HQEFWhArRpYvjySBrzSbtBBlOpeZDpHY",
  "email": "ops-admin@storefront.example.com",
  "password": "AdminSecurePassword@2026!"
}
```

#### Success Response (`200 OK`):
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "redirectUrl": "https://storefront.example.com/admin/dashboard",
  "admin": {
    "id": "66e74b21d8b2a1a4567e8901",
    "email": "ops-admin@storefront.example.com",
    "name": "Operations Lead",
    "clientId": "qMoXkZwvWnZJRmFhpiTyzLMozZYrwvlF",
    "role": "app_admin",
    "redirectUrl": "https://storefront.example.com/admin/dashboard"
  }
}
```

> [!TIP]
> **Redirect URL Routing**: After a successful login, navigate the administrator to the returned `redirectUrl`. The origin of `redirectUrl` is guaranteed to match your application's registered `allowed_origins` or `redirect_uris`.

#### Error Responses:
- `400 Bad Request`: Missing `client_id`, `client_secret`, `email`, or `password`.
- `401 Unauthorized`: Invalid client credentials (`invalid_client`) or invalid admin credentials (`invalid_credentials`).
- `403 Forbidden`: Admin account is deactivated (`account_disabled`) or application suspended.
- `429 Too Many Requests`: Rate limit exceeded (target-keyed and IP-based defense).

---

### 5.3 Step 2: Protecting Admin Routes (`/api/auth/app-admin/verify`)

Your backend verifies the incoming admin token before allowing access to sensitive administrative endpoints. This ensures that deactivated admins or revoked sessions are rejected immediately.

#### Next.js 14 App Router Verification Handler Example:
```typescript
// app/api/admin/verify-session/route.ts
import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function GET() {
  const token = cookies().get('app_admin_session')?.value;
  if (!token) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  const res = await fetch(`${process.env.AUTH_ISSUER}/api/auth/app-admin/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
    }),
  });

  const data = await res.json();
  if (!res.ok || !data.valid) {
    return NextResponse.json({ error: data.message || 'forbidden' }, { status: res.status });
  }

  return NextResponse.json({ authenticated: true, admin: data.admin });
}
```

#### Express.js Admin Guard Middleware Example:
```typescript
// middleware/requireAppAdmin.ts
import type { Request, Response, NextFunction } from 'express';

export async function requireAppAdmin(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'unauthorized', message: 'Missing admin token' });
  }

  try {
    const response = await fetch(`${process.env.AUTH_ISSUER}/api/auth/app-admin/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        token,
      }),
    });

    const data = await response.json();
    if (!response.ok || !data.valid) {
      return res.status(response.status).json({
        error: data.error || 'forbidden',
        message: data.message || 'Invalid admin session',
      });
    }

    // Attach verified admin to request
    (req as any).admin = data.admin;
    next();
  } catch (err) {
    return res.status(500).json({ error: 'internal_error', message: 'Verification failed' });
  }
}
```

---

### 5.4 Step 3: Administrator Logout & Token Revocation (`/api/auth/app-admin/logout`)

When the administrator logs out, invoke the logout endpoint to revoke the token's unique identifier (`jti`). Even if a revoked token has not reached its 1-hour expiration time, `/verify` will reject it immediately.

#### Express / Next.js Logout Example:
```typescript
export async function logoutAdmin(adminToken: string) {
  const res = await fetch(`${process.env.AUTH_ISSUER}/api/auth/app-admin/logout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      token: adminToken,
    }),
  });

  return await res.json();
}
```
