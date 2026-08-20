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
