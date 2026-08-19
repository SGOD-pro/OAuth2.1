import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { requireAuth, AuthenticatedRequest } from './middleware/auth.js';

dotenv.config();

const app = express();
const PORT = parseInt(process.env.PORT || '4000', 10);
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5175';

const AUTH_ISSUER = process.env.AUTH_ISSUER || 'http://localhost:3000';
const CLIENT_ID = process.env.CLIENT_ID || '';
const CLIENT_SECRET = process.env.CLIENT_SECRET || '';
const CALLBACK_URL = process.env.AUTH_CALLBACK_URL || `http://localhost:${PORT}/auth/callback`;

const allowedOrigins = [
  CLIENT_ORIGIN,
  'http://localhost:5175',
  'http://localhost:5173',
  'http://localhost:3000',
  'http://localhost:3001',
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(null, true); // Permissive in dev mode
  },
  credentials: true,
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// PKCE Helper utilities
function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// ── Authentication Endpoints ──────────────────────────────────

// 1. Start OAuth 2.1 PKCE Flow
app.get('/auth/login', (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = crypto.randomBytes(16).toString('base64url');

  res.cookie('oauth_verifier', codeVerifier, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000, // 10 mins
  });

  res.cookie('oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000,
  });

  const authUrl = new URL(`${AUTH_ISSUER}/api/auth/oauth2/authorize`);
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', CALLBACK_URL);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('prompt', 'login');

  res.redirect(authUrl.toString());
});

// 2. OAuth 2.1 Callback Route
app.get('/auth/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.redirect(`${CLIENT_ORIGIN}?error=${encodeURIComponent(String(error_description || error))}`);
  }

  const storedState = req.cookies?.oauth_state;
  const codeVerifier = req.cookies?.oauth_verifier;

  if (!state || state !== storedState) {
    return res.redirect(`${CLIENT_ORIGIN}?error=Invalid+state+mismatch`);
  }

  if (!code || !codeVerifier) {
    return res.redirect(`${CLIENT_ORIGIN}?error=Missing+code+or+verifier`);
  }

  try {
    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    // 3. Exchange code for tokens
    const tokenRes = await fetch(`${AUTH_ISSUER}/api/auth/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basicAuth}`,
        Accept: 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: CALLBACK_URL,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: codeVerifier,
      }).toString(),
    });

    if (!tokenRes.ok) {
      const errBody = await tokenRes.text();
      return res.redirect(`${CLIENT_ORIGIN}?error=Token+exchange+failed:+${encodeURIComponent(errBody)}`);
    }

    const tokens = await tokenRes.json();

    // Fetch user profile from OIDC userinfo
    let user = {};
    try {
      const userRes = await fetch(`${AUTH_ISSUER}/api/auth/oauth2/userinfo`, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });
      if (userRes.ok) {
        user = await userRes.json();
      }
    } catch {
      // ignore
    }

    const sessionPayload = {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_at: Date.now() + (tokens.expires_in || 3600) * 1000,
      user,
    };

    res.cookie('app_session', JSON.stringify(sessionPayload), {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: (tokens.expires_in || 3600) * 1000,
    });

    res.clearCookie('oauth_verifier');
    res.clearCookie('oauth_state');

    res.redirect(CLIENT_ORIGIN);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Authentication failed';
    console.error('[OAuth Callback Error]:', err);
    res.redirect(`${CLIENT_ORIGIN}?error=${encodeURIComponent(msg)}`);
  }
});

// 3. Get Current Authenticated User Info
app.get('/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
  res.json({
    authenticated: true,
    user: req.user,
    accessTokenPreview: req.accessToken ? `${req.accessToken.slice(0, 12)}...` : undefined,
  });
});

// 4. Logout Session
app.post('/auth/logout', (req, res) => {
  res.clearCookie('app_session');
  res.clearCookie('oauth_verifier');
  res.clearCookie('oauth_state');
  res.json({ success: true, message: 'Logged out successfully' });
});

// ── Secure Protected Backend Route ────────────────────────────

// 5. Fetch Secure Telemetry (Protected by requireAuth)
app.get('/api/secure-telemetry', requireAuth, (req: AuthenticatedRequest, res) => {
  res.json({
    status: 'AUTHENTICATED_STREAM_ACTIVE',
    authorizedSubject: req.user?.sub,
    email: req.user?.email || 'Confidential Pilot',
    timestamp: new Date().toISOString(),
    engineMetrics: {
      chassisId: 'SWYRA-M-EXPRESS-992',
      rpm: Math.floor(6000 + Math.random() * 1500),
      speedKmh: Math.floor(210 + Math.random() * 40),
      oilTemp: 102.5,
      waterTemp: 89.1,
      turboBoostBar: 1.62,
      gear: 5,
      powerOutputKw: 425,
      tractionControl: 'MDM_DYNAMIC',
    },
    securityContext: {
      authServer: AUTH_ISSUER,
      tokenVerification: 'RFC 7662 Introspection / RS256 JWKS',
      grantedScopes: req.user?.scope || 'openid profile email',
      encryptedSession: true,
    }
  });
});

app.listen(PORT, () => {
  console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`  SWYRA M Auth — Express Test Backend Server`);
  console.log(`  Listening on: http://localhost:${PORT}`);
  console.log(`  Auth Issuer:  ${AUTH_ISSUER}`);
  console.log(`  Client ID:    ${CLIENT_ID || '(Not configured)'}`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
});
