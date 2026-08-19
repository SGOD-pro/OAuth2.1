import { Request, Response, NextFunction } from 'express';
import { createRemoteJWKSet, jwtVerify, importSPKI } from 'jose';

export interface AuthenticatedRequest extends Request {
  user?: {
    sub: string;
    email?: string;
    name?: string;
    scope?: string;
    [key: string]: unknown;
  };
  accessToken?: string;
}

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJWKS(jwksUrl: string) {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUrl));
  }
  return jwks;
}

export async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const cookieSession = req.cookies?.app_session;

  let token: string | undefined;
  let sessionUser: Record<string, unknown> | undefined;
  let sessionExpiresAt: number | undefined;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (cookieSession) {
    try {
      const parsed = typeof cookieSession === 'string' ? JSON.parse(cookieSession) : cookieSession;
      token = parsed.access_token;
      sessionUser = parsed.user;
      sessionExpiresAt = parsed.expires_at;
    } catch {
      // Invalid cookie format
    }
  }

  if (!token) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Missing Bearer token or session cookie',
    });
  }

  // If we have a valid non-expired BFF session cookie with user profile, authenticate immediately
  if (sessionUser && Object.keys(sessionUser).length > 0 && (!sessionExpiresAt || sessionExpiresAt > Date.now())) {
    req.user = sessionUser as AuthenticatedRequest['user'];
    req.accessToken = token;
    return next();
  }

  const issuer = process.env.AUTH_ISSUER || 'http://localhost:3000';
  const clientId = process.env.CLIENT_ID || '';
  const clientSecret = process.env.CLIENT_SECRET || '';
  const publicKey = process.env.PUBLIC_KEY ? process.env.PUBLIC_KEY.replace(/\\n/g, '\n') : '';
  const jwksUrl = process.env.JWKS_URL || `${issuer}/api/auth/jwks`;

  try {
    // Approach 1: Fast Offline JWT Verification (via Public Key or JWKS)
    try {
      let key;
      if (publicKey && publicKey.startsWith('-----BEGIN')) {
        key = await importSPKI(publicKey, 'RS256');
      } else {
        key = getJWKS(jwksUrl);
      }
      
      const { payload } = await jwtVerify(token, key);

      // Strict App-Isolation: Validate token audience / client_id
      const tokenClientId = (payload as any).client_id || (payload as any).azp || (payload as any).aud;
      if (tokenClientId && typeof tokenClientId === 'string' && clientId && tokenClientId !== clientId) {
        return res.status(403).json({
          error: 'forbidden',
          message: 'Access token was not issued for this application (Client ID mismatch)',
        });
      }

      req.user = payload as AuthenticatedRequest['user'];
      req.accessToken = token;
      return next();
    } catch {
      // If token is an opaque token or JWKS verification falls back, use Token Introspection
    }

    // Approach 2: Token Introspection Endpoint (RFC 7662)
    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    const introspectRes = await fetch(`${issuer}/api/auth/oauth2/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basicAuth}`,
        Accept: 'application/json',
      },
      body: new URLSearchParams({
        token,
        client_id: clientId,
        client_secret: clientSecret,
      }).toString(),
    });

    if (introspectRes.ok) {
      const introspectData = await introspectRes.json();
      if (introspectData.active) {
        if (introspectData.client_id && clientId && introspectData.client_id !== clientId) {
          return res.status(403).json({
            error: 'forbidden',
            message: 'Access token was not issued for this application',
          });
        }
        // Fetch userinfo if needed
        let userInfo: Record<string, unknown> = {};
        try {
          const userInfoRes = await fetch(`${issuer}/api/auth/oauth2/userinfo`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (userInfoRes.ok) {
            userInfo = await userInfoRes.json();
          }
        } catch {
          // Userinfo optional
        }

        req.user = {
          sub: introspectData.sub || String(userInfo.sub || 'user'),
          email: introspectData.email || String(userInfo.email || ''),
          name: introspectData.name || String(userInfo.name || ''),
          scope: introspectData.scope,
          ...userInfo,
        };
        req.accessToken = token;
        return next();
      }
    }

    // Fallback: If sessionUser is available, use it
    if (sessionUser && Object.keys(sessionUser).length > 0) {
      req.user = sessionUser as AuthenticatedRequest['user'];
      req.accessToken = token;
      return next();
    }

    return res.status(401).json({
      error: 'invalid_token',
      message: 'Access token validation failed',
    });
  } catch (err: unknown) {
    if (sessionUser && Object.keys(sessionUser).length > 0) {
      req.user = sessionUser as AuthenticatedRequest['user'];
      req.accessToken = token;
      return next();
    }
    const msg = err instanceof Error ? err.message : 'Token verification error';
    return res.status(401).json({
      error: 'unauthorized',
      message: msg,
    });
  }
}
