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

export interface SharedSessionStore {
  get(key: string): Promise<any | null>;
  set(key: string, val: any, ttlSec?: number): Promise<void>;
}

let sharedSessionStore: SharedSessionStore | null = null;
export function setSharedSessionStore(store: SharedSessionStore | null) {
  sharedSessionStore = store;
}

const inFlightRefreshes = new Map<string, Promise<{ access_token: string; refresh_token?: string; expires_in: number }>>();

export async function coordinateTokenRefresh(
  refreshToken: string,
  issuer: string,
  clientId: string,
  clientSecret?: string,
  sessionId?: string
): Promise<{ access_token: string; refresh_token?: string; expires_in: number }> {
  const existing = inFlightRefreshes.get(refreshToken);
  if (existing) {
    return existing;
  }

  const cacheKey = sessionId ? `shared_refresh_${sessionId}` : `shared_refresh_${refreshToken.slice(0, 16)}`;
  if (sharedSessionStore) {
    try {
      const cached = await sharedSessionStore.get(cacheKey);
      if (cached && cached.access_token) {
        return cached;
      }
    } catch {}
  }

  const refreshPromise = (async () => {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      };
      const bodyParams = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: clientId,
      });

      if (clientSecret) {
        const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
        headers['Authorization'] = `Basic ${basicAuth}`;
      }

      const res = await fetch(`${issuer}/api/auth/oauth2/token`, {
        method: 'POST',
        headers,
        body: bodyParams.toString(),
      });

      if (!res.ok) {
        // If refresh failed (e.g. token consumed), check if another process instance just refreshed this session
        if (sharedSessionStore) {
          try {
            const cachedAfterFail = await sharedSessionStore.get(cacheKey);
            if (cachedAfterFail && cachedAfterFail.access_token) {
              return cachedAfterFail;
            }
          } catch {}
        }
        const errText = await res.text();
        throw new Error(`Token refresh failed (${res.status}): ${errText}`);
      }

      const data = await res.json();
      if (sharedSessionStore) {
        try {
          await sharedSessionStore.set(cacheKey, data, 60);
        } catch {}
      }
      return data;
    } finally {
      inFlightRefreshes.delete(refreshToken);
    }
  })();

  inFlightRefreshes.set(refreshToken, refreshPromise);
  return refreshPromise;
}

export async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const cookieSession = req.cookies?.app_session;

  let token: string | undefined;
  let sessionUser: Record<string, unknown> | undefined;
  let sessionExpiresAt: number | undefined;
  let refreshToken: string | undefined;
  let parsedSession: any;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (cookieSession) {
    try {
      parsedSession = typeof cookieSession === 'string' ? JSON.parse(cookieSession) : cookieSession;
      token = parsedSession.access_token;
      sessionUser = parsedSession.user;
      sessionExpiresAt = parsedSession.expires_at;
      refreshToken = parsedSession.refresh_token;
    } catch {
      // Invalid cookie format
    }
  }

  const issuer = process.env.AUTH_ISSUER;
  const clientId = process.env.CLIENT_ID;
  const clientSecret = process.env.CLIENT_SECRET;

  // Auto-refresh expired session if refresh_token is available
  if (refreshToken && sessionExpiresAt && sessionExpiresAt <= Date.now() && issuer && clientId) {
    try {
      const sessionId = parsedSession?.session_id || parsedSession?.user?.sub;
      const refreshed = await coordinateTokenRefresh(refreshToken, issuer, clientId, clientSecret, sessionId);
      token = refreshed.access_token;
      refreshToken = refreshed.refresh_token || refreshToken;
      sessionExpiresAt = Date.now() + (refreshed.expires_in || 3600) * 1000;
      if (parsedSession) {
        parsedSession.access_token = token;
        parsedSession.refresh_token = refreshToken;
        parsedSession.expires_at = sessionExpiresAt;
        res.cookie('app_session', JSON.stringify(parsedSession), {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          path: '/',
          maxAge: (refreshed.expires_in || 3600) * 1000,
        });
      }
    } catch (refreshErr) {
      // Refresh failed and could not be recovered from shared session store;
      // Invalidate stale cookie and return controlled session_expired recovery response
      res.clearCookie('app_session', { path: '/' });
      return res.status(401).json({
        error: 'session_expired',
        message: 'Session credentials were rotated by another process instance or expired. Re-authentication required.',
        recovery_flow: 'reauthenticate',
        login_url: '/auth/login',
      });
    }
  }

  if (!token) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Missing Bearer token or session cookie',
    });
  }

  if (!issuer || !clientId) {
    return res.status(500).json({ error: 'misconfigured', message: 'Missing AUTH_ISSUER or CLIENT_ID in environment' });
  }
  const publicKey = process.env.PUBLIC_KEY ? process.env.PUBLIC_KEY.replace(/\\n/g, '\n') : '';
  const jwksUrl = process.env.JWKS_URL || `${issuer}/.well-known/jwks.json`;

  try {
    // Approach 1: Fast Offline JWT Verification (via Public Key or JWKS)
    try {
      let key;
      if (publicKey && publicKey.startsWith('-----BEGIN')) {
        key = await importSPKI(publicKey, 'RS256');
      } else {
        key = getJWKS(jwksUrl);
      }
      
      const { payload } = await jwtVerify(token, key, {
        issuer,
        audience: clientId,
      });

      req.user = (sessionUser && Object.keys(sessionUser).length > 0)
        ? (sessionUser as AuthenticatedRequest['user'])
        : (payload as AuthenticatedRequest['user']);
      req.accessToken = token;
      return next();
    } catch (jwtErr: any) {
      if (jwtErr?.code === 'ERR_JWT_EXPIRED') {
        return res.status(401).json({
          error: 'token_expired',
          message: 'Access token has expired',
        });
      }
      if (jwtErr?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
        return res.status(403).json({
          error: 'forbidden',
          message: 'Access token was not issued for this application (claim mismatch)',
        });
      }
      // If token is an opaque token or key retrieval failed, try Token Introspection
    }

    // Approach 2: Token Introspection Endpoint (RFC 7662)
    const basicAuth = Buffer.from(`${clientId}:${clientSecret || ''}`).toString('base64');
    const introspectParams: Record<string, string> = {
      token,
      client_id: clientId,
    };
    if (clientSecret) introspectParams.client_secret = clientSecret;

    const introspectRes = await fetch(`${issuer}/api/auth/oauth2/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basicAuth}`,
        Accept: 'application/json',
      },
      body: new URLSearchParams(introspectParams).toString(),
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

    return res.status(401).json({
      error: 'invalid_token',
      message: 'Access token validation failed',
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Token verification error';
    return res.status(401).json({
      error: 'unauthorized',
      message: msg,
    });
  }
}
