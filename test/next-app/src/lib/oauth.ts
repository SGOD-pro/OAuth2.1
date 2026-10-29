import crypto from 'crypto';

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

export function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

export function generateState(): string {
  return crypto.randomBytes(16).toString('base64url');
}

export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === '') {
    throw new Error(`[Configuration Error] Missing required environment variable: ${name}`);
  }
  return value.trim();
}

export async function exchangeCodeForTokens(
  code: string,
  codeVerifier: string,
  redirectUri: string
): Promise<TokenResponse> {
  const issuer = requireEnv('AUTH_ISSUER');
  const clientId = requireEnv('CLIENT_ID');
  const clientSecret = requireEnv('CLIENT_SECRET');

  const tokenEndpoint = `${issuer}/api/auth/oauth2/token`;
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });

  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${basicAuth}`,
      Accept: 'application/json',
    },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token exchange failed (${response.status}): ${errorText}`);
  }

  return response.json();
}

export async function getUserInfo(accessToken: string) {
  const issuer = requireEnv('AUTH_ISSUER');
  const response = await fetch(`${issuer}/api/auth/oauth2/userinfo`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch userinfo (${response.status})`);
  }

  return response.json();
}

export interface SharedSessionStore {
  get(key: string): Promise<TokenResponse | null>;
  set(key: string, value: TokenResponse, ttlSeconds?: number): Promise<void>;
}

let externalSessionStore: SharedSessionStore | null = null;

/**
 * Configure an optional distributed session store (for example, Redis)
 * to coordinate token refresh across multiple server instances or cluster nodes.
 */
export function setSharedSessionStore(store: SharedSessionStore | null) {
  externalSessionStore = store;
}

/**
 * Single process in memory mutex for in flight token refresh requests.
 *
 * Distributed coordination note:
 * In a multi process or cluster environment (such as multiple containers, cluster workers,
 * or serverless instances), multiple processes handling requests for the same session
 * will execute token refresh independently unless sticky sessions or a shared session store
 * (like Redis) is configured.
 *
 * The IdP implements single winner atomic rotation with a grace window for in flight requests.
 * When multiple processes race, the winner receives rotated credentials. The losing process receives
 * HTTP 400 invalid_grant. If a shared session store is configured via setSharedSessionStore,
 * the losing process recovers the new tokens stored by the winner. Without a shared store,
 * the losing process requires reauthentication recovery via HTTP 401 session_expired.
 */
const inFlightRefreshes = new Map<string, Promise<TokenResponse>>();

export async function coordinateTokenRefresh(
  refreshToken: string,
  refreshFn: () => Promise<TokenResponse>,
  sessionKey?: string
): Promise<TokenResponse> {
  const cacheKey = sessionKey || refreshToken;

  if (externalSessionStore) {
    try {
      const cached = await externalSessionStore.get(cacheKey);
      if (cached && cached.access_token) {
        return cached;
      }
    } catch {}
  }

  const existing = inFlightRefreshes.get(refreshToken);
  if (existing) {
    return existing;
  }

  const promise = (async () => {
    try {
      const result = await refreshFn();
      if (externalSessionStore) {
        try {
          await externalSessionStore.set(cacheKey, result, result.expires_in || 900);
        } catch {}
      }
      return result;
    } catch (err) {
      if (externalSessionStore) {
        try {
          const cachedAfterFail = await externalSessionStore.get(cacheKey);
          if (cachedAfterFail && cachedAfterFail.access_token) {
            return cachedAfterFail;
          }
        } catch {}
      }
      throw err;
    } finally {
      inFlightRefreshes.delete(refreshToken);
    }
  })();

  inFlightRefreshes.set(refreshToken, promise);
  return promise;
}

export async function refreshAccessToken(refreshToken: string, sessionKey?: string): Promise<TokenResponse> {
  return coordinateTokenRefresh(refreshToken, async () => {
    const issuer = requireEnv('AUTH_ISSUER');
    const clientId = requireEnv('CLIENT_ID');
    const clientSecret = requireEnv('CLIENT_SECRET');

    const tokenEndpoint = `${issuer}/api/auth/oauth2/token`;
    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
    });

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basicAuth}`,
        Accept: 'application/json',
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Refresh token failed (${response.status}): ${errorText}`);
    }

    return response.json();
  });
}

