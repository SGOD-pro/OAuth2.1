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
