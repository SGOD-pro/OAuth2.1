// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Browser-Only OAuth 2.1 PKCE Client (Decoupled SPA)
// RFC 7636 Proof Key for Code Exchange (S256)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  window.crypto.getRandomValues(array);
  return base64UrlEncode(array.buffer);
}

export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(digest);
}

export interface StartOAuthOptions {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
}

export async function startOAuthFlow({
  issuer,
  clientId,
  redirectUri,
  scope = 'openid profile email offline_access',
}: StartOAuthOptions) {
  const verifier = generateCodeVerifier();
  const challenge = await generateCodeChallenge(verifier);
  const state = generateCodeVerifier();

  sessionStorage.setItem('spa_oauth_verifier', verifier);
  sessionStorage.setItem('spa_oauth_state', state);

  const authUrl = new URL(`${issuer}/api/auth/oauth2/authorize`);
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', scope);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('prompt', 'login');

  window.location.href = authUrl.toString();
}

export interface ExchangeCodeOptions {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  code: string;
  state: string;
}

export async function exchangeCodeForTokens({
  issuer,
  clientId,
  clientSecret,
  redirectUri,
  code,
  state,
}: ExchangeCodeOptions) {
  const savedState = sessionStorage.getItem('spa_oauth_state');
  const codeVerifier = sessionStorage.getItem('spa_oauth_verifier');

  if (!savedState || state !== savedState) {
    throw new Error('OAuth State Mismatch: Security validation failed.');
  }

  if (!codeVerifier) {
    throw new Error('Missing PKCE code verifier in session storage.');
  }

  const params: Record<string, string> = {
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    code_verifier: codeVerifier,
    redirect_uri: redirectUri,
  };

  if (clientSecret) {
    params.client_secret = clientSecret;
  }

  const res = await fetch(`${issuer}/api/auth/oauth2/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams(params),
  });

  // Clean up one-time verifier from storage
  sessionStorage.removeItem('spa_oauth_verifier');
  sessionStorage.removeItem('spa_oauth_state');

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.error_description || errData.error || `HTTP ${res.status}: Token exchange failed`);
  }

  return await res.json();
}

export async function fetchUserInfo(issuer: string, accessToken: string) {
  const res = await fetch(`${issuer}/api/auth/oauth2/userinfo`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch userinfo: HTTP ${res.status}`);
  }

  return await res.json();
}
