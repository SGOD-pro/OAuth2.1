import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';
import { generateCodeVerifier, generateCodeChallenge, generateState, requireEnv } from '@/lib/oauth';

export async function GET() {
  const issuer = requireEnv('AUTH_ISSUER');
  const clientId = requireEnv('CLIENT_ID');
  const redirectUri = requireEnv('AUTH_CALLBACK_URL');

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = generateState();

  const authUrl = new URL(`${issuer}/api/auth/oauth2/authorize`);
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('prompt', 'login');

  const cookieStore = await cookies();

  // Store verifier and state in temporary cookies for PKCE validation in callback
  cookieStore.set('oauth_verifier', codeVerifier, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 600, // 10 minutes
  });

  cookieStore.set('oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 600,
  });

  const response = NextResponse.redirect(authUrl.toString());
  response.cookies.set('oauth_verifier', codeVerifier, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 600,
  });
  response.cookies.set('oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 600,
  });

  return response;
}
