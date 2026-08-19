import { NextRequest, NextResponse } from 'next/server';
import { exchangeCodeForTokens, getUserInfo } from '@/lib/oauth';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const code = searchParams.get('code');
  const state = searchParams.get('state');
  const error = searchParams.get('error');
  const errorDescription = searchParams.get('error_description');

  const redirectUri = process.env.AUTH_CALLBACK_URL || 'http://localhost:3001/api/auth/callback';

  if (error) {
    return NextResponse.redirect(
      new URL(`/?error=${encodeURIComponent(errorDescription || error)}`, request.url)
    );
  }

  const storedState = request.cookies.get('oauth_state')?.value;
  const codeVerifier = request.cookies.get('oauth_verifier')?.value;

  if (!state || state !== storedState) {
    return NextResponse.redirect(
      new URL('/?error=Invalid+OAuth+state+mismatch', request.url)
    );
  }

  if (!code || !codeVerifier) {
    return NextResponse.redirect(
      new URL('/?error=Missing+authorization+code+or+verifier', request.url)
    );
  }

  try {
    const tokens = await exchangeCodeForTokens(code, codeVerifier, redirectUri);
    const userInfo = await getUserInfo(tokens.access_token);

    const sessionPayload = {
      tokens,
      user: userInfo,
      createdAt: Date.now(),
    };

    const response = NextResponse.redirect(new URL('/dashboard', request.url));

    // Save session in encrypted/base64 HTTP-only cookie
    response.cookies.set('auth_session', JSON.stringify(sessionPayload), {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: tokens.expires_in || 3600,
    });

    // Clear one-time OAuth handshake cookies
    response.cookies.delete('oauth_verifier');
    response.cookies.delete('oauth_state');

    return response;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Authentication failed';
    return NextResponse.redirect(
      new URL(`/?error=${encodeURIComponent(message)}`, request.url)
    );
  }
}
