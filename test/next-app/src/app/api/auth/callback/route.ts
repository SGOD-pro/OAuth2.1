import { cookies } from 'next/headers';
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

  const cookieStore = await cookies();
  const storedState = cookieStore.get('oauth_state')?.value || request.cookies.get('oauth_state')?.value;
  const codeVerifier = cookieStore.get('oauth_verifier')?.value || request.cookies.get('oauth_verifier')?.value;

  if (!state || !storedState || state !== storedState) {
    console.error(`[OAuth State Mismatch] Received state: "${state}", Stored state: "${storedState}"`);
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

    cookieStore.set('auth_session', JSON.stringify(sessionPayload), {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: tokens.expires_in || 3600,
    });

    cookieStore.delete('oauth_verifier');
    cookieStore.delete('oauth_state');

    const response = NextResponse.redirect(new URL('/dashboard', request.url));
    response.cookies.set('auth_session', JSON.stringify(sessionPayload), {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: tokens.expires_in || 3600,
    });
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
