import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';
import { refreshAccessToken } from '@/lib/oauth';

export async function POST(request: NextRequest) {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('auth_session')?.value || request.cookies.get('auth_session')?.value;

  let refreshToken: string | undefined;
  let sessionPayload: any;

  if (sessionCookie) {
    try {
      sessionPayload = JSON.parse(sessionCookie);
      refreshToken = sessionPayload?.tokens?.refresh_token;
    } catch {
      // ignore
    }
  }

  // Also accept refreshToken in request body if provided
  try {
    const body = await request.json().catch(() => ({}));
    if (body?.refresh_token) {
      refreshToken = body.refresh_token;
    }
  } catch {
    // ignore
  }

  if (!refreshToken) {
    return NextResponse.json(
      { error: 'invalid_request', message: 'Missing refresh token in session or body' },
      { status: 400 }
    );
  }

  try {
    const tokens = await refreshAccessToken(refreshToken);

    if (sessionPayload) {
      sessionPayload.tokens = tokens;
      sessionPayload.updatedAt = Date.now();

      cookieStore.set('auth_session', JSON.stringify(sessionPayload), {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: tokens.expires_in || 3600,
      });
    }

    const response = NextResponse.json(tokens);
    if (sessionPayload) {
      response.cookies.set('auth_session', JSON.stringify(sessionPayload), {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: tokens.expires_in || 3600,
      });
    }

    return response;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Refresh failed';
    return NextResponse.json({ error: 'refresh_failed', message }, { status: 401 });
  }
}
