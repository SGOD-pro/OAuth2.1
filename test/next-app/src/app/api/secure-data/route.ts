import { NextRequest, NextResponse } from 'next/server';
import { refreshAccessToken, requireEnv } from '@/lib/oauth';
import { createRemoteJWKSet, jwtVerify } from 'jose';

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
function getJWKS(issuer: string) {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
  }
  return jwks;
}

export async function GET(request: NextRequest) {
  // Check auth_session cookie or Bearer token header
  const sessionCookie = request.cookies.get('auth_session')?.value;
  const authHeader = request.headers.get('Authorization');

  let isAuthenticated = false;
  let userEmail = 'Unknown';
  let tokenPreview = '';
  let updatedSession: any = null;

  if (sessionCookie) {
    try {
      const session = JSON.parse(sessionCookie);
      const isExpired = session.createdAt && session.tokens?.expires_in && (session.createdAt + session.tokens.expires_in * 1000 <= Date.now());

      if (isExpired && session.tokens?.refresh_token) {
        try {
          const newTokens = await refreshAccessToken(session.tokens.refresh_token);
          session.tokens = newTokens;
          session.createdAt = Date.now();
          updatedSession = session;
        } catch {
          // auto-refresh failed
        }
      }

      if (session?.tokens?.access_token) {
        const issuer = requireEnv('AUTH_ISSUER');
        const clientId = requireEnv('CLIENT_ID');
        const { payload } = await jwtVerify(session.tokens.access_token, getJWKS(issuer), {
          issuer,
          audience: clientId,
        });
        isAuthenticated = true;
        userEmail = session.user?.email || (payload.email as string) || session.user?.sub || (payload.sub as string) || 'Authenticated User';
        tokenPreview = `${session.tokens.access_token.slice(0, 10)}...${session.tokens.access_token.slice(-6)}`;
      }
    } catch {
      // Invalid session cookie format or token verification failed
      isAuthenticated = false;
    }
  } else if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.replace('Bearer ', '');
    try {
      const issuer = requireEnv('AUTH_ISSUER');
      const clientId = requireEnv('CLIENT_ID');
      const { payload } = await jwtVerify(token, getJWKS(issuer), {
        issuer,
        audience: clientId,
      });
      isAuthenticated = true;
      userEmail = (payload.email as string) || (payload.sub as string) || 'Bearer Token Client';
      tokenPreview = `${token.slice(0, 10)}...${token.slice(-6)}`;
    } catch {
      isAuthenticated = false;
    }
  }

  if (!isAuthenticated) {
    return NextResponse.json(
      {
        error: 'Unauthorized',
        message: 'A valid OAuth 2.1 access token or session is required to access telemetry data.',
      },
      { status: 401 }
    );
  }

  // Return realistic dummy secure telemetry data
  const response = NextResponse.json({
    status: 'SECURE_STREAM_ACTIVE',
    authorizedUser: userEmail,
    tokenPreview,
    timestamp: new Date().toISOString(),
    telemetry: {
      vehicleId: 'M-TELEMETRY-VIN-4892A',
      mode: 'SPORT_PLUS',
      engineSpeedRpm: 6450,
      velocityKmh: 242.6,
      gear: 6,
      oilTempCelsius: 98.4,
      coolantTempCelsius: 90.2,
      boostPressureBar: 1.45,
      batteryLevelPct: 94.2,
      differentialLockPct: 82,
      gForce: {
        lateral: 1.15,
        longitudinal: 0.78,
      },
      lapTimes: [
        { lap: 1, time: '1:44.218', sector1: '28.1', sector2: '36.4', sector3: '39.7' },
        { lap: 2, time: '1:42.890', sector1: '27.8', sector2: '35.9', sector3: '39.1' },
        { lap: 3, time: '1:41.954', sector1: '27.4', sector2: '35.6', sector3: '38.9' },
      ],
      cryptographicDiagnostics: {
        protocol: 'OAuth 2.1 RFC 6749bis',
        authMethod: 'Authorization Code + PKCE (S256)',
        encryption: 'Argon2id + RS256 JWT Introspection',
        accessControl: 'Enforced via SWYRA M Auth IdP',
      }
    }
  });

  if (updatedSession) {
    response.cookies.set('auth_session', JSON.stringify(updatedSession), {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: updatedSession.tokens?.expires_in || 3600,
    });
  }

  return response;
}
