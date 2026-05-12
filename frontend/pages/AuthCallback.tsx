import React, { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import GlassSurface from '@/components/GlassSurface';

/**
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * AuthCallback — /callback
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Handles one edge case: user lands on auth service
 * with no consuming-app OAuth flow in progress.
 *
 * Case A — code + state in URL:
 *   OAuth Provider mid-flow. Show spinner.
 *   Better Auth handles the redirect automatically.
 *
 * Case B — client_id in URL but no code:
 *   Flow starting without going through /auth.
 *   Redirect to /auth preserving all URL params.
 *
 * Case C — no params at all:
 *   User navigated directly. Show informational message.
 *   No form, no buttons.
 */
export const AuthCallback: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const code     = searchParams.get('code');
  const state    = searchParams.get('state');
  const clientId = searchParams.get('client_id');

  // Case B: OAuth flow starting, redirect to /auth preserving params
  useEffect(() => {
    if (!code && clientId) {
      navigate(
        { pathname: '/auth', search: searchParams.toString() },
        { replace: true, viewTransition: true }
      );
    }
  }, [code, clientId, navigate, searchParams]);

  // Case A: mid-flow (code + state present) — Better Auth handles redirect
  if (code && state) {
    return (
      <div className="w-full max-w-3xl px-6">
        <GlassSurface
          width="100%"
          height="auto"
          borderRadius={28}
          backgroundOpacity={0.12}
          blur={12}
          saturation={1.6}
          className="w-full max-w-md mx-auto"
        >
          <div className="w-full px-8 py-10 text-center">
            <div className="mx-auto h-9 w-9 animate-spin rounded-full border-2 border-white/30 border-t-white" />
            <p className="mt-6 text-sm text-muted-foreground">Completing sign in...</p>
          </div>
        </GlassSurface>
      </div>
    );
  }

  // Case B: redirect happening via useEffect — show spinner briefly
  if (!code && clientId) {
    return (
      <div className="w-full max-w-3xl px-6">
        <GlassSurface
          width="100%"
          height="auto"
          borderRadius={28}
          backgroundOpacity={0.12}
          blur={12}
          saturation={1.6}
          className="w-full max-w-md mx-auto"
        >
          <div className="w-full px-8 py-10 text-center">
            <div className="mx-auto h-9 w-9 animate-spin rounded-full border-2 border-white/30 border-t-white" />
          </div>
        </GlassSurface>
      </div>
    );
  }

  // Case C: no params — user navigated directly
  return (
    <div className="w-full max-w-3xl px-6">
      <GlassSurface
        width="100%"
        height="auto"
        borderRadius={28}
        backgroundOpacity={0.12}
        blur={12}
        saturation={1.6}
        className="w-full max-w-md mx-auto"
      >
        <div className="w-full px-8 py-10 text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-white/10 bg-white/10">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="text-foreground"
            >
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>
          <h1 className="mt-6 text-xl font-semibold text-foreground">SWYRA Auth</h1>
          <p className="mt-3 text-sm text-muted-foreground leading-6">
            This service handles authentication for SWYRA applications. To sign in,
            return to the application you were using and initiate sign in from there.
          </p>
        </div>
      </GlassSurface>
    </div>
  );
};
