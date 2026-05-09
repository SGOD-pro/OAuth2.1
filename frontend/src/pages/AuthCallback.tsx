import React, { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { SilkBackground } from '../components/SilkBackground';
import { ThemeToggle } from '../components/ThemeToggle';

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
 *   Flow starting without going through /sign-in.
 *   Redirect to /sign-in preserving all URL params.
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

  // Case B: OAuth flow starting, redirect to /sign-in preserving params
  useEffect(() => {
    if (!code && clientId) {
      navigate({ pathname: '/sign-in', search: searchParams.toString() }, { replace: true });
    }
  }, [code, clientId, navigate, searchParams]);

  // Case A: mid-flow (code + state present) — Better Auth handles redirect
  if (code && state) {
    return (
      <div className="app-container">
        <ThemeToggle />
        <div className="left-pane">
          <div className="glass-surface auth-form" style={{ textAlign: 'center' }}>
            <div className="loading-spinner" />
            <p style={{ marginTop: '1.5rem', opacity: 0.7 }}>Completing sign in...</p>
          </div>
        </div>
        <SilkBackground />
      </div>
    );
  }

  // Case B: redirect happening via useEffect — show spinner briefly
  if (!code && clientId) {
    return (
      <div className="app-container">
        <ThemeToggle />
        <div className="left-pane">
          <div className="glass-surface auth-form" style={{ textAlign: 'center' }}>
            <div className="loading-spinner" />
          </div>
        </div>
        <SilkBackground />
      </div>
    );
  }

  // Case C: no params — user navigated directly
  return (
    <div className="app-container">
      <ThemeToggle />
      <div className="left-pane">
        <div className="glass-surface auth-form" style={{ textAlign: 'center' }}>
          <div style={{ marginBottom: '1.5rem' }}>
            {/* Lock icon */}
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="48"
              height="48"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ color: 'var(--primary-color)', margin: '0 auto 1rem' }}
            >
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>
          <div className="auth-header">
            <h1>SWYRA Auth</h1>
            <p style={{ lineHeight: 1.7 }}>
              This service handles authentication for SWYRA applications.
              To sign in, return to the application you were using
              and initiate sign in from there.
            </p>
          </div>
        </div>
      </div>
      <SilkBackground />
    </div>
  );
};
