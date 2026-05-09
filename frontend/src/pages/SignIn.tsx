import React, { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { SilkBackground } from '../components/SilkBackground';
import { ThemeToggle } from '../components/ThemeToggle';
import { authClient } from '../lib/auth-client';
import { useOAuthParams } from '../hooks/useOAuthParams';
import { InvalidRequest } from '../components/InvalidRequest';

export const SignIn: React.FC = () => {
  // Task 5 — OAuth param guard.
  // Must be called before any other hook (rules of hooks).
  const { isValid } = useOAuthParams();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [searchParams] = useSearchParams();

  // If OAuth params are missing or invalid, refuse to render the sign-in form.
  // Without valid params, a successful login has nowhere to redirect.
  if (!isValid) return <InvalidRequest reason="missing_params" />;

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const { error: authError } = await authClient.signIn.email({
      email,
      password,
      // callbackURL is supplied by the consuming app via the OAuth flow.
      // Better Auth will redirect back to the consuming app after sign-in.
      callbackURL: searchParams.get('callbackURL') ?? undefined,
    });

    if (authError) {
      setError(authError.message || 'Sign in failed. Please try again.');
      setLoading(false);
    }
    // On success, Better Auth handles the redirect back to the consuming app.
    // Do NOT navigate anywhere manually — this is a passport office, not an app.
  };

  const handleGoogleSignIn = async () => {
    setLoading(true);
    setError('');
    await authClient.signIn.social({
      provider: 'google',
      callbackURL: searchParams.get('callbackURL') ?? undefined,
    });
  };

  return (
    <div className="app-container">
      <ThemeToggle />
      <div className="left-pane">
        <div className="glass-surface auth-form" style={{ viewTransitionName: 'auth-form' }}>
          <div className="auth-header">
            <h1>Welcome Back</h1>
            <p>Please enter your details to sign in.</p>
          </div>

          {error && (
            <div className="auth-error" role="alert">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
              {error}
            </div>
          )}

          <form onSubmit={handleSignIn} className="input-group">
            <div className="input-group">
              <label htmlFor="email">Email</label>
              <input
                type="email"
                id="email"
                placeholder="swyra@example.com"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={loading}
              />
            </div>
            <div className="input-group" style={{ marginTop: '1rem' }}>
              <label htmlFor="password">Password</label>
              <input
                type="password"
                id="password"
                placeholder="••••••••"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
              />
            </div>
            <div className="auth-links">
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input type="checkbox" /> Remember me
              </label>
              <Link to="/forgot-password" viewTransition>Forgot Password?</Link>
            </div>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <div className="divider">
            <span>or</span>
          </div>

          <button
            type="button"
            className="btn-social"
            onClick={handleGoogleSignIn}
            disabled={loading}
          >
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 48 48">
              <path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8c-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C12.955 4 4 12.955 4 24s8.955 20 20 20s20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z"/>
              <path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C16.318 4 9.656 8.337 6.306 14.691z"/>
              <path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238A11.91 11.91 0 0 1 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z"/>
              <path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 0 1-4.087 5.571l.003-.002l6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z"/>
            </svg>
            Continue with Google
          </button>

          <div style={{ textAlign: 'center', marginTop: '1rem', fontSize: '0.95rem' }}>
            Don't have an account? <Link to="/sign-up" viewTransition style={{ color: 'var(--primary-color)', fontWeight: 600, textDecoration: 'none' }}>Sign Up</Link>
          </div>
        </div>
      </div>
      <SilkBackground />
    </div>
  );
};
