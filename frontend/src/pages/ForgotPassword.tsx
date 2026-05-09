import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { SilkBackground } from '../components/SilkBackground';
import { ThemeToggle } from '../components/ThemeToggle';
import { authClient } from '../lib/auth-client';

export const ForgotPassword: React.FC = () => {
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const { error: authError } = await authClient.requestPasswordReset({
      email,
      redirectTo: '/reset-password',
    });

    if (authError) {
      setError(authError.message || 'Failed to send reset email.');
    } else {
      setSuccess(true);
    }
    setLoading(false);
  };

  return (
    <div className="app-container">
      <ThemeToggle />
      <div className="left-pane">
        <div className="glass-surface auth-form" style={{ viewTransitionName: 'auth-form' }}>
          <div className="auth-header">
            <h1>Reset Password</h1>
            <p>Enter your email and we'll send a link to reset your password.</p>
          </div>

          {error && (
            <div className="auth-error" role="alert">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
              {error}
            </div>
          )}

          {success ? (
            <div className="auth-success" role="status">
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              <div>
                <strong>Check your email</strong>
                <p style={{ marginTop: '0.25rem', opacity: 0.8 }}>
                  We've sent a password reset link to <strong>{email}</strong>.
                </p>
              </div>
            </div>
          ) : (
            <form onSubmit={handleReset} className="input-group">
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
              <button type="submit" className="btn-primary" disabled={loading}>
                {loading ? 'Sending...' : 'Send Reset Link'}
              </button>
            </form>
          )}

          <div style={{ textAlign: 'center', marginTop: '1rem', fontSize: '0.95rem' }}>
            Remembered? <Link to="/" viewTransition style={{ color: 'var(--primary-color)', fontWeight: 600, textDecoration: 'none' }}>Back to Sign In</Link>
          </div>
        </div>
      </div>
      <SilkBackground />
    </div>
  );
};
