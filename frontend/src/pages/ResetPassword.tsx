import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { SilkBackground } from '../components/SilkBackground';
import { ThemeToggle } from '../components/ThemeToggle';
import { authClient } from '../lib/auth-client';

export const ResetPassword: React.FC = () => {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const handleReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      setLoading(false);
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters.');
      setLoading(false);
      return;
    }

    const token = searchParams.get('token');
    if (!token) {
      setError('Invalid or expired reset link.');
      setLoading(false);
      return;
    }

    const { error: authError } = await authClient.resetPassword({
      newPassword: password,
      token,
    });

    if (authError) {
      setError(authError.message || 'Failed to reset password.');
    } else {
      setSuccess(true);
      setTimeout(() => navigate('/'), 3000);
    }
    setLoading(false);
  };

  return (
    <div className="app-container">
      <ThemeToggle />
      <div className="left-pane">
        <div className="glass-surface auth-form" style={{ viewTransitionName: 'auth-form' }}>
          <div className="auth-header">
            <h1>New Password</h1>
            <p>Enter your new password below.</p>
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
                <strong>Password reset successfully!</strong>
                <p style={{ marginTop: '0.25rem', opacity: 0.8 }}>
                  Redirecting to sign in...
                </p>
              </div>
            </div>
          ) : (
            <form onSubmit={handleReset} className="input-group">
              <div className="input-group">
                <label htmlFor="password">New Password</label>
                <input
                  type="password"
                  id="password"
                  placeholder="••••••••"
                  required
                  minLength={8}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loading}
                />
              </div>
              <div className="input-group" style={{ marginTop: '1rem' }}>
                <label htmlFor="confirmPassword">Confirm Password</label>
                <input
                  type="password"
                  id="confirmPassword"
                  placeholder="••••••••"
                  required
                  minLength={8}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={loading}
                />
              </div>
              <button type="submit" className="btn-primary" disabled={loading}>
                {loading ? 'Resetting...' : 'Reset Password'}
              </button>
            </form>
          )}

          <div style={{ textAlign: 'center', marginTop: '1rem', fontSize: '0.95rem' }}>
            <Link to="/" viewTransition style={{ color: 'var(--primary-color)', fontWeight: 600, textDecoration: 'none' }}>Back to Sign In</Link>
          </div>
        </div>
      </div>
      <SilkBackground />
    </div>
  );
};
