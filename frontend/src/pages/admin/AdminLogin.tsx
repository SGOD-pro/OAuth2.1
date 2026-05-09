import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { SilkBackground } from '../../components/SilkBackground';
import { ThemeToggle } from '../../components/ThemeToggle';
import { authClient, useSession } from '../../lib/auth-client';

export const AdminLogin: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const { data: session, isPending } = useSession();

  useEffect(() => {
    if (searchParams.get('error') === 'access_denied') {
      setError('Your account does not have admin access.');
    }
  }, [searchParams]);

  useEffect(() => {
    if (!isPending && session?.user) {
      const role = (session.user as { role?: string }).role;
      if (role === 'admin') {
        navigate('/admin', { replace: true });
      }
    }
  }, [session, isPending, navigate]);

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const { error: authError } = await authClient.signIn.email({
      email,
      password,
      callbackURL: '/admin',
    });

    if (authError) {
      setError(authError.message || 'Invalid credentials');
      setLoading(false);
    }
  };

  const handleSignOut = async () => {
    setLoading(true);
    await authClient.signOut();
    navigate('/admin/login');
    setLoading(false);
  };

  if (isPending) {
    return (
      <div className="app-container">
        <SilkBackground />
      </div>
    );
  }

  const role = (session?.user as { role?: string })?.role;
  const isAuthenticated = !!session?.user;

  return (
    <div className="app-container">
      <ThemeToggle />
      <div className="left-pane">
        <div className="glass-surface auth-form" style={{ viewTransitionName: 'auth-form' }}>
          <div className="auth-header">
            <h1>Admin Login</h1>
            <p>Access the SWYRA central administration panel.</p>
          </div>

          {error && (
            <div className="auth-error" role="alert">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
              {error}
            </div>
          )}

          {isAuthenticated && role !== 'admin' ? (
            <div style={{ textAlign: 'center', marginTop: '1rem' }}>
              <p style={{ marginBottom: '1.5rem', color: 'var(--text-secondary)' }}>
                You are currently signed in as <strong>{session.user.email}</strong>.
              </p>
              <button onClick={handleSignOut} className="btn-secondary" disabled={loading} style={{ width: '100%' }}>
                {loading ? 'Signing out...' : 'Sign Out'}
              </button>
            </div>
          ) : (
            <form onSubmit={handleSignIn} className="input-group">
              <div className="input-group">
                <label htmlFor="email">Email</label>
                <input
                  type="email"
                  id="email"
                  placeholder="admin@swyra.com"
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
              <button type="submit" className="btn-primary" disabled={loading} style={{ marginTop: '1.5rem' }}>
                {loading ? 'Signing in...' : 'Sign In to Admin'}
              </button>
            </form>
          )}
        </div>
      </div>
      <SilkBackground />
    </div>
  );
};
