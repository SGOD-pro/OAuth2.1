import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { authClient, useSession } from '@/lib/auth-client';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';

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
        navigate('/admin', { replace: true, viewTransition: true });
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
    navigate('/admin/login', { viewTransition: true });
    setLoading(false);
  };

  if (isPending) {
    return (
      <div className="w-full h-dvh px-6 grid place-items-center">
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

  const role = (session?.user as { role?: string })?.role;
  const isAuthenticated = !!session?.user;

  return (
    <div className="w-full h-dvh px-6 grid place-items-center">
      <GlassSurface
        width="100%"
        height="auto"
        borderRadius={28}
        backgroundOpacity={0.12}
        blur={12}
        saturation={1.6}
        className="w-full max-w-md mx-auto"
      >
        <div className="w-full px-8 py-10 text-left">
          <p className="text-xs uppercase tracking-[0.18em] text-chart-1">SWYRA Admin</p>
          <h1 className="mt-3 text-2xl font-semibold text-foreground">Admin login</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Access the SWYRA central administration panel.
          </p>

          {error && (
            <div
              className="mt-6 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
              role="alert"
            >
              {error}
            </div>
          )}

          {isAuthenticated && role !== 'admin' ? (
            <div className="mt-6 text-sm text-muted-foreground">
              <p className="mb-4">
                You are currently signed in as <strong className="text-foreground">{session.user.email}</strong>.
              </p>
              <Button onClick={handleSignOut} variant="outline" className="w-full" disabled={loading}>
                {loading ? 'Signing out...' : 'Sign out'}
              </Button>
            </div>
          ) : (
            <form onSubmit={handleSignIn} className="mt-6 space-y-4">
              <div className="space-y-2">
                <label htmlFor="email" className="text-sm font-medium text-foreground">
                  Email address
                </label>
                <Input
                  type="email"
                  id="email"
                  placeholder="admin@swyra.com"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={loading}
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="password" className="text-sm font-medium text-foreground">
                  Password
                </label>
                <Input
                  type="password"
                  id="password"
                  placeholder="••••••••"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loading}
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? 'Signing in...' : 'Sign in to admin'}
              </Button>
            </form>
          )}

          <div className="my-6 flex items-center gap-4">
            <Separator className="flex-1" />
            <span className="text-[11px] uppercase tracking-[0.2em] text-muted-foreground">secure</span>
            <Separator className="flex-1" />
          </div>

          <p className="text-xs text-muted-foreground text-center">
            Only users with the admin role can access this panel.
          </p>
        </div>
      </GlassSurface>
    </div>
  );
};
