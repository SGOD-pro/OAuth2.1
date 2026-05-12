import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';

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
    <div className="w-full max-w-3xl px-6">
      <GlassSurface
        width="100%"
        height="auto"
        borderRadius={28}
        backgroundOpacity={0.14}
        blur={12}
        saturation={1.6}
        className="w-full max-w-md mx-auto"
      >
        <div className="w-full px-8 py-10 text-center">
          <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">SWYRA</p>
          <h1 className="mt-3 text-2xl font-semibold text-foreground">Forgot password?</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Enter your email to receive a reset link.
          </p>

          {error && (
            <div
              className="mt-6 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive text-left"
              role="alert"
            >
              {error}
            </div>
          )}

          {success ? (
            <div className="mt-6 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-700 text-left">
              <strong>Check your email</strong>
              <p className="mt-1 text-xs text-emerald-700/80">
                We've sent a password reset link to <strong>{email}</strong>.
              </p>
            </div>
          ) : (
            <form onSubmit={handleReset} className="mt-6 space-y-4 text-left">
              <div className="space-y-2">
                <label htmlFor="email" className="text-sm font-medium text-foreground">
                  Email address
                </label>
                <Input
                  type="email"
                  id="email"
                  placeholder="Enter your email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={loading}
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? 'Sending...' : 'Send reset link'}
              </Button>
            </form>
          )}

          <div className="my-6 flex items-center gap-4">
            <Separator className="flex-1" />
            <span className="text-[11px] uppercase tracking-[0.2em] text-muted-foreground">or</span>
            <Separator className="flex-1" />
          </div>

          <Link to="/auth" viewTransition className="text-sm text-muted-foreground hover:text-foreground">
            Back to login
          </Link>
        </div>
      </GlassSurface>
    </div>
  );
};
