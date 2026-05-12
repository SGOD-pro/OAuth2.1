import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';

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
      setTimeout(() => navigate('/auth', { viewTransition: true }), 3000);
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
        <div className="w-full px-8 py-10 text-left">
          <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">SWYRA</p>
          <h1 className="mt-3 text-2xl font-semibold text-foreground">Set a new password</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Choose a strong password you do not use elsewhere.
          </p>

          {error && (
            <div
              className="mt-6 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
              role="alert"
            >
              {error}
            </div>
          )}

          {success ? (
            <div className="mt-6 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-700">
              <strong>Password reset successfully!</strong>
              <p className="mt-1 text-xs text-emerald-700/80">
                Redirecting to sign in...
              </p>
            </div>
          ) : (
            <form onSubmit={handleReset} className="mt-6 space-y-4">
              <div className="space-y-2">
                <label htmlFor="password" className="text-sm font-medium text-foreground">
                  New password
                </label>
                <Input
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
              <div className="space-y-2">
                <label htmlFor="confirmPassword" className="text-sm font-medium text-foreground">
                  Confirm password
                </label>
                <Input
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
              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? 'Resetting...' : 'Reset password'}
              </Button>
            </form>
          )}

          <div className="my-6 flex items-center gap-4">
            <Separator className="flex-1" />
            <span className="text-[11px] uppercase tracking-[0.2em] text-muted-foreground">or</span>
            <Separator className="flex-1" />
          </div>

          <Link to="/auth" viewTransition className="text-sm text-muted-foreground hover:text-foreground">
            Back to sign in
          </Link>
        </div>
      </GlassSurface>
    </div>
  );
};
