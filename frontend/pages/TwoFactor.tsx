import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { safeCallbackURL } from '@/lib/security';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { toast } from 'sonner';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';
import { ThemeToggle } from '@/components/ThemeToggle';

type Mode = 'totp' | 'backup';

export const TwoFactor: React.FC = () => {
  usePageTitle('Two factor authentication');

  const [code, setCode] = useState('');
  const [mode, setMode] = useState<Mode>('totp');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  // If already authenticated with an active session, automatically resume continuation
  useEffect(() => {
    const getSessionFn = authClient.getSession as unknown as () => Promise<{
      data?: { user?: Record<string, unknown> } | null;
    }>;
    getSessionFn().then((res) => {
      if (res?.data?.user) {
        if (searchParams.get('client_id') && searchParams.get('redirect_uri')) {
          window.location.assign(`/api/auth/oauth2/authorize?${searchParams.toString()}`);
        }
      }
    }).catch(() => {});
  }, [searchParams]);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedCode = code.trim();
    if (!trimmedCode) return;
    setLoading(true);
    setError(null);

    try {
      if (mode === 'totp') {
        const { error: err } = await authClient.twoFactor.verifyTotp({ code: trimmedCode });
        if (err) {
          const errMsg = err.message || 'Invalid 6 digit code. Check your authenticator app.';
          setError(errMsg);
          toast.error(errMsg);
          const nextFail = failedAttempts + 1;
          setFailedAttempts(nextFail);

          if (nextFail >= 3 || err.status === 401 || err.status === 403 || errMsg.toLowerCase().includes('session')) {
            toast.error('Verification session expired. Please sign in again.');
            setTimeout(() => {
              navigate(`/auth?${searchParams.toString()}&error=mfa_failed`, { replace: true });
            }, 1200);
          }
          return;
        }
      } else {
        const { error: err } = await authClient.twoFactor.verifyBackupCode({ code: trimmedCode });
        if (err) {
          const errMsg = err.message || 'Invalid recovery code.';
          setError(errMsg);
          toast.error(errMsg);
          const nextFail = failedAttempts + 1;
          setFailedAttempts(nextFail);

          if (nextFail >= 3 || err.status === 401 || err.status === 403 || errMsg.toLowerCase().includes('session')) {
            toast.error('Verification session expired. Please sign in again.');
            setTimeout(() => {
              navigate(`/auth?${searchParams.toString()}&error=mfa_failed`, { replace: true });
            }, 1200);
          }
          return;
        }
      }

      toast.success('Two factor authentication verified');

      // 1. Authoritative OAuth continuation takes strict precedence
      if (searchParams.get('client_id') && searchParams.get('redirect_uri')) {
        window.location.assign(`/api/auth/oauth2/authorize?${searchParams.toString()}`);
        return;
      }

      // 2. Otherwise check explicit callbackURL, strictly rejecting platform administrator routes
      const rawCallback = searchParams.get('callbackURL');
      if (rawCallback) {
        const safe = safeCallbackURL(rawCallback);
        if (safe && !safe.startsWith('/admin') && !safe.startsWith('/api/admin')) {
          window.location.assign(safe);
          return;
        }
      }

      // 3. Fallback to application home
      window.location.assign('/');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network error validating code';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const toggleMode = () => {
    setCode('');
    setError(null);
    setMode((m) => (m === 'totp' ? 'backup' : 'totp'));
  };

  const handleBackToSignIn = async () => {
    await authClient.signOut({}).catch(() => {});
    navigate(`/auth?${searchParams.toString()}`);
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 sm:p-6 bg-background relative">
      <div className="fixed top-4 right-4 z-50">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-[420px]">
        <Card className="w-full border border-border bg-card shadow-sm">
          <CardContent className="p-6 sm:p-8">
            <div className="mb-6">
              <BrandMark />
            </div>

            <div className="mb-6">
              <h1 className="font-heading text-2xl font-semibold text-foreground tracking-tight">
                {mode === 'totp' ? 'Two factor authentication' : 'Recovery code'}
              </h1>
              <p className="font-sans text-xs text-muted-foreground mt-1">
                {mode === 'totp'
                  ? 'Enter the 6 digit code generated by your authenticator app.'
                  : 'Enter one of your saved single use recovery codes.'}
              </p>
            </div>

            {error && (
              <div className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 p-3 font-sans text-xs text-destructive flex items-center gap-2">
                <svg className="size-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleVerify} className="space-y-4">
              <div className="space-y-1.5">
                <label className="font-sans text-xs font-medium text-foreground">
                  {mode === 'totp' ? 'Verification Code' : 'Recovery Code'}
                </label>
                <Input
                  type="text"
                  inputMode={mode === 'totp' ? 'numeric' : 'text'}
                  autoComplete={mode === 'totp' ? 'one-time-code' : 'off'}
                  autoFocus
                  placeholder={mode === 'totp' ? '123456' : 'Enter recovery code'}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  disabled={loading}
                  className="font-mono text-center tracking-widest text-base h-11"
                />
              </div>

              <Button
                type="submit"
                className="w-full h-10 font-sans text-xs font-medium"
                disabled={loading || !code.trim()}
              >
                {loading ? 'Verifying...' : 'Verify and continue'}
              </Button>
            </form>

            <div className="mt-6 flex flex-col items-center gap-2">
              <button
                type="button"
                onClick={toggleMode}
                className="font-sans text-xs text-muted-foreground hover:text-foreground transition-colors underline underline-offset-4"
              >
                {mode === 'totp' ? 'Use recovery backup code instead' : 'Use authenticator code instead'}
              </button>

              <button
                type="button"
                onClick={handleBackToSignIn}
                className="font-sans text-xs text-muted-foreground hover:text-foreground transition-colors mt-2"
              >
                Return to sign in
              </button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
