import React, { useState, useEffect, useRef } from 'react';
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
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const focusInput = () => {
      inputRef.current?.focus();
    };
    focusInput();
    const timer = setTimeout(focusInput, 60);
    return () => clearTimeout(timer);
  }, [mode]);

  const getAuthRedirect = (errorVal: string) => {
    const params = new URLSearchParams(searchParams);
    params.set('error', errorVal);
    return `/auth?${params.toString()}`;
  };

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
          const errCode = (err as { code?: string })?.code;
          const errMsg = err.message || 'Invalid 6 digit code. Check your authenticator app.';
          const isExpired = errCode === 'INVALID_TWO_FACTOR_COOKIE' ||
                            errMsg.toLowerCase().includes('cookie') ||
                            errMsg.toLowerCase().includes('session') ||
                            errMsg.toLowerCase().includes('expired');
          const isRateLimited = err.status === 429 || errCode === 'ACCOUNT_TEMPORARILY_LOCKED';

          if (isRateLimited) {
            setError('Too many verification attempts. Please wait before trying again.');
            toast.error('Too many attempts. Account temporarily locked.');
            return;
          }

          if (isExpired) {
            setError('Verification challenge expired. Please sign in again.');
            toast.error('Verification challenge expired. Please sign in again.');
            setTimeout(() => {
              navigate(getAuthRedirect('mfa_expired'), { replace: true });
            }, 1200);
            return;
          }

          const nextFail = failedAttempts + 1;
          setFailedAttempts(nextFail);
          setError(errMsg);
          toast.error(errMsg);

          if (nextFail >= 3 || errCode === 'TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE') {
            toast.error('Too many failed attempts. Please sign in again.');
            setTimeout(() => {
              navigate(getAuthRedirect('mfa_failed'), { replace: true });
            }, 1200);
          }
          return;
        }
      } else {
        const { error: err } = await authClient.twoFactor.verifyBackupCode({ code: trimmedCode });
        if (err) {
          const errCode = (err as { code?: string })?.code;
          const errMsg = err.message || 'Invalid recovery code.';
          const isExpired = errCode === 'INVALID_TWO_FACTOR_COOKIE' ||
                            errMsg.toLowerCase().includes('cookie') ||
                            errMsg.toLowerCase().includes('session') ||
                            errMsg.toLowerCase().includes('expired');
          const isRateLimited = err.status === 429 || errCode === 'ACCOUNT_TEMPORARILY_LOCKED';

          if (isRateLimited) {
            setError('Too many verification attempts. Please wait before trying again.');
            toast.error('Too many attempts. Account temporarily locked.');
            return;
          }

          if (isExpired) {
            setError('Verification challenge expired. Please sign in again.');
            toast.error('Verification challenge expired. Please sign in again.');
            setTimeout(() => {
              navigate(getAuthRedirect('mfa_expired'), { replace: true });
            }, 1200);
            return;
          }

          const nextFail = failedAttempts + 1;
          setFailedAttempts(nextFail);
          setError(errMsg);
          toast.error(errMsg);

          if (nextFail >= 3 || errCode === 'TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE') {
            toast.error('Too many failed attempts. Please sign in again.');
            setTimeout(() => {
              navigate(getAuthRedirect('mfa_failed'), { replace: true });
            }, 1200);
          }
          return;
        }
      }

      // Check for OAuth continuation parameters
      const clientId = searchParams.get('client_id');
      const redirectUri = searchParams.get('redirect_uri');

      if (clientId && redirectUri) {
        const oauthParams = new URLSearchParams(searchParams);
        oauthParams.delete('prompt');
        window.location.assign(`/api/auth/oauth2/authorize?${oauthParams.toString()}`);
        return;
      }

      const explicitCallback = searchParams.get('callbackURL');
      if (explicitCallback) {
        const validated = safeCallbackURL(explicitCallback);
        if (validated && !validated.startsWith('/admin') && !validated.startsWith('/api/admin')) {
          window.location.assign(validated);
          return;
        }
      }

      window.location.assign('/admin');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Verification failed.';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const toggleMode = () => {
    setMode((m) => (m === 'totp' ? 'backup' : 'totp'));
    setCode('');
    setError(null);
  };

  const handleBackToSignIn = async () => {
    await authClient.signOut({}).catch(() => undefined);
    navigate(getAuthRedirect('mfa_cancelled'));
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 sm:p-6 bg-background relative">
      <div className="fixed top-4 right-4 z-50">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-[420px]">
        <Card className="w-full border border-border bg-card shadow-xs rounded-xl overflow-hidden">
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
              <div role="alert" className="mb-4 rounded-lg border border-destructive/20 bg-destructive/10 p-3.5 font-sans text-xs text-destructive flex items-center gap-2.5">
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
                  ref={inputRef}
                  type="text"
                  inputMode={mode === 'totp' ? 'numeric' : 'text'}
                  pattern={mode === 'totp' ? '[0-9]*' : undefined}
                  autoComplete={mode === 'totp' ? 'one-time-code' : 'off'}
                  autoFocus
                  placeholder={mode === 'totp' ? '123456' : 'Enter recovery code'}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  disabled={loading}
                  className={mode === 'totp' ? 'font-mono text-center tracking-[0.35em] text-xl h-12' : 'font-mono text-center text-sm h-11'}
                />
              </div>

              <Button
                type="submit"
                className="w-full h-11 font-medium rounded-pill mt-2"
                disabled={loading || !code.trim()}
              >
                {loading ? 'Verifying...' : 'Verify and continue'}
              </Button>
            </form>

            <div className="mt-6 flex flex-col items-center gap-2 pt-4 border-t border-border/60">
              <button
                type="button"
                onClick={toggleMode}
                className="font-sans text-xs text-muted-foreground hover:text-foreground transition-colors underline underline-offset-4 cursor-pointer"
              >
                {mode === 'totp' ? 'Use recovery backup code instead' : 'Use authenticator code instead'}
              </button>

              <button
                type="button"
                onClick={handleBackToSignIn}
                className="font-sans text-xs text-muted-foreground hover:text-foreground transition-colors mt-1 cursor-pointer"
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
