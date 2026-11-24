import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';
import { apiFetch } from '@/lib/api';
import { csrfHeaders } from '@/lib/csrf';

interface IntentStatusState {
  status: 'pending' | 'verified' | 'exhausted' | 'expired' | 'consumed';
  expiresAt: string;
  otpExpiresAt: string;
  resendAvailableAt: string;
  remainingAttempts: number;
}

function formatSeconds(sec: number): string {
  const s = Math.max(0, Math.floor(sec));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}:${rem.toString().padStart(2, '0')}`;
}

export const VerifyEmail: React.FC = () => {
  usePageTitle('Verify email code');
  const [searchParams] = useSearchParams();
  const intentId = searchParams.get('intentId') || '';
  const codeInputRef = useRef<HTMLInputElement>(null);
  const codeErrId = useId();

  const [mode, setMode] = useState<'loading' | 'disabled' | 'ready'>('loading');
  const [intentState, setIntentState] = useState<IntentStatusState | null>(null);
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [resending, setResending] = useState(false);
  const [nowMs, setNowMs] = useState(() => Date.now());

  const loadIntentStatus = useCallback(async () => {
    if (!intentId) {
      setStatusError('Missing verification session. Start registration again.');
      setMode('ready');
      return;
    }
    try {
      const cfgRes = await apiFetch('/api/identity/registration/config');
      const cfg = cfgRes.ok ? await cfgRes.json() : null;
      if (cfg?.registrationMode !== 'verified') {
        setMode('disabled');
        return;
      }
      const stRes = await apiFetch(`/api/identity/registration/intent/${encodeURIComponent(intentId)}`);
      if (!stRes.ok) {
        setStatusError('Verification session unavailable or expired. Start again with your email address.');
        setMode('ready');
        return;
      }
      const data = (await stRes.json()) as IntentStatusState;
      setIntentState(data);
      setMode('ready');
    } catch {
      setStatusError('Unable to load verification session status.');
      setMode('ready');
    }
  }, [intentId]);

  useEffect(() => {
    void loadIntentStatus();
  }, [loadIntentStatus]);

  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const otpSecondsLeft = intentState ? Math.max(0, Math.floor((new Date(intentState.otpExpiresAt).getTime() - nowMs) / 1000)) : 0;
  const resendSecondsLeft = intentState ? Math.max(0, Math.ceil((new Date(intentState.resendAvailableAt).getTime() - nowMs) / 1000)) : 0;
  const isExpired = intentState?.status === 'expired' || (intentState?.status === 'pending' && otpSecondsLeft <= 0);
  const isExhausted = intentState?.status === 'exhausted';
  const isVerified = intentState?.status === 'verified';

  const validateCodeSyntax = (raw: string): string | null => {
    const trimmed = raw.trim();
    if (!trimmed) return 'Enter the 6 digit code from your email.';
    if (!/^\d{6}$/.test(trimmed)) return 'Verification code must be 6 digits.';
    return null;
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusError(null);
    const err = validateCodeSyntax(code);
    setCodeError(err);
    if (err) {
      codeInputRef.current?.focus();
      return;
    }
    setVerifying(true);
    try {
      const res = await apiFetch('/api/identity/registration/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
        body: JSON.stringify({ intentId, code: code.trim() }),
      });
      const body = await res.json().catch(() => ({}));
      if (res.ok && body?.verified) {
        setIntentState((prev) => (prev ? { ...prev, status: 'verified' } : {
          status: 'verified',
          expiresAt: new Date(Date.now() + 600_000).toISOString(),
          otpExpiresAt: new Date(Date.now() + 600_000).toISOString(),
          resendAvailableAt: new Date().toISOString(),
          remainingAttempts: 0,
        }));
        return;
      }
      if (typeof body?.remainingAttempts === 'number') {
        setIntentState((prev) => prev ? {
          ...prev,
          remainingAttempts: body.remainingAttempts,
          status: body.remainingAttempts === 0 ? 'exhausted' : prev.status,
        } : prev);
      }
      if (res.status === 429) {
        const waitSec = typeof body?.retryAfterSeconds === 'number' ? body.retryAfterSeconds : 60;
        setStatusError(`Too many verification guesses. Wait ${waitSec} seconds before trying again.`);
        return;
      }
      if (body?.code === 'ERR_OTP_EXPIRED') {
        setIntentState((prev) => (prev ? { ...prev, status: 'expired' } : prev));
        setStatusError('Verification code expired. Request a new code or start over.');
        return;
      }
      setStatusError(body?.remainingAttempts === 0
        ? 'Maximum attempts reached for this code. Request a new verification code.'
        : 'Invalid or expired verification code.');
    } catch {
      setStatusError('Network error while checking your verification code.');
    } finally {
      setVerifying(false);
    }
  };

  const handleResend = async () => {
    if (!intentId || resending || resendSecondsLeft > 0) return;
    setResending(true);
    setStatusError(null);
    setCodeError(null);
    try {
      const res = await apiFetch('/api/identity/registration/resend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
        body: JSON.stringify({ intentId }),
      });
      const body = await res.json().catch(() => ({}));
      if (res.status === 202) {
        setCode('');
        await loadIntentStatus();
        return;
      }
      if (res.status === 429) {
        const waitSec = typeof body?.retryAfterSeconds === 'number' ? body.retryAfterSeconds : 60;
        setStatusError(`Wait ${waitSec} seconds before requesting another code.`);
        return;
      }
      if (res.status === 503) {
        setStatusError('Verification email delivery is temporarily unavailable.');
        return;
      }
      setStatusError('Unable to resend verification code. Start registration again.');
    } catch {
      setStatusError('Network error while resending verification code.');
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 sm:p-8 bg-background">
      <div className="w-full max-w-[440px]">
        <Card className="w-full shadow-xs border-border rounded-xl overflow-hidden">
          <CardContent className="p-6 sm:p-8 space-y-6">
            <div>
              <div className="flex items-center justify-between mb-4">
                <BrandMark size="default" />
                <span className="font-mono text-xs text-muted-foreground border border-border px-2.5 py-0.5 rounded-pill bg-secondary/50">
                  Email check
                </span>
              </div>
              <h1 className="font-heading text-2xl sm:text-[28px] leading-tight font-semibold text-foreground">
                {isVerified ? 'Email verified' : 'Check your email'}
              </h1>
            </div>

            {mode === 'loading' ? (
              <div className="py-8 flex flex-col items-center gap-3 text-muted-foreground" role="status">
                <div className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                <span className="font-sans text-xs">Loading verification state...</span>
              </div>
            ) : mode === 'disabled' ? (
              <div role="status" className="rounded-lg border border-border bg-secondary/40 p-4 text-xs text-muted-foreground space-y-3">
                <p className="font-semibold text-foreground">Registration unavailable</p>
                <p>New account verification is disabled.</p>
                <Button asChild variant="outline" className="w-full h-10"><Link to="/auth">Return to sign in</Link></Button>
              </div>
            ) : isVerified ? (
              <div className="space-y-4">
                <div role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-700 dark:text-emerald-300 space-y-1.5">
                  <p className="font-semibold">Mailbox ownership confirmed</p>
                  <p>Your one use verification proof is stored safely. Account credential creation is deferred to P2b; no account or session has been created.</p>
                </div>
                <Button asChild variant="outline" className="w-full h-10"><Link to="/auth">Return to sign in</Link></Button>
              </div>
            ) : (
              <form onSubmit={handleVerify} noValidate className="space-y-4">
                {intentState && !isExpired && !isExhausted && (
                  <div role="status" className="rounded-lg border border-border bg-secondary/40 px-4 py-2.5 text-xs text-muted-foreground">
                    <p className="font-medium text-foreground">Verification code sent</p>
                    <p className="mt-0.5">Code expires in {formatSeconds(otpSecondsLeft)}. Remaining attempts: {intentState.remainingAttempts}.</p>
                  </div>
                )}

                {(statusError || isExpired || isExhausted) && (
                  <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2.5 font-sans text-xs text-destructive">
                    {statusError || (isExhausted
                      ? 'Attempts exhausted for this code. Request a new code.'
                      : 'Verification code expired. Request a new code or start over.')}
                  </div>
                )}

                <div className="space-y-1.5">
                  <label htmlFor="verify-otp-code" className="font-sans text-xs font-medium text-foreground block">
                    6 digit verification code
                  </label>
                  <Input
                    ref={codeInputRef}
                    id="verify-otp-code"
                    name="code"
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    enterKeyHint="done"
                    maxLength={6}
                    value={code}
                    aria-invalid={codeError ? 'true' : 'false'}
                    aria-describedby={codeError ? codeErrId : undefined}
                    onChange={(e) => {
                      const next = e.target.value;
                      setCode(next);
                      if (codeError && !validateCodeSyntax(next)) setCodeError(null);
                    }}
                    onBlur={() => {
                      if (code.trim()) setCodeError(validateCodeSyntax(code));
                    }}
                    className="h-11 font-mono tracking-widest text-center text-base"
                  />
                  {codeError && (
                    <p id={codeErrId} role="alert" className="font-sans text-xs text-destructive">{codeError}</p>
                  )}
                </div>

                <Button type="submit" disabled={verifying || isExpired || isExhausted || !intentId} className="w-full h-10">
                  {verifying ? 'Verifying code...' : 'Verify code'}
                </Button>

                <div className="flex flex-col sm:flex-row items-center justify-between gap-2 pt-1 text-xs">
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={resending || resendSecondsLeft > 0 || !intentId}
                    onClick={() => void handleResend()}
                  >
                    {resendSecondsLeft > 0 ? `Resend available in ${resendSecondsLeft}s` : (resending ? 'Sending...' : 'Resend code')}
                  </Button>
                  <Link to="/register" className="font-sans text-muted-foreground hover:text-foreground underline-offset-4 hover:underline">
                    Use another email address
                  </Link>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
