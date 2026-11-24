import React, { useEffect, useId, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { Card, CardContent } from '@/components/ui/card';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';
import { apiFetch } from '@/lib/api';
import { csrfHeaders } from '@/lib/csrf';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export const Register: React.FC = () => {
  usePageTitle('Create verified account');
  const navigate = useNavigate();
  const emailRef = useRef<HTMLInputElement>(null);
  const termsRef = useRef<HTMLButtonElement>(null);
  const emailHintId = useId();
  const emailErrId = useId();

  const [modeLoading, setModeLoading] = useState(true);
  const [mode, setMode] = useState<'disabled' | 'verified'>('disabled');
  const [email, setEmail] = useState('');
  const [emailTouched, setEmailTouched] = useState(false);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [idempotencyKey] = useState(() =>
    typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : String(Date.now())
  );

  useEffect(() => {
    let active = true;
    apiFetch('/api/identity/registration/config')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!active) return;
        setMode(data?.registrationMode === 'verified' ? 'verified' : 'disabled');
      })
      .catch(() => {
        if (active) setMode('disabled');
      })
      .finally(() => {
        if (active) setModeLoading(false);
      });
    return () => { active = false; };
  }, []);

  const validateEmailValue = (raw: string): string | null => {
    const trimmed = raw.trim();
    if (!trimmed) return 'Enter your email address.';
    if (!EMAIL_RE.test(trimmed)) return 'Enter an email address like name@example.com.';
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError(null);
    const err = validateEmailValue(email);
    setEmailTouched(true);
    setEmailError(err);
    if (err) {
      emailRef.current?.focus();
      return;
    }
    if (!termsAccepted) {
      setSubmitError('Accept the terms of service before requesting a verification code.');
      termsRef.current?.focus();
      return;
    }

    setSubmitting(true);
    try {
      const res = await apiFetch('/api/identity/registration/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey,
          ...csrfHeaders(),
        },
        body: JSON.stringify({
          email: email.trim(),
          acceptedTermsVersion: 'v1',
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (res.status === 202 && body?.intentId) {
        navigate(`/register/verify?intentId=${encodeURIComponent(body.intentId)}`);
        return;
      }
      if (res.status === 429) {
        const waitSec = typeof body?.retryAfterSeconds === 'number' ? body.retryAfterSeconds : 60;
        setSubmitError(`Too many code requests right now. Wait ${waitSec} seconds and try again.`);
        return;
      }
      if (res.status === 503) {
        setSubmitError('Verification email delivery is temporarily unavailable. Please try again shortly.');
        return;
      }
      setSubmitError('Unable to start email verification right now. Check your details and try again.');
    } catch {
      setSubmitError('Network error while contacting the identity server.');
    } finally {
      setSubmitting(false);
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
                  Step 1 of 2
                </span>
              </div>
              <h1 className="font-heading text-2xl sm:text-[28px] leading-tight font-semibold text-foreground">
                Verify your email
              </h1>
              <p className="font-sans text-xs text-muted-foreground mt-1.5">
                Confirm ownership of your email address before setting up account credentials.
              </p>
            </div>

            {modeLoading ? (
              <div className="py-8 flex flex-col items-center gap-3 text-muted-foreground" role="status">
                <div className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                <span className="font-sans text-xs">Checking registration availability...</span>
              </div>
            ) : mode === 'disabled' ? (
              <div className="space-y-4">
                <div role="status" className="rounded-lg border border-border bg-secondary/40 p-4 text-xs text-muted-foreground space-y-1.5">
                  <p className="font-semibold text-foreground">Registration unavailable</p>
                  <p>New account registration is currently disabled by operator configuration.</p>
                </div>
                <Button asChild variant="outline" className="w-full h-10">
                  <Link to="/auth">Return to sign in</Link>
                </Button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} noValidate className="space-y-4">
                {submitError && (
                  <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2.5 font-sans text-xs text-destructive">
                    {submitError}
                  </div>
                )}

                <div className="space-y-1.5">
                  <label htmlFor="reg-email" className="font-sans text-xs font-medium text-foreground block">
                    Email address
                  </label>
                  <Input
                    ref={emailRef}
                    id="reg-email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    enterKeyHint="next"
                    required
                    value={email}
                    aria-invalid={emailError ? 'true' : 'false'}
                    aria-describedby={[emailHintId, emailError ? emailErrId : null].filter(Boolean).join(' ')}
                    onChange={(e) => {
                      const next = e.target.value;
                      setEmail(next);
                      if (emailError && !validateEmailValue(next)) setEmailError(null);
                    }}
                    onBlur={() => {
                      setEmailTouched(true);
                      setEmailError(validateEmailValue(email));
                    }}
                    className="h-10"
                  />
                  <p id={emailHintId} className="font-sans text-[11px] text-muted-foreground">
                    We send a 6 digit verification code that expires in 5 minutes. No account exists yet.
                  </p>
                  {emailTouched && emailError && (
                    <p id={emailErrId} role="alert" className="font-sans text-xs text-destructive">
                      {emailError}
                    </p>
                  )}
                </div>

                <label className="flex items-start gap-2.5 cursor-pointer text-xs text-muted-foreground pt-1">
                  <Checkbox
                    ref={termsRef}
                    data-testid="terms-checkbox"
                    checked={termsAccepted}
                    onCheckedChange={(checked) => {
                      setTermsAccepted(checked === true);
                      if (checked === true) setSubmitError(null);
                    }}
                  />
                  <span>I accept the platform terms of service and privacy notice.</span>
                </label>

                <Button type="submit" disabled={submitting} className="w-full h-10">
                  {submitting ? 'Sending verification code...' : 'Send verification code'}
                </Button>

                <div className="text-center pt-1">
                  <Link to="/auth" className="font-sans text-xs text-muted-foreground hover:text-foreground underline-offset-4 hover:underline">
                    Already have an account? Sign in
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
