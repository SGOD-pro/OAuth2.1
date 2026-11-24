import React, { useEffect, useId, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Eye, EyeOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';
import { apiFetch } from '@/lib/api';
import { csrfHeaders } from '@/lib/csrf';

const USERNAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$/;

function validateUsernameValue(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return 'Choose a username.';
  if (trimmed.includes('@') || trimmed.includes('..') || trimmed.endsWith('.') || !USERNAME_RE.test(trimmed)) {
    return 'Use 3 to 32 letters, numbers, dots, underscores, or hyphens starting with a letter or number.';
  }
  return null;
}

function validatePasswordValue(raw: string): string | null {
  if (!raw) return 'Enter a strong password.';
  if (raw.length < 12 || raw.length > 128) return 'Password must be 12 to 128 characters long.';
  if (!/[A-Z]/.test(raw) || !/[a-z]/.test(raw) || !/[0-9]/.test(raw) || !/[^A-Za-z0-9]/.test(raw)) {
    return 'Include uppercase, lowercase, a number, and a symbol.';
  }
  return null;
}

export const CompleteRegistration: React.FC = () => {
  usePageTitle('Complete registration');
  const usernameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const userHintId = useId();
  const userErrId = useId();
  const passHintId = useId();
  const passErrId = useId();

  const [modeLoading, setModeLoading] = useState(true);
  const [mode, setMode] = useState<'disabled' | 'verified'>('disabled');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [userError, setUserError] = useState<string | null>(null);
  const [passError, setPassError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [errorAction, setErrorAction] = useState<'register' | 'signin' | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [idempotencyKey, setIdempotencyKey] = useState(() =>
    typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : String(Date.now())
  );
  const [completed, setCompleted] = useState<{ username: string; sessionEstablished: boolean; requiresSignIn: boolean } | null>(null);

  useEffect(() => {
    let active = true;
    apiFetch('/api/identity/registration/config')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => { if (active) setMode(data?.registrationMode === 'verified' ? 'verified' : 'disabled'); })
      .catch(() => { if (active) setMode('disabled'); })
      .finally(() => { if (active) setModeLoading(false); });
    return () => { active = false; };
  }, []);

  const rotateKey = () => setIdempotencyKey(typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : String(Date.now()));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError(null);
    setErrorAction(null);
    const uErr = validateUsernameValue(username);
    const pErr = validatePasswordValue(password);
    setUserError(uErr);
    setPassError(pErr);
    if (uErr) { usernameRef.current?.focus(); return; }
    if (pErr) { passwordRef.current?.focus(); return; }

    setSubmitting(true);
    try {
      const res = await apiFetch('/api/identity/registration/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey, ...csrfHeaders() },
        body: JSON.stringify({ username: username.trim(), password, acceptedTermsVersion: 'v1' }),
      });
      const body = await res.json().catch(() => ({}));
      if (res.ok && body?.completed) {
        setPassword('');
        setCompleted({ username: body.user?.username || username.trim(), sessionEstablished: Boolean(body.sessionEstablished), requiresSignIn: Boolean(body.requiresSignIn) });
        return;
      }
      rotateKey();
      if (body?.code === 'ERR_USERNAME_TAKEN') {
        setUserError('That username is already taken. Choose a different username.');
        setSubmitError('That username is unavailable. Your email verification is still active so you can retry.');
        usernameRef.current?.focus();
        return;
      }
      if (body?.code === 'ERR_EMAIL_ALREADY_REGISTERED') {
        setSubmitError('An account with this verified email already exists.');
        setErrorAction('signin');
        return;
      }
      if (res.status === 400 || res.status === 403 || res.status === 409) {
        if (body?.code === 'ERR_WEAK_PASSWORD') {
          setPassError('Password must be 12 to 128 characters with uppercase, lowercase, number, and symbol.');
          passwordRef.current?.focus();
          return;
        }
        setSubmitError('Your email verification proof is missing, expired, or no longer valid. Start verification again.');
        setErrorAction('register');
        return;
      }
      setSubmitError('Unable to finish creating your account right now. Please try submitting again.');
    } catch {
      setSubmitError('Network error while completing registration. You can safely retry.');
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
                  Step 2 of 2
                </span>
              </div>
              <h1 className="font-heading text-2xl sm:text-[28px] leading-tight font-semibold text-foreground">
                {completed ? 'Account created' : 'Create your profile'}
              </h1>
              <p className="font-sans text-xs text-muted-foreground mt-1.5">
                {completed
                  ? 'Your verified account credentials are active.'
                  : 'Choose a unique username and password to activate your verified account.'}
              </p>
            </div>

            {modeLoading ? (
              <div className="py-8 flex flex-col items-center gap-3 text-muted-foreground" role="status">
                <div className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                <span className="font-sans text-xs">Loading registration settings...</span>
              </div>
            ) : mode === 'disabled' ? (
              <div role="status" className="rounded-lg border border-border bg-secondary/40 p-4 text-xs text-muted-foreground space-y-3">
                <p className="font-semibold text-foreground">Registration unavailable</p>
                <p>New account registration is currently disabled by operator configuration.</p>
                <Button asChild variant="outline" className="w-full h-10"><Link to="/auth">Return to sign in</Link></Button>
              </div>
            ) : completed ? (
              <div className="space-y-4">
                <div role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-700 dark:text-emerald-300 space-y-1.5">
                  <p className="font-semibold">Welcome, {completed.username}</p>
                  <p>
                    {completed.requiresSignIn
                      ? 'Your verified account was created, but we could not start a session automatically. Sign in with your email and password to continue.'
                      : 'Your verified account and ordinary sign in session are ready.'}
                  </p>
                </div>
                <Button asChild className="w-full h-10"><Link to="/auth">Continue to sign in</Link></Button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} noValidate className="space-y-4">
                {submitError && (
                  <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2.5 font-sans text-xs text-destructive space-y-1.5">
                    <p>{submitError}</p>
                    {errorAction === 'register' && (
                      <Link to="/register" className="underline font-medium inline-block text-foreground">Restart email verification</Link>
                    )}
                    {errorAction === 'signin' && (
                      <Link to="/auth" className="underline font-medium inline-block text-foreground">Go to sign in</Link>
                    )}
                  </div>
                )}

                <div className="space-y-1.5">
                  <label htmlFor="complete-username" className="font-sans text-xs font-medium text-foreground block">
                    Username
                  </label>
                  <Input
                    ref={usernameRef}
                    id="complete-username"
                    name="username"
                    type="text"
                    autoComplete="username"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    enterKeyHint="next"
                    required
                    value={username}
                    aria-invalid={userError ? 'true' : 'false'}
                    aria-describedby={[userHintId, userError ? userErrId : null].filter(Boolean).join(' ')}
                    onChange={(e) => {
                      const next = e.target.value;
                      setUsername(next);
                      if (userError && !validateUsernameValue(next)) setUserError(null);
                    }}
                    onBlur={() => {
                      if (username.trim()) setUserError(validateUsernameValue(username));
                    }}
                    className="h-10"
                  />
                  <p id={userHintId} className="font-sans text-[11px] text-muted-foreground">
                    3 to 32 characters using letters, numbers, dots, underscores, or hyphens.
                  </p>
                  {userError && <p id={userErrId} role="alert" className="font-sans text-xs text-destructive">{userError}</p>}
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="complete-password" className="font-sans text-xs font-medium text-foreground block">
                    Password
                  </label>
                  <div className="relative">
                    <Input
                      ref={passwordRef}
                      id="complete-password"
                      name="password"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      enterKeyHint="done"
                      required
                      value={password}
                      aria-invalid={passError ? 'true' : 'false'}
                      aria-describedby={[passHintId, passError ? passErrId : null].filter(Boolean).join(' ')}
                      onChange={(e) => {
                        const next = e.target.value;
                        setPassword(next);
                        if (passError && !validatePasswordValue(next)) setPassError(null);
                      }}
                      onBlur={() => {
                        if (password) setPassError(validatePasswordValue(password));
                      }}
                      className="h-10 pr-10"
                    />
                    <button
                      type="button"
                      aria-pressed={showPassword}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      onClick={() => setShowPassword((v) => !v)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-1 rounded"
                    >
                      {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                    </button>
                  </div>
                  <p id={passHintId} className="font-sans text-[11px] text-muted-foreground">
                    12 to 128 characters including uppercase, lowercase, number, and symbol.
                  </p>
                  {passError && <p id={passErrId} role="alert" className="font-sans text-xs text-destructive">{passError}</p>}
                </div>

                <Button type="submit" disabled={submitting} className="w-full h-10">
                  {submitting ? 'Creating account...' : 'Complete registration'}
                </Button>

                <div className="text-center pt-1">
                  <Link to="/register" className="font-sans text-xs text-muted-foreground hover:text-foreground underline-offset-4 hover:underline">
                    Start over with another email
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
