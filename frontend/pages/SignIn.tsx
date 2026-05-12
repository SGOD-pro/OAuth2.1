import React, { useCallback, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';

type SignInFormProps = {
  email: string;
  password: string;
  error: string;
  loading: boolean;
  onEmailChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onSubmit: (event: React.FormEvent) => void;
  onGoogle: () => void;
};

const SignInForm = React.memo(({
  email,
  password,
  error,
  loading,
  onEmailChange,
  onPasswordChange,
  onSubmit,
  onGoogle,
}: SignInFormProps) => (
  <TabsContent value="sign-in" className="mt-6">
    {error && (
      <div
        className="mb-4 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
        role="alert"
      >
        {error}
      </div>
    )}

    <form onSubmit={onSubmit} className="space-y-4">
      <div className="space-y-2">
        <label htmlFor="email" className="text-sm font-medium text-foreground">
          Email address
        </label>
        <Input
          type="email"
          id="email"
          placeholder="swyra@example.com"
          required
          value={email}
          onChange={(e) => onEmailChange(e.target.value)}
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
          onChange={(e) => onPasswordChange(e.target.value)}
          disabled={loading}
        />
      </div>

      <div className="flex items-center justify-between text-sm">
        <label className="flex items-center gap-2 text-muted-foreground">
          <Checkbox disabled={loading} id="remember" />
          Remember me
        </label>
        <Link to="/forgot-password" viewTransition className="text-primary hover:underline">
          Forgot password?
        </Link>
      </div>

      <Button type="submit" className="w-full" disabled={loading}>
        {loading ? 'Signing in...' : 'Sign in'}
      </Button>
    </form>

    <div className="my-6 flex items-center gap-4">
      <Separator className="flex-1" />
      <span className="text-xs uppercase tracking-widest text-muted-foreground">or</span>
      <Separator className="flex-1" />
    </div>

    <Button type="button" variant="outline" className="w-full" onClick={onGoogle} disabled={loading}>
      <svg className="h-4 w-4" viewBox="0 0 48 48" aria-hidden="true">
        <path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8c-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C12.955 4 4 12.955 4 24s8.955 20 20 20s20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z" />
        <path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C16.318 4 9.656 8.337 6.306 14.691z" />
        <path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238A11.91 11.91 0 0 1 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z" />
        <path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 0 1-4.087 5.571l.003-.002l6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z" />
      </svg>
      Continue with Google
    </Button>
  </TabsContent>
));

type SignUpFormProps = {
  name: string;
  email: string;
  password: string;
  error: string;
  loading: boolean;
  onNameChange: (value: string) => void;
  onEmailChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onSubmit: (event: React.FormEvent) => void;
  onGoogle: () => void;
};

const SignUpForm = React.memo(({
  name,
  email,
  password,
  error,
  loading,
  onNameChange,
  onEmailChange,
  onPasswordChange,
  onSubmit,
  onGoogle,
}: SignUpFormProps) => (
  <TabsContent value="sign-up" className="mt-6">
    {error && (
      <div
        className="mb-4 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
        role="alert"
      >
        {error}
      </div>
    )}

    <form onSubmit={onSubmit} className="space-y-4">
      <div className="space-y-2">
        <label htmlFor="name" className="text-sm font-medium text-foreground">
          Full name
        </label>
        <Input
          type="text"
          id="name"
          placeholder="John Doe"
          required
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          disabled={loading}
        />
      </div>
      <div className="space-y-2">
        <label htmlFor="signup-email" className="text-sm font-medium text-foreground">
          Email address
        </label>
        <Input
          type="email"
          id="signup-email"
          placeholder="swyra@example.com"
          required
          value={email}
          onChange={(e) => onEmailChange(e.target.value)}
          disabled={loading}
        />
      </div>
      <div className="space-y-2">
        <label htmlFor="signup-password" className="text-sm font-medium text-foreground">
          Password
        </label>
        <Input
          type="password"
          id="signup-password"
          placeholder="••••••••"
          required
          minLength={8}
          value={password}
          onChange={(e) => onPasswordChange(e.target.value)}
          disabled={loading}
        />
      </div>

      <Button type="submit" className="w-full" disabled={loading}>
        {loading ? 'Creating account...' : 'Create account'}
      </Button>
    </form>

    <div className="my-6 flex items-center gap-4">
      <Separator className="flex-1" />
      <span className="text-xs uppercase tracking-widest text-muted-foreground">or</span>
      <Separator className="flex-1" />
    </div>

    <Button type="button" variant="outline" className="w-full" onClick={onGoogle} disabled={loading}>
      <svg className="h-4 w-4" viewBox="0 0 48 48" aria-hidden="true">
        <path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8c-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C12.955 4 4 12.955 4 24s8.955 20 20 20s20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z" />
        <path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C16.318 4 9.656 8.337 6.306 14.691z" />
        <path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238A11.91 11.91 0 0 1 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z" />
        <path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 0 1-4.087 5.571l.003-.002l6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z" />
      </svg>
      Continue with Google
    </Button>
  </TabsContent>
));

export const SignIn: React.FC = () => {
  const [tab, setTab] = useState('sign-in');
  const [signUpName, setSignUpName] = useState('');
  const [signUpEmail, setSignUpEmail] = useState('');
  const [signUpPassword, setSignUpPassword] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [signUpError, setSignUpError] = useState('');
  const [loading, setLoading] = useState(false);
  const [searchParams] = useSearchParams();

  const callbackURL = useMemo(
    () => searchParams.get('callbackURL') ?? undefined,
    [searchParams]
  );

  const handleSignIn = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const { error: authError } = await authClient.signIn.email({
      email,
      password,
      // callbackURL is supplied by the consuming app via the OAuth flow.
      // Better Auth will redirect back to the consuming app after sign-in.
      callbackURL,
    });

    if (authError) {
      setError(authError.message || 'Sign in failed. Please try again.');
      setLoading(false);
    }
    // On success, Better Auth handles the redirect back to the consuming app.
    // Do NOT navigate anywhere manually — this is a passport office, not an app.
  }, [callbackURL, email, password]);

  const handleGoogleSignIn = useCallback(async () => {
    setLoading(true);
    setError('');
    await authClient.signIn.social({
      provider: 'google',
      callbackURL,
    });
  }, [callbackURL]);

  const handleSignUp = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setSignUpError('');

    const { error: authError } = await authClient.signUp.email({
      email: signUpEmail,
      password: signUpPassword,
      name: signUpName,
      callbackURL,
    });

    if (authError) {
      setSignUpError(authError.message || 'Sign up failed. Please try again.');
      setLoading(false);
    }
  }, [callbackURL, signUpEmail, signUpName, signUpPassword]);

  const handleGoogleSignUp = useCallback(async () => {
    setLoading(true);
    setSignUpError('');
    await authClient.signIn.social({
      provider: 'google',
      callbackURL,
    });
  }, [callbackURL]);

  return (
    <div className="w-full max-w-3xl px-6">
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
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-2xl border border-white/10 bg-white/10 flex items-center justify-center">
              <span className="text-sm font-semibold">SW</span>
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">SWYRA</p>
              <h1 className="text-xl font-semibold text-foreground">Welcome back</h1>
            </div>
          </div>
          <p className="mt-3 text-sm text-muted-foreground">
            Sign in to continue to SWYRA.
          </p>
          <Tabs value={tab} onValueChange={setTab} className="mt-6">
            <TabsList className="w-full grid grid-cols-2">
              <TabsTrigger value="sign-in">Sign in</TabsTrigger>
              <TabsTrigger value="sign-up">Sign up</TabsTrigger>
            </TabsList>

            <SignInForm
              email={email}
              password={password}
              error={error}
              loading={loading}
              onEmailChange={setEmail}
              onPasswordChange={setPassword}
              onSubmit={handleSignIn}
              onGoogle={handleGoogleSignIn}
            />

            <SignUpForm
              name={signUpName}
              email={signUpEmail}
              password={signUpPassword}
              error={signUpError}
              loading={loading}
              onNameChange={setSignUpName}
              onEmailChange={setSignUpEmail}
              onPasswordChange={setSignUpPassword}
              onSubmit={handleSignUp}
              onGoogle={handleGoogleSignUp}
            />
          </Tabs>
        </div>
      </GlassSurface>
    </div>
  );
};

