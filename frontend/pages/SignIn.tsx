import React, { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { Card, CardContent } from '@/components/ui/card';
import { isPublicSignupEnabled, safeCallbackURL } from '@/lib/security';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { toast } from 'sonner';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Eye, EyeOff } from 'lucide-react';

const signInSchema = z.object({
  email: z.string().email({ message: "Invalid email address" }),
  password: z.string().min(1, { message: "Password is required" }),
  remember: z.boolean().optional(),
});

const signUpSchema = z.object({
  name: z.string().min(2, { message: "Name must be at least 2 characters" }),
  email: z.string().email({ message: "Invalid email address" }),
  password: z.string().min(12, { message: "Password must be at least 12 characters" }),
});

export const SignIn: React.FC = () => {
  const [tab, setTab] = useState('sign-in');
  usePageTitle(tab === 'sign-in' ? 'Sign in' : 'Create account');

  const [loading, setLoading] = useState(false);
  const [showSignInPassword, setShowSignInPassword] = useState(false);
  const [showSignUpPassword, setShowSignUpPassword] = useState(false);
  const [redirecting, setRedirecting] = useState(false);
  const [searchParams] = useSearchParams();
  const initialError = searchParams.get('error_description') || searchParams.get('error');
  const [error, setError] = useState<string | null>(
    initialError && initialError !== 'login_required' && initialError !== 'consent_required'
      ? initialError.replace(/\+/g, ' ')
      : null
  );
  const isPrivateApp = useMemo(() => {
    return searchParams.get('is_public') === 'false';
  }, [searchParams]);

  const signupEnabled = useMemo(() => {
    if (isPrivateApp) return false;
    return isPublicSignupEnabled();
  }, [isPrivateApp]);

  const callbackURL = useMemo(() => {
    // 1. Authoritative OAuth continuation takes strict precedence
    if (searchParams.get('client_id') && searchParams.get('redirect_uri')) {
      const oauthParams = new URLSearchParams(searchParams);
      oauthParams.delete('prompt');
      return `/api/auth/oauth2/authorize?${oauthParams.toString()}`;
    }

    // 2. Otherwise inspect explicit callbackURL, strictly rejecting platform administrator routes
    const rawCallback = searchParams.get('callbackURL');
    if (rawCallback) {
      const explicit = safeCallbackURL(rawCallback);
      if (explicit && !explicit.startsWith('/admin') && !explicit.startsWith('/api/admin')) {
        return explicit;
      }
    }

    return undefined;
  }, [searchParams]);

  const signInForm = useForm<z.infer<typeof signInSchema>>({
    resolver: zodResolver(signInSchema),
    defaultValues: {
      email: '',
      password: '',
      remember: false,
    },
  });

  const signUpForm = useForm<z.infer<typeof signUpSchema>>({
    resolver: zodResolver(signUpSchema),
    defaultValues: {
      name: '',
      email: '',
      password: '',
    },
  });

  const signUpPassword = useWatch({ control: signUpForm.control, name: 'password' }) || '';

  useEffect(() => {
    if (searchParams.get('prompt') === 'login') return;
    if (!callbackURL) return;

    let active = true;
    authClient.getSession().then(({ data }) => {
      if (!active || !data?.user) return;
      setRedirecting(true);
      window.location.assign(callbackURL);
    }).catch(() => {});

    return () => { active = false; };
  }, [callbackURL, searchParams]);

  const handleSignIn = async (values: z.infer<typeof signInSchema>) => {
    setLoading(true);
    setError(null);

    try {
      const res = await authClient.signIn.email({
        email: values.email,
        password: values.password,
        rememberMe: false,
      });

      if (res.error) {
        setError(res.error.message || 'Authentication failed. Please verify credentials.');
        setLoading(false);
        return;
      }

      if ((res.data as Record<string, unknown>)?.twoFactorRedirect) {
        const twoFactorUrl = `/two-factor?${searchParams.toString()}`;
        window.location.assign(twoFactorUrl);
        return;
      }

      setRedirecting(true);
      if (callbackURL) {
        window.location.assign(callbackURL);
      } else {
        window.location.assign('/admin');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'A network error occurred.';
      setError(msg);
      toast.error(msg);
      setLoading(false);
    }
  };

  const handleSignUp = async (values: z.infer<typeof signUpSchema>) => {
    if (!signupEnabled) {
      setError('Registration is disabled.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await authClient.signUp.email({
        name: values.name,
        email: values.email,
        password: values.password,
      });

      if (res.error) {
        setError(res.error.message || 'Failed to create account.');
        setLoading(false);
        return;
      }

      setRedirecting(true);
      if (callbackURL) {
        window.location.assign(callbackURL);
      } else {
        window.location.assign('/admin');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Registration failed.';
      setError(msg);
      toast.error(msg);
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setLoading(true);
    setRedirecting(true);
    setError(null);
    try {
      await authClient.signIn.social({
        provider: 'google',
        callbackURL,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Social authentication unavailable.';
      setError(msg);
      toast.error(msg);
      setLoading(false);
      setRedirecting(false);
    }
  };

  return (
    <div className="min-h-screen w-full grid grid-cols-1 lg:grid-cols-12 relative bg-background">
      {/* Top right theme toggle */}
      <div className="absolute top-4 right-4 z-50">
        <ThemeToggle />
      </div>

      {/* Left Brand Panel (Evergreen Forest Stone in both themes) */}
      <div className="lg:col-span-5 hidden lg:flex flex-col justify-between p-8 sm:p-12 lg:p-14 border-r border-[#1B3A31] bg-[#102D25] text-white relative overflow-hidden">
        {/* Topographic Contour SVG */}
        <svg
          aria-hidden="true"
          className="absolute inset-0 w-full h-full opacity-[0.07] pointer-events-none"
          viewBox="0 0 400 600"
          preserveAspectRatio="none"
        >
          <path d="M0,80 Q100,140 200,80 T400,100 M0,180 Q140,240 260,160 T400,200 M0,280 Q80,360 220,280 T400,320 M0,380 Q160,460 300,380 T400,420 M0,480 Q100,560 240,480 T400,520" fill="none" stroke="currentColor" strokeWidth="1.5" />
        </svg>

        <div className="relative z-10">
          <BrandMark />

          {/* Motorsport tricolor accent */}
          <div className="mt-8 flex h-1 w-12 items-stretch rounded-full overflow-hidden" aria-hidden="true">
            <div className="w-1/3 bg-motorsport-light" />
            <div className="w-1/3 bg-motorsport-dark" />
            <div className="w-1/3 bg-motorsport-red" />
          </div>

          <h1 className="mt-6 font-heading text-4xl sm:text-[46px] leading-[1.08] tracking-tight font-semibold text-white">
            Identity.<br />Under control.
          </h1>
          <p className="mt-4 font-sans text-sm text-[#EEECE5]/80 leading-relaxed max-w-md">
            High performance OAuth 2.1 authorization service. Precision tokens, cryptographic integrity, and session protection.
          </p>
        </div>

        <div className="relative z-10 space-y-2.5 pt-6 border-t border-[#1B3A31]">
          <div className="flex items-center justify-between font-sans text-xs text-[#EEECE5]/70">
            <span>Protocol</span>
            <span className="text-[#B7C9AD] font-mono">OAuth 2.1 RFC 6749 / 7636</span>
          </div>
          <div className="flex items-center justify-between font-sans text-xs text-[#EEECE5]/70">
            <span>Security standard</span>
            <span className="text-[#B7C9AD] font-mono">PKCE & RS256 JWKS</span>
          </div>
        </div>
      </div>

      {/* Right Form Area */}
      <div className="lg:col-span-7 w-full flex items-center justify-center p-4 sm:p-8 lg:p-12">
        <div className="w-full max-w-[440px]">
          {/* Mobile brand header */}
          <div className="lg:hidden flex items-center justify-between mb-6">
            <BrandMark />
          </div>

          <Card className="w-full border border-border bg-card shadow-xs rounded-xl overflow-hidden">
            {redirecting && (
              <div className="absolute inset-0 z-50 flex flex-col items-center justify-center bg-card/95 p-8 text-center animate-in fade-in duration-200">
                <div className="relative mb-5">
                  <div className="size-14 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center">
                    <svg className="size-7 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                </div>
                <h3 className="font-heading text-xl font-medium text-foreground mb-1">
                  Signed in
                </h3>
                <p className="font-sans text-xs text-muted-foreground">
                  Redirecting to your application...
                </p>
              </div>
            )}

            <CardContent className="p-6 sm:p-8 w-full">
              <div className="mb-6">
                <h2 className="font-heading text-2xl font-semibold text-foreground tracking-tight">
                  {tab === 'sign-in' ? 'Sign in' : 'Create an account'}
                </h2>
                <p className="font-sans text-xs text-muted-foreground mt-1">
                  {tab === 'sign-in' 
                    ? 'Enter your credentials to access your account' 
                    : 'Get started by creating your identity'}
                </p>
              </div>

              {isPrivateApp && (
                <div role="status" className="mb-6 rounded-lg border border-primary/20 bg-primary/5 p-3.5 text-xs text-muted-foreground flex items-center gap-2.5">
                  <svg className="size-4 shrink-0 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                  <span>Private Application: Please sign in with your authorized account. Public self-registration is disabled.</span>
                </div>
              )}

              <Tabs value={tab} onValueChange={setTab} className="w-full">
                {signupEnabled && (
                  <TabsList className="w-full grid grid-cols-2 mb-6 h-10 p-1 bg-secondary rounded-pill">
                    <TabsTrigger value="sign-in" className="text-xs rounded-pill data-[state=active]:bg-primary data-[state=active]:text-primary-foreground font-medium transition-colors">Sign in</TabsTrigger>
                    <TabsTrigger value="sign-up" className="text-xs rounded-pill data-[state=active]:bg-primary data-[state=active]:text-primary-foreground font-medium transition-colors">Sign up</TabsTrigger>
                  </TabsList>
                )}

                <TabsContent value="sign-in">
                  <Form {...signInForm}>
                    <form onSubmit={signInForm.handleSubmit(handleSignIn)} className="space-y-4">
                      {error && (
                        <div role="alert" className="rounded-lg border border-destructive/20 bg-destructive/10 p-3.5 font-sans text-xs text-destructive flex items-center gap-2.5">
                          <svg className="size-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                          <span>{error}</span>
                        </div>
                      )}

                      <FormField
                        control={signInForm.control}
                        name="email"
                        render={({ field }) => (
                          <FormItem className="space-y-1.5">
                            <FormLabel className="font-sans text-xs font-medium text-foreground">Email Address</FormLabel>
                            <FormControl>
                              <Input
                                type="email"
                                placeholder="name@example.com"
                                {...field}
                                disabled={loading}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={signInForm.control}
                        name="password"
                        render={({ field }) => (
                          <FormItem className="space-y-1.5">
                            <div className="flex items-center justify-between">
                              <FormLabel className="font-sans text-xs font-medium text-foreground">Password</FormLabel>
                              <Link
                                to="/forgot-password"
                                className="font-sans text-xs text-primary hover:underline transition-colors font-medium"
                              >
                                Forgot password?
                              </Link>
                            </div>
                            <FormControl>
                              <div className="relative">
                                <Input
                                  type={showSignInPassword ? 'text' : 'password'}
                                  placeholder="••••••••••••"
                                  {...field}
                                  disabled={loading}
                                  className="pr-10"
                                />
                                <button
                                  type="button"
                                  onClick={() => setShowSignInPassword(!showSignInPassword)}
                                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground focus:outline-none cursor-pointer"
                                  aria-label={showSignInPassword ? 'Hide password' : 'Show password'}
                                  tabIndex={-1}
                                >
                                  {showSignInPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                                </button>
                              </div>
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <Button type="submit" className="w-full h-11 font-medium rounded-pill mt-2" disabled={loading}>
                        {loading ? 'Signing in...' : 'Sign in'}
                      </Button>
                    </form>
                  </Form>

                  <div className="my-5 flex items-center gap-3">
                    <Separator className="flex-1" />
                    <span className="font-sans text-xs text-muted-foreground">
                      or
                    </span>
                    <Separator className="flex-1" />
                  </div>

                  <Button
                    type="button"
                    variant="outline"
                    className="w-full h-11 rounded-pill"
                    onClick={handleGoogleSignIn}
                    disabled={loading}
                  >
                    <svg className="size-4 mr-2" viewBox="0 0 48 48" aria-hidden="true">
                      <path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8c-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C12.955 4 4 12.955 4 24s8.955 20 20 20s20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z" />
                      <path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C16.318 4 9.656 8.337 6.306 14.691z" />
                      <path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238A11.91 11.91 0 0 1 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z" />
                      <path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 0 1-4.087 5.571l.003-.002l6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z" />
                    </svg>
                    Continue with Google
                  </Button>
                </TabsContent>

                {signupEnabled && (
                  <TabsContent value="sign-up">
                    <Form {...signUpForm}>
                      <form onSubmit={signUpForm.handleSubmit(handleSignUp)} className="space-y-4">
                        {error && (
                          <div role="alert" className="rounded-lg border border-destructive/20 bg-destructive/10 p-3.5 font-sans text-xs text-destructive flex items-center gap-2.5">
                            <svg className="size-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <span>{error}</span>
                          </div>
                        )}

                        <FormField
                          control={signUpForm.control}
                          name="name"
                          render={({ field }) => (
                            <FormItem className="space-y-1.5">
                              <FormLabel className="font-sans text-xs font-medium text-foreground">Full Name</FormLabel>
                              <FormControl>
                                <Input
                                  placeholder="Alex Walker"
                                  {...field}
                                  disabled={loading}
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={signUpForm.control}
                          name="email"
                          render={({ field }) => (
                            <FormItem className="space-y-1.5">
                              <FormLabel className="font-sans text-xs font-medium text-foreground">Email Address</FormLabel>
                              <FormControl>
                                <Input
                                  type="email"
                                  placeholder="alex@example.com"
                                  {...field}
                                  disabled={loading}
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={signUpForm.control}
                          name="password"
                          render={({ field }) => (
                            <FormItem className="space-y-1.5">
                              <FormLabel className="font-sans text-xs font-medium text-foreground">Password (min. 12 characters)</FormLabel>
                              <FormControl>
                                <div className="relative">
                                  <Input
                                    type={showSignUpPassword ? 'text' : 'password'}
                                    placeholder="••••••••••••"
                                    {...field}
                                    disabled={loading}
                                    className="pr-10"
                                  />
                                  <button
                                    type="button"
                                    onClick={() => setShowSignUpPassword(!showSignUpPassword)}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground focus:outline-none cursor-pointer"
                                    aria-label={showSignUpPassword ? 'Hide password' : 'Show password'}
                                    tabIndex={-1}
                                  >
                                    {showSignUpPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                                  </button>
                                </div>
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        {/* Password Requirements Checklist */}
                        <div className="rounded-lg border border-border bg-secondary/30 p-3.5 space-y-2 font-sans text-xs">
                          <span className="text-muted-foreground text-xs font-medium block">
                            Password requirements:
                          </span>
                          <div className="flex items-center gap-2">
                            <span className={`size-1.5 rounded-full ${signUpPassword.length >= 12 ? 'bg-success' : 'bg-muted-foreground/40'}`} />
                            <span className={signUpPassword.length >= 12 ? 'text-foreground font-medium' : 'text-muted-foreground'}>
                              At least 12 characters
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`size-1.5 rounded-full ${/[a-z]/.test(signUpPassword) && /[A-Z]/.test(signUpPassword) ? 'bg-success' : 'bg-muted-foreground/40'}`} />
                            <span className={signUpPassword.length >= 12 ? 'text-foreground font-medium' : 'text-muted-foreground'}>
                              Lowercase and uppercase letters
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`size-1.5 rounded-full ${/[0-9]/.test(signUpPassword) ? 'bg-success' : 'bg-muted-foreground/40'}`} />
                            <span className={signUpPassword.length >= 12 ? 'text-foreground font-medium' : 'text-muted-foreground'}>
                              At least one number
                            </span>
                          </div>
                        </div>

                        <Button type="submit" className="w-full h-11 font-medium rounded-pill mt-2" disabled={loading}>
                          {loading ? 'Creating account...' : 'Create account'}
                        </Button>
                      </form>
                    </Form>

                    <div className="my-5 flex items-center gap-3">
                      <Separator className="flex-1" />
                      <span className="font-sans text-xs text-muted-foreground">
                        or
                      </span>
                      <Separator className="flex-1" />
                    </div>

                    <Button
                      type="button"
                      variant="outline"
                      className="w-full h-11 rounded-pill"
                      onClick={handleGoogleSignIn}
                      disabled={loading}
                    >
                      <svg className="size-4 mr-2" viewBox="0 0 48 48" aria-hidden="true">
                        <path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8c-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C12.955 4 4 12.955 4 24s8.955 20 20 20s20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z" />
                        <path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C16.318 4 9.656 8.337 6.306 14.691z" />
                        <path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238A11.91 11.91 0 0 1 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z" />
                        <path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 0 1-4.087 5.571l.003-.002l6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z" />
                      </svg>
                      Continue with Google
                    </Button>
                  </TabsContent>
                )}
              </Tabs>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};
