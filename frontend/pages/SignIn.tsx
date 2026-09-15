import React, { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
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
  const [redirecting, setRedirecting] = useState(false);
  const [searchParams] = useSearchParams();
  const initialError = searchParams.get('error_description') || searchParams.get('error');
  const [error, setError] = useState<string | null>(
    initialError && initialError !== 'login_required' && initialError !== 'consent_required'
      ? initialError.replace(/\+/g, ' ')
      : null
  );
  const signupEnabled = useMemo(() => isPublicSignupEnabled(), []);

  const callbackURL = useMemo(() => {
    const explicit = safeCallbackURL(searchParams.get('callbackURL'));
    if (explicit) return explicit;

    if (searchParams.get('client_id') && searchParams.get('redirect_uri')) {
      return `/api/auth/oauth2/authorize?${searchParams.toString()}`;
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

    authClient.getSession().then((sessionRes) => {
      if (sessionRes?.data?.user) {
        setRedirecting(true);
        window.location.assign(callbackURL);
      }
    }).catch(() => {});
  }, [callbackURL, searchParams]);

  const handleSignIn = async (values: z.infer<typeof signInSchema>) => {
    setLoading(true);
    setError(null);

    try {
      const res = await authClient.signIn.email({
        email: values.email,
        password: values.password,
        callbackURL,
      });

      if (res?.error) {
        setRedirecting(false);
        if (res.error.message?.toLowerCase().includes("two factor") || res.error.status === 403) {
          return;
        }
        const msg = res.error.message || 'Invalid email or password. Please check your credentials.';
        setError(msg);
        toast.error(msg);
        setLoading(false);
      } else {
        const dest = (res?.data as { url?: string } | undefined)?.url || callbackURL;
        if (dest) {
          setRedirecting(true);
          window.location.assign(dest);
        } else {
          setLoading(false);
          toast.success("Signed in successfully.");
        }
      }
    } catch (err: unknown) {
      setRedirecting(false);
      const msg = err instanceof Error ? err.message : 'Network error communicating with authentication service.';
      setError(msg);
      toast.error(msg);
      setLoading(false);
    }
  };

  const handleSignUp = async (values: z.infer<typeof signUpSchema>) => {
    if (!signupEnabled) {
      toast.error('Public sign-up is disabled.');
      return;
    }
    setLoading(true);
    setRedirecting(false);
    setError(null);
    try {
      const res = await authClient.signUp.email({
        email: values.email,
        password: values.password,
        name: values.name,
        callbackURL,
      } as Parameters<typeof authClient.signUp.email>[0]);
      const { error: authError } = res;
      if (authError) {
        setRedirecting(false);
        const msg = authError.message || 'Registration failed. Please check your details.';
        setError(msg);
        toast.error(msg);
        setLoading(false);
        return;
      }

      const signInRes = await authClient.signIn.email({
        email: values.email,
        password: values.password,
        callbackURL,
      });

      if (signInRes?.error) {
        setRedirecting(false);
        setLoading(false);
        toast.success("Account created successfully. Please sign in.");
        signInForm.setValue('email', values.email);
        setTab('sign-in');
      } else {
        const dest = (signInRes?.data as { url?: string } | undefined)?.url || callbackURL;
        if (dest) {
          setRedirecting(true);
          window.location.assign(dest);
        } else {
          setLoading(false);
          toast.success("Account created and signed in successfully.");
        }
      }
    } catch (err: unknown) {
      setRedirecting(false);
      const msg = err instanceof Error ? err.message : 'Network error during registration.';
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

      {/* Left Brand Panel (approx 42% on desktop) */}
      <div className="lg:col-span-5 hidden lg:flex flex-col justify-between p-8 sm:p-12 lg:p-[55px] border-r border-border bg-sidebar relative overflow-hidden">
        <div>
          <BrandMark />

          {/* Short M tricolor accent on authentication panel */}
          <div className="mt-12 flex h-1 w-12 items-stretch rounded-full overflow-hidden" aria-hidden="true">
            <div className="w-1/3 bg-[#0066B1]" />
            <div className="w-1/3 bg-[#1C69D4]" />
            <div className="w-1/3 bg-[#E22718]" />
          </div>

          <h1 className="mt-6 font-heading text-[55px] leading-[1.05] tracking-tight font-semibold text-foreground">
            Identity.<br />Under control.
          </h1>
          <p className="mt-5 font-sans text-sm text-muted-foreground leading-relaxed">
            High-performance OAuth 2.1 authorization service. Precision tokens, cryptographic integrity, and session protection.
          </p>
        </div>

        <div className="space-y-2 pt-6 border-t border-border/80">
          <div className="flex items-center justify-between font-sans text-xs text-muted-foreground">
            <span>Protocol</span>
            <span className="text-foreground font-mono">OAuth 2.1 RFC 6749 / 7636</span>
          </div>
          <div className="flex items-center justify-between font-sans text-xs text-muted-foreground">
            <span>Security standard</span>
            <span className="text-foreground font-mono">PKCE & RS256 JWKS</span>
          </div>
        </div>
      </div>

      {/* Right Form Area (approx 58% on desktop) */}
      <div className="lg:col-span-7 w-full flex items-center justify-center p-4 sm:p-8 lg:p-12">
        <div className="w-full max-w-[440px]">
          {/* Mobile brand header */}
          <div className="lg:hidden flex items-center justify-between mb-6">
            <BrandMark />
          </div>

          <Card className="w-full border border-border bg-card shadow-sm">
            {redirecting && (
              <div className="absolute inset-0 z-50 flex flex-col items-center justify-center bg-card/95 backdrop-blur-md p-8 text-center animate-in fade-in duration-200">
                <div className="relative mb-5">
                  <div className="size-14 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center">
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

              <Tabs value={tab} onValueChange={setTab} className="w-full">
                {signupEnabled && (
                  <TabsList className="w-full grid grid-cols-2 mb-6 h-9">
                    <TabsTrigger value="sign-in" className="text-xs">Sign In</TabsTrigger>
                    <TabsTrigger value="sign-up" className="text-xs">Sign Up</TabsTrigger>
                  </TabsList>
                )}

                <TabsContent value="sign-in">
                  <Form {...signInForm}>
                    <form onSubmit={signInForm.handleSubmit(handleSignIn)} className="space-y-4">
                      {error && (
                        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 font-sans text-xs text-destructive flex items-center gap-2">
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
                                className="h-10"
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
                                className="font-sans text-xs text-primary hover:underline transition-colors"
                              >
                                Forgot password?
                              </Link>
                            </div>
                            <FormControl>
                              <Input
                                type="password"
                                placeholder="••••••••••••"
                                {...field}
                                disabled={loading}
                                className="h-10"
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={signInForm.control}
                        name="remember"
                        render={({ field }) => (
                          <FormItem className="flex items-center space-x-2 space-y-0 pt-0.5">
                            <FormControl>
                              <Checkbox
                                checked={field.value}
                                onCheckedChange={field.onChange}
                                disabled={loading}
                              />
                            </FormControl>
                            <FormLabel className="text-xs font-sans text-muted-foreground font-normal cursor-pointer">
                              Remember this device
                            </FormLabel>
                          </FormItem>
                        )}
                      />

                      <Button type="submit" className="w-full h-10 font-medium" disabled={loading}>
                        {loading ? 'Signing in...' : 'Sign in'}
                      </Button>
                    </form>
                  </Form>

                  <div className="my-5 flex items-center gap-3">
                    <Separator className="flex-1" />
                    <span className="font-sans text-[11px] text-muted-foreground">
                      or
                    </span>
                    <Separator className="flex-1" />
                  </div>

                  <Button
                    type="button"
                    variant="outline"
                    className="w-full h-10"
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
                          <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 font-sans text-xs text-destructive flex items-center gap-2">
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
                                  className="h-10"
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
                                  className="h-10"
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
                                <Input
                                  type="password"
                                  placeholder="••••••••••••"
                                  {...field}
                                  disabled={loading}
                                  className="h-10"
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        {/* Password Requirements Checklist */}
                        <div className="rounded-md border border-border bg-secondary/30 p-3 space-y-1.5 font-sans text-xs">
                          <span className="text-muted-foreground text-[11px] font-medium block mb-1">
                            Password requirements:
                          </span>
                          <div className="flex items-center gap-2">
                            <span className={`size-1.5 rounded-full ${signUpPassword.length >= 12 ? 'bg-emerald-500' : 'bg-muted-foreground/40'}`} />
                            <span className={signUpPassword.length >= 12 ? 'text-foreground' : 'text-muted-foreground'}>
                              At least 12 characters
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`size-1.5 rounded-full ${/[a-z]/.test(signUpPassword) ? 'bg-emerald-500' : 'bg-muted-foreground/40'}`} />
                            <span className={signUpPassword.length >= 12 ? 'text-foreground' : 'text-muted-foreground'}>
                              Lowercase and uppercase letters
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`size-1.5 rounded-full ${/[0-9]/.test(signUpPassword) ? 'bg-emerald-500' : 'bg-muted-foreground/40'}`} />
                            <span className={signUpPassword.length >= 12 ? 'text-foreground' : 'text-muted-foreground'}>
                              At least one number
                            </span>
                          </div>
                        </div>

                        <Button type="submit" className="w-full h-10 font-medium" disabled={loading}>
                          {loading ? 'Creating account...' : 'Create account'}
                        </Button>
                      </form>
                    </Form>

                    <div className="my-5 flex items-center gap-3">
                      <Separator className="flex-1" />
                      <span className="font-sans text-[11px] text-muted-foreground">
                        or
                      </span>
                      <Separator className="flex-1" />
                    </div>

                    <Button
                      type="button"
                      variant="outline"
                      className="w-full h-10"
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
