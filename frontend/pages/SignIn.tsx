import React, { useMemo, useState } from 'react';
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
  const [loading, setLoading] = useState(false);
  const [redirecting, setRedirecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchParams] = useSearchParams();
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

  const handleSignIn = async (values: z.infer<typeof signInSchema>) => {
    setLoading(true);
    setError(null);

    try {
      const { error: authError } = await authClient.signIn.email({
        email: values.email,
        password: values.password,
        callbackURL,
      });

      if (authError) {
        setRedirecting(false);
        if (authError.message?.toLowerCase().includes("two factor") || authError.status === 403) {
          return;
        }
        const msg = authError.message || 'Invalid email or password. Please verify your credentials.';
        setError(msg);
        toast.error(msg);
        setLoading(false);
      } else {
        if (callbackURL) {
          setRedirecting(true);
        } else {
          setLoading(false);
          toast.success("Successfully authenticated.");
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
    console.log("handleSignUp called with callbackURL:", callbackURL);
    setLoading(true);
    setRedirecting(false);
    setError(null);
    try {
      const res = await authClient.signUp.email({
        email: values.email,
        password: values.password,
        name: values.name,
        // callbackURL,
      });
      console.log("res:", res);
      const { error: authError } = res
      console.log("authError:", error);
      if (authError) {
        setRedirecting(false);
        const msg = authError.message?.toLowerCase().includes('already exists')
          ? 'An account with this email already exists. Please sign in instead.'
          : (authError.message || 'Registration failed. Please check your details.');
        setError(msg);
        toast.error(msg);
        setLoading(false);
      } else {
        if (callbackURL) {
          setRedirecting(true);
        } else {
          setLoading(false);
          toast.success("Account created successfully! Please sign in.");
          setTab('sign-in');
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
    <div className="min-h-screen w-full grid grid-cols-1 lg:grid-cols-2">
      {/* Left (38.2%): Monumental Space Grotesk Headline & Telemetry */}
      <div className="w-full min-w-0 flex flex-col justify-center p-8 sm:p-12 lg:p-xl border-b lg:border-b-0 lg:border-r border-border/40 bg-background/50 backdrop-blur-sm relative">


        <div className="my-12 lg:my-0">
          <div className="flex items-center gap-3">
            <div className="flex h-4 gap-1 items-center">
              <div className="w-0.5 h-3 bg-[#0066B1] -skew-x-12" />
              <div className="w-0.5 h-3 bg-[#1C69D4] -skew-x-12" />
              <div className="w-0.5 h-3 bg-[#E22718] -skew-x-12" />
            </div>
            <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-muted-foreground">
              SWYRA // M Telemetry System v2.1
            </span>
          </div>
          <h1 className="font-heading text-5xl sm:text-6xl lg:text-[90px] leading-[1] tracking-[-0.04em] font-normal text-foreground">
            Digital<br />Telemetry.
          </h1>
          <p className="mt-6 font-mono text-xs uppercase tracking-[0.05em] text-muted-foreground leading-relaxed max-w-[380px] w-full">
            SWYRA high-performance authorization engine. Precision identity token exchange and cryptographic verification.
          </p>
        </div>

        <div className="space-y-2 pt-6 border-t border-border/30 absolute bottom-4 lg:bottom-8 w-[80%] m-auto">
          <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            <span>Protocol</span>
            <span className="text-foreground">OAuth 2.1 RFC-6749</span>
          </div>
          <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            <span>Auth Service</span>
            <span className="text-accent flex items-center gap-1.5">
              <span className="inline-block size-1.5 rounded-full bg-accent animate-ping" />
              SWYRA M Auth
            </span>
          </div>
        </div>

      </div>

      <div className="w-full min-w-0 flex items-center justify-center p-6 sm:p-12 lg:p-12.5">
        <div className="w-full max-w-[500px]">
          <Card className="w-full relative overflow-hidden" watermark="SWYRA">
            {redirecting && (
              <div className="absolute inset-0 z-50 flex flex-col items-center justify-center bg-card/95 backdrop-blur-md p-8 text-center animate-in fade-in duration-300">
                <div className="relative mb-6">
                  <div className="h-16 w-16 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center">
                    <svg className="h-8 w-8 text-primary animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                  <div className="absolute inset-0 rounded-full border-2 border-primary border-t-transparent animate-spin" />
                </div>
                <h3 className="font-heading text-2xl font-normal text-foreground mb-2">
                  Identity Verified
                </h3>
                <p className="font-mono text-xs uppercase tracking-wider text-muted-foreground text-center mb-4">
                  Establishing authorized token session & redirecting...
                </p>
                <div className="flex items-center gap-2 text-xs font-mono text-primary/90 bg-primary/10 px-3 py-1.5 rounded-full border border-primary/20">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-ping" />
                  <span>OAuth 2.1 Handshake In Progress</span>
                </div>
              </div>
            )}
            <CardContent className="p-8 sm:p-lg w-full">
              <div className="mb-8">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                    SWYRA // M Auth
                  </span>
                  <span className="font-mono text-[10px] uppercase text-accent border border-accent/30 rounded-pill px-2 py-0.5">
                    Secured
                  </span>
                </div>
                <h2 className="font-heading text-[34px] leading-[1.2] tracking-[-0.02em] font-normal text-foreground">
                  {tab === 'sign-in' ? 'Authenticate' : 'Register Pilot'}
                </h2>
              </div>

              <Tabs value={tab} onValueChange={setTab} className="w-full">
                <TabsList className={`w-full grid ${signupEnabled ? 'grid-cols-2' : 'grid-cols-1'} mb-8`}>
                  <TabsTrigger value="sign-in">Sign In</TabsTrigger>
                  {signupEnabled && <TabsTrigger value="sign-up">Sign Up</TabsTrigger>}
                </TabsList>

                  <TabsContent value="sign-in" className="animate-in fade-in duration-300">
                    <Form {...signInForm}>
                      <form onSubmit={signInForm.handleSubmit(handleSignIn)} className="space-y-[21px]">
                        {error && (
                          <div className="rounded-[16px] border border-destructive/30 bg-destructive/10 p-3.5 font-mono text-xs text-destructive flex items-center gap-2.5 animate-in fade-in zoom-in-95">
                            <svg className="size-4 shrink-0 text-destructive" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <span>{error}</span>
                          </div>
                        )}

                        <FormField
                          control={signInForm.control}
                          name="email"
                          render={({ field }) => (
                            <FormItem className="space-y-1">
                              <FormLabel>Email Address</FormLabel>
                              <FormControl>
                                <Input
                                  type="email"
                                  placeholder="pilot@swyra.com"
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
                            <FormItem className="space-y-1">
                              <div className="flex items-center justify-between">
                                <FormLabel>Passkey / Secret</FormLabel>
                                <Link
                                  to="/forgot-password"
                                  className="font-mono text-xs text-muted-foreground hover:text-accent transition-colors"
                                >
                                  Forgot?
                                </Link>
                              </div>
                              <FormControl>
                                <Input
                                  type="password"
                                  placeholder="••••••••••••"
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
                          name="remember"
                          render={({ field }) => (
                            <FormItem className="flex items-center space-x-2 space-y-0">
                              <FormControl>
                                <Checkbox
                                  checked={field.value}
                                  onCheckedChange={field.onChange}
                                  disabled={loading}
                                />
                              </FormControl>
                              <FormLabel className="text-xs font-mono text-muted-foreground font-normal cursor-pointer">
                                Remember terminal identity
                              </FormLabel>
                            </FormItem>
                          )}
                        />

                        <Button type="submit" className="w-full" disabled={loading}>
                          {loading ? 'Authenticating...' : 'Authenticate with Credentials'}
                        </Button>
                      </form>
                    </Form>

                    <div className="my-[21px] flex items-center gap-4">
                      <Separator className="flex-1" />
                      <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                        OR
                      </span>
                      <Separator className="flex-1" />
                    </div>

                    <Button
                      type="button"
                      variant="outline"
                      className="w-full"
                      onClick={handleGoogleSignIn}
                      disabled={loading}
                    >
                      <svg className="h-4 w-4 mr-2" viewBox="0 0 48 48" aria-hidden="true">
                        <path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8c-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C12.955 4 4 12.955 4 24s8.955 20 20 20s20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z" />
                        <path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4C16.318 4 9.656 8.337 6.306 14.691z" />
                        <path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238A11.91 11.91 0 0 1 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z" />
                        <path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 0 1-4.087 5.571l.003-.002l6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z" />
                      </svg>
                      Continue with Google
                    </Button>
                  </TabsContent>

                  {signupEnabled && (
                    <TabsContent value="sign-up" className="animate-in fade-in duration-300">
                      <Form {...signUpForm}>
                        <form onSubmit={signUpForm.handleSubmit(handleSignUp)} className="space-y-4">
                          {error && (
                            <div className="rounded-[16px] border border-destructive/30 bg-destructive/10 p-3.5 font-mono text-xs text-destructive flex items-center gap-2.5 animate-in fade-in zoom-in-95">
                              <svg className="size-4 shrink-0 text-destructive" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                              <span>{error}</span>
                            </div>
                          )}

                          <FormField
                            control={signUpForm.control}
                            name="name"
                            render={({ field }) => (
                              <FormItem className="space-y-1">
                                <FormLabel>Full Legal Name</FormLabel>
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
                              <FormItem className="space-y-1">
                                <FormLabel>Work / Pilot Email</FormLabel>
                                <FormControl>
                                  <Input
                                    type="email"
                                    placeholder="alex@swyra.com"
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
                              <FormItem className="space-y-1">
                                <FormLabel>Master Passphrase (min 12 chars)</FormLabel>
                                <FormControl>
                                  <Input
                                    type="password"
                                    placeholder="••••••••••••"
                                    {...field}
                                    disabled={loading}
                                  />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />

                          {/* Password Requirements Checklist */}
                          <div className="rounded-[16px] border border-border/40 bg-muted/20 p-3 space-y-1.5 font-mono text-[11px]">
                            <span className="text-muted-foreground uppercase tracking-wider text-[10px] block mb-1">
                              Security Constraints
                            </span>
                            <div className="flex items-center gap-2">
                              <span className={`size-1.5 rounded-full ${signUpPassword.length >= 12 ? 'bg-emerald-500' : 'bg-muted-foreground/40'}`} />
                              <span className={signUpPassword.length >= 12 ? 'text-foreground' : 'text-muted-foreground'}>
                                Minimum 12 characters
                              </span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className={`size-1.5 rounded-full ${/[A-Z]/.test(signUpPassword) ? 'bg-emerald-500' : 'bg-muted-foreground/40'}`} />
                              <span className={/[A-Z]/.test(signUpPassword) ? 'text-foreground' : 'text-muted-foreground'}>
                                At least one uppercase letter
                              </span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className={`size-1.5 rounded-full ${/[0-9]/.test(signUpPassword) ? 'bg-emerald-500' : 'bg-muted-foreground/40'}`} />
                              <span className={/[0-9]/.test(signUpPassword) ? 'text-foreground' : 'text-muted-foreground'}>
                                At least one numerical digit
                              </span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className={`size-1.5 rounded-full ${/[^A-Za-z0-9]/.test(signUpPassword) ? 'bg-emerald-500' : 'bg-muted-foreground/40'}`} />
                              <span className={/[^A-Za-z0-9]/.test(signUpPassword) ? 'text-foreground' : 'text-muted-foreground'}>
                                At least one special symbol
                              </span>
                            </div>
                          </div>

                          <Button type="submit" className="w-full" disabled={loading}>
                            {loading ? 'Creating...' : 'Register New Identity'}
                          </Button>
                        </form>
                      </Form>

                      <div className="my-[21px] flex items-center gap-4">
                        <Separator className="flex-1" />
                        <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                          OR
                        </span>
                        <Separator className="flex-1" />
                      </div>

                      <Button
                        type="button"
                        variant="outline"
                        className="w-full"
                        onClick={handleGoogleSignIn}
                        disabled={loading}
                      >
                        <svg className="h-4 w-4 mr-2" viewBox="0 0 48 48" aria-hidden="true">
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
