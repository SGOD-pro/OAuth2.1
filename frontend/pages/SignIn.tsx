import React, { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { isPublicSignupEnabled, safeCallbackURL } from '@/lib/security';
import { useForm } from 'react-hook-form';
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
  const [searchParams] = useSearchParams();
  const signupEnabled = useMemo(() => isPublicSignupEnabled(), []);

  const callbackURL = useMemo(
    () => safeCallbackURL(searchParams.get('callbackURL')),
    [searchParams]
  );

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

  const handleSignIn = async (values: z.infer<typeof signInSchema>) => {
    setLoading(true);
    const { error: authError } = await authClient.signIn.email({
      email: values.email,
      password: values.password,
      callbackURL,
    });

    if (authError) {
      toast.error(authError.message || 'Sign in failed. Please try again.');
      setLoading(false);
    }
  };

  const handleSignUp = async (values: z.infer<typeof signUpSchema>) => {
    if (!signupEnabled) {
      toast.error('Public sign-up is disabled.');
      return;
    }

    setLoading(true);
    const { error: authError } = await authClient.signUp.email({
      email: values.email,
      password: values.password,
      name: values.name,
      callbackURL,
    });

    if (authError) {
      toast.error(authError.message || 'Sign up failed. Please try again.');
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setLoading(true);
    await authClient.signIn.social({
      provider: 'google',
      callbackURL,
    });
  };

  return (
    <div className="w-full max-w-md px-4 mx-auto">
      <div className="glass-card rounded-[22px] p-8 w-full transition-all duration-300 relative overflow-hidden">
        <div className="text-left z-10 relative">
          <div className="flex items-center gap-3 mb-6">
            <div className="h-10 w-10 rounded-2xl border border-white/10 bg-black/10 dark:bg-white/10 flex items-center justify-center backdrop-blur-md">
              <span className="text-sm font-semibold">SW</span>
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground font-mono">SWYRA</p>
              <h1 className="text-xl font-semibold text-foreground font-heading">Welcome back</h1>
            </div>
          </div>
          
          <Tabs value={tab} onValueChange={setTab} className="w-full">
            <TabsList className={`w-full grid ${signupEnabled ? 'grid-cols-2' : 'grid-cols-1'} mb-6`}>
              <TabsTrigger value="sign-in">Sign in</TabsTrigger>
              {signupEnabled && <TabsTrigger value="sign-up">Sign up</TabsTrigger>}
            </TabsList>

            <TabsContent value="sign-in" className="animate-in fade-in slide-in-from-bottom-2 duration-300">
              <Form {...signInForm}>
                <form onSubmit={signInForm.handleSubmit(handleSignIn)} className="space-y-4">
                  <FormField
                    control={signInForm.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Email address</FormLabel>
                        <FormControl>
                          <Input placeholder="name@example.com" {...field} disabled={loading} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={signInForm.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Password</FormLabel>
                        <FormControl>
                          <Input type="password" placeholder="••••••••" {...field} disabled={loading} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  
                  <div className="flex items-center justify-between text-sm">
                    <FormField
                      control={signInForm.control}
                      name="remember"
                      render={({ field }) => (
                        <FormItem className="flex flex-row items-center space-x-2 space-y-0">
                          <FormControl>
                            <Checkbox
                              checked={field.value}
                              onCheckedChange={field.onChange}
                              disabled={loading}
                            />
                          </FormControl>
                          <FormLabel className="font-normal text-muted-foreground">
                            Remember me
                          </FormLabel>
                        </FormItem>
                      )}
                    />
                    <Link to="/forgot-password" viewTransition className="text-ring hover:underline font-medium text-xs">
                      Forgot password?
                    </Link>
                  </div>

                  <Button type="submit" className="w-full rounded-full mt-2" disabled={loading}>
                    {loading ? 'Signing in...' : 'Sign in'}
                  </Button>
                </form>
              </Form>
              
              <div className="my-6 flex items-center gap-4">
                <Separator className="flex-1" />
                <span className="text-xs uppercase tracking-widest text-muted-foreground font-mono">or</span>
                <Separator className="flex-1" />
              </div>

              <Button type="button" variant="outline" className="w-full rounded-full bg-white/50 dark:bg-black/20 hover:bg-white/80 dark:hover:bg-black/40 border-white/20 backdrop-blur-sm" onClick={handleGoogleSignIn} disabled={loading}>
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
              <TabsContent value="sign-up" className="animate-in fade-in slide-in-from-bottom-2 duration-300">
                <Form {...signUpForm}>
                  <form onSubmit={signUpForm.handleSubmit(handleSignUp)} className="space-y-4">
                    <FormField
                      control={signUpForm.control}
                      name="name"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Full name</FormLabel>
                          <FormControl>
                            <Input placeholder="John Doe" {...field} disabled={loading} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={signUpForm.control}
                      name="email"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Email address</FormLabel>
                          <FormControl>
                            <Input placeholder="name@example.com" {...field} disabled={loading} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={signUpForm.control}
                      name="password"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Password</FormLabel>
                          <FormControl>
                            <Input type="password" placeholder="••••••••" {...field} disabled={loading} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    
                    {/* Visual password strength indicator */}
                    {signUpForm.watch('password').length > 0 && (
                      <div className="w-full flex gap-1 mt-2">
                        <div className={`h-1 flex-1 rounded-full ${signUpForm.watch('password').length > 0 ? 'bg-destructive' : 'bg-border'} transition-colors`} />
                        <div className={`h-1 flex-1 rounded-full ${signUpForm.watch('password').length >= 6 ? 'bg-orange-400' : 'bg-border'} transition-colors`} />
                        <div className={`h-1 flex-1 rounded-full ${signUpForm.watch('password').length >= 12 ? 'bg-ring' : 'bg-border'} transition-colors`} />
                      </div>
                    )}

                    <Button type="submit" className="w-full rounded-full mt-4" disabled={loading}>
                      {loading ? 'Creating account...' : 'Create account'}
                    </Button>
                  </form>
                </Form>
                
                <div className="my-6 flex items-center gap-4">
                  <Separator className="flex-1" />
                  <span className="text-xs uppercase tracking-widest text-muted-foreground font-mono">or</span>
                  <Separator className="flex-1" />
                </div>

                <Button type="button" variant="outline" className="w-full rounded-full bg-white/50 dark:bg-black/20 hover:bg-white/80 dark:hover:bg-black/40 border-white/20 backdrop-blur-sm" onClick={handleGoogleSignIn} disabled={loading}>
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
        </div>
      </div>
      <p className="text-center mt-6 text-xs text-foreground/50 font-mono tracking-widest uppercase">
        Protected by Nexus Security Policies
      </p>
    </div>
  );
};
