import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { authClient, useSession } from '@/lib/auth-client';
import { isSuperAdminUser, isAppAdminUser } from '@/lib/role-predicates';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { toast } from 'sonner';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { RouteLoader } from '@/components/RouteLoader';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Eye, EyeOff } from 'lucide-react';

const adminLoginSchema = z.object({
  email: z.string().email({ message: "Invalid email address" }),
  password: z.string().min(1, { message: "Password is required" }),
});

export const AdminLogin: React.FC = () => {
  usePageTitle('Admin sign in');

  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const { data: session, isPending, refetch } = useSession();

  const form = useForm<z.infer<typeof adminLoginSchema>>({
    resolver: zodResolver(adminLoginSchema),
    defaultValues: {
      email: '',
      password: '',
    },
  });

  useEffect(() => {
    const err = searchParams.get('error');
    if (err === 'access_denied_scoped') {
      setError('Access restricted: Application administrators manage their app through their application portal. To access the central console, sign in with Global Super Admin credentials.');
    } else if (err === 'access_denied') {
      setError('Access restricted: Administrator privileges required. Please sign in with Global Super Admin credentials.');
    } else if (err === 'mfa_failed' || err === 'mfa_expired') {
      setError('Two factor verification failed or session expired. Please re-enter your credentials.');
    }
  }, [searchParams]);

  const user = (session as unknown as { user?: { role?: string; scopedClientId?: string | null; email?: string } })?.user;

  useEffect(() => {
    if (!isPending && user) {
      if (isSuperAdminUser(user)) {
        navigate('/admin', { replace: true });
      }
    }
  }, [user, isPending, navigate]);

  const handleSignIn = async (values: z.infer<typeof adminLoginSchema>) => {
    setLoading(true);
    setError(null);

    try {
      const res = await authClient.signIn.email({
        email: values.email,
        password: values.password,
        callbackURL: '/admin',
      });

      if (res?.error) {
        const is2FA =
          res.error.message?.toLowerCase().includes("two factor") ||
          res.error.message?.toLowerCase().includes("two-factor") ||
          (res.error as unknown as { code?: string }).code === "TWO_FACTOR_REQUIRED";
        if (is2FA) {
          navigate('/admin/two-factor');
          return;
        }
        const msg = res.error.message || 'Invalid administrator credentials';
        setError(msg);
        toast.error(msg);
        return;
      }

      if ((res?.data as { twoFactorRedirect?: boolean })?.twoFactorRedirect) {
        navigate('/admin/two-factor');
        return;
      }

      // Check role and isolation scope
      const getSessionFn = authClient.getSession as unknown as () => Promise<{
        data?: { user?: { role?: string; scopedClientId?: string | null } };
      }>;
      const userRes = await getSessionFn();
      const currentUser = userRes?.data?.user;

      if (isAppAdminUser(currentUser)) {
        await authClient.signOut({});
        const msg = 'Access denied: Application administrators are not authorized to access the central IdP console. Please sign in through your application portal.';
        setError(msg);
        toast.error(msg);
        form.setValue('password', '');
        return;
      }

      if (!isSuperAdminUser(currentUser)) {
        await authClient.signOut({});
        const msg = 'Access denied: Administrator privileges required for the platform console.';
        setError(msg);
        toast.error(msg);
        form.setValue('password', '');
        return;
      }

      toast.success('Signed in successfully');
      navigate('/admin');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Authentication service unavailable';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleSignOut = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await authClient.signOut({});
      if (res?.error) {
        const errorMsg = res.error.message || 'Failed to sign out current session. Please try again.';
        setError(errorMsg);
        toast.error(errorMsg);
        setLoading(false);
        return;
      }

      // Invalidate and refetch session state using supported SDK APIs
      if (typeof refetch === 'function') {
        await refetch();
      }

      // Verify that the server session is actually cleared
      const getSessionFn = authClient.getSession as unknown as () => Promise<{
        data?: { user?: unknown };
        error?: unknown;
      }>;
      const verified = await getSessionFn().catch(() => null);
      if (verified?.data?.user) {
        setError('Session is still active on server. Please retry account switch.');
        setLoading(false);
        return;
      }

      form.reset({ email: '', password: '' });
      setError(null);
      toast.success('Session cleared. Please sign in with administrator credentials.');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to clear session. Please retry.';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  if (isPending) {
    return <RouteLoader />;
  }

  const isAuthenticated = !!user;
  const isSuperAdmin = isSuperAdminUser(user);
  const isCurrentAppAdmin = isAppAdminUser(user);
  const isConflictingSession = isAuthenticated && !isSuperAdmin;

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
                Admin sign in
              </h1>
              <p className="font-sans text-xs text-muted-foreground mt-1">
                Enter your administrator credentials to access the console.
              </p>
            </div>

            {isConflictingSession ? (
              <div className="space-y-4">
                <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-4 text-xs">
                  <h4 className="font-sans font-medium text-amber-900 dark:text-amber-200 text-sm">
                    Active consumer session detected
                  </h4>
                  <div className="mt-2 space-y-1 text-muted-foreground">
                    <p>
                      Signed in as: <strong className="text-foreground">{user?.email}</strong>
                    </p>
                    <p className="text-[11px]">
                      Account role: <span className="font-medium text-foreground">{isCurrentAppAdmin ? 'Application Administrator' : 'Standard User'}</span>
                    </p>
                  </div>
                  <p className="font-sans text-muted-foreground mt-2 leading-relaxed text-[11px]">
                    The MAuth Platform Console is reserved exclusively for Global Super Administrators. Application administrators must manage their assigned application through their application portal.
                  </p>
                </div>
                {error && (
                  <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 font-sans text-xs text-destructive flex items-center gap-2">
                    <svg className="size-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span>{error}</span>
                  </div>
                )}
                <Button
                  type="button"
                  onClick={handleSignOut}
                  className="w-full h-10 font-medium"
                  disabled={loading}
                >
                  {loading ? 'Switching account...' : 'Sign in with a different account'}
                </Button>
                <div className="text-center">
                  <button
                    type="button"
                    onClick={() => { window.location.href = '/'; }}
                    className="font-sans text-xs text-muted-foreground hover:text-foreground underline underline-offset-4"
                  >
                    Return to home
                  </button>
                </div>
              </div>
            ) : (
              <Form {...form}>
                <form onSubmit={form.handleSubmit(handleSignIn)} className="space-y-4">
                  {error && (
                    <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 font-sans text-xs text-destructive flex items-center gap-2">
                      <svg className="size-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span>{error}</span>
                    </div>
                  )}

                  <FormField
                    control={form.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem className="space-y-1.5">
                        <FormLabel className="font-sans text-xs font-medium text-foreground">Email Address</FormLabel>
                        <FormControl>
                          <Input 
                            type="email" 
                            placeholder="admin@example.com" 
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
                    control={form.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem className="space-y-1.5">
                        <FormLabel className="font-sans text-xs font-medium text-foreground">Password</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Input 
                              type={showPassword ? "text" : "password"} 
                              placeholder="••••••••••••" 
                              {...field} 
                              disabled={loading} 
                              className="h-10 pr-10"
                            />
                            <button
                              type="button"
                              onClick={() => setShowPassword(!showPassword)}
                              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground focus:outline-none"
                              aria-label={showPassword ? "Hide password" : "Show password"}
                              tabIndex={-1}
                            >
                              {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                            </button>
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <Button type="submit" className="w-full h-10 font-medium mt-2" disabled={loading}>
                    {loading ? 'Signing in...' : 'Sign in to console'}
                  </Button>
                </form>
              </Form>
            )}

            <p className="font-sans text-[11px] text-muted-foreground text-center mt-6">
              Protected by two factor authentication.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
