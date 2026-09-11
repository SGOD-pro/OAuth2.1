import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { authClient, useSession } from '@/lib/auth-client';
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

const adminLoginSchema = z.object({
  email: z.string().email({ message: "Invalid email address" }),
  password: z.string().min(1, { message: "Password is required" }),
});

export const AdminLogin: React.FC = () => {
  usePageTitle('Admin sign in');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const { data: session, isPending } = useSession();

  const form = useForm<z.infer<typeof adminLoginSchema>>({
    resolver: zodResolver(adminLoginSchema),
    defaultValues: {
      email: '',
      password: '',
    },
  });

  useEffect(() => {
    const err = searchParams.get('error');
    if (err === 'access_denied') {
      toast.error('Access denied: Your account does not have admin privileges.');
    } else if (err === 'mfa_failed' || err === 'mfa_expired') {
      toast.error('2FA verification failed or session expired. Please re-enter your credentials.');
    }
  }, [searchParams]);

  const user = (session as unknown as { user?: { role?: string } })?.user;

  useEffect(() => {
    if (!isPending && user) {
      if (user.role === 'admin') {
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
        if (res.error.message?.toLowerCase().includes("two factor") || res.error.status === 403) {
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

      // Check role
      const getSessionFn = authClient.getSession as unknown as () => Promise<{ data?: { user?: { role?: string } } }>;
      const userRes = await getSessionFn();
      const userRole = userRes?.data?.user?.role;
      if (userRole !== 'admin') {
        setError('Access denied: Administrator privileges required.');
        toast.error('Access denied: Administrator privileges required.');
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
    try {
      await authClient.signOut({});
    } catch {
      // ignore
    }
    navigate('/admin/login');
    setLoading(false);
  };

  if (isPending) {
    return <RouteLoader />;
  }

  const role = user?.role;
  const isAuthenticated = !!user;

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

            {isAuthenticated && role !== 'admin' ? (
              <div className="space-y-4">
                <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3.5">
                  <h4 className="font-sans text-xs font-medium text-destructive">Access Restricted</h4>
                  <p className="font-sans text-xs text-muted-foreground mt-1">
                    Your account does not have administrator privileges.
                  </p>
                </div>
                <Button onClick={handleSignOut} variant="outline" className="w-full h-9 text-xs">
                  Sign out & switch account
                </Button>
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

                  <Button type="submit" className="w-full h-10 font-medium mt-2" disabled={loading}>
                    {loading ? 'Signing in...' : 'Sign in to console'}
                  </Button>
                </form>
              </Form>
            )}

            <p className="font-sans text-[11px] text-muted-foreground text-center mt-6">
              Protected by two-factor authentication.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
