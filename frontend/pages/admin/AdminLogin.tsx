import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { authClient, useSession } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { toast } from 'sonner';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';

const adminLoginSchema = z.object({
  email: z.string().email({ message: "Invalid email address" }),
  password: z.string().min(1, { message: "Password is required" }),
});

export const AdminLogin: React.FC = () => {
  const [loading, setLoading] = useState(false);
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
    if (searchParams.get('error') === 'access_denied') {
      toast.error('Your account does not have admin access.');
    }
  }, [searchParams]);

  useEffect(() => {
    if (!isPending && session?.user) {
      const role = (session.user as { role?: string }).role;
      if (role === 'admin') {
        navigate('/admin', { replace: true, viewTransition: true });
      }
    }
  }, [session, isPending, navigate]);

  const handleSignIn = async (values: z.infer<typeof adminLoginSchema>) => {
    setLoading(true);

    const { error: authError } = await authClient.signIn.email({
      email: values.email,
      password: values.password,
      callbackURL: '/admin',
    });

    if (authError) {
      if (authError.message?.toLowerCase().includes("two factor") || authError.status === 403) {
        // Handled by the auth-client plugin redirect.
        return;
      }
      toast.error(authError.message || 'Invalid credentials');
      setLoading(false);
      return;
    }

    toast.success('Signed in successfully');
    navigate('/admin', { replace: true, viewTransition: true });
    setLoading(false);
  };

  const handleSignOut = async () => {
    setLoading(true);
    await authClient.signOut();
    navigate('/admin/login', { viewTransition: true });
    setLoading(false);
  };

  if (isPending) {
    return (
      <div className="w-full h-dvh px-6 grid place-items-center relative">
        <div className="fixed inset-0 top-0 left-0 bg-mesh-warm dark:bg-mesh-cool bg-noise -z-10" />
        <div className="w-full max-w-md mx-auto">
          <div className="glass-card rounded-[22px] p-12 flex items-center justify-center">
            <div className="h-10 w-10 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          </div>
        </div>
      </div>
    );
  }

  const role = (session?.user as { role?: string })?.role;
  const isAuthenticated = !!session?.user;

  return (
    <div className="w-full h-dvh px-6 grid place-items-center relative">
      <div className="fixed inset-0 top-0 left-0 bg-mesh-warm dark:bg-mesh-cool bg-noise -z-10" />
      
      <div className="w-full max-w-md mx-auto">
        <div className="glass-card rounded-[22px] p-8 w-full transition-all duration-300 relative overflow-hidden">
          <div className="text-left z-10 relative">
            <div className="flex items-center gap-3 mb-6">
              <div className="h-10 w-10 rounded-2xl bg-primary flex items-center justify-center text-primary-foreground shadow-sm">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-sparkle"><path d="M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594z" /></svg>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.18em] text-primary font-mono">NexusID</p>
                <h1 className="text-xl font-semibold text-foreground font-heading">Admin Console</h1>
              </div>
            </div>

            {isAuthenticated && role !== 'admin' ? (
              <div className="mt-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                <div className="rounded-2xl border border-destructive/30 bg-destructive/10 p-5 text-sm text-destructive mb-6 text-center">
                  <div className="mx-auto h-10 w-10 rounded-full bg-destructive/20 flex items-center justify-center mb-3">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                  </div>
                  <p className="mb-2">Access Denied</p>
                  <p className="text-xs text-destructive/80">
                    You are currently signed in as <strong className="font-medium text-destructive">{session.user.email}</strong>, but do not have administrative privileges.
                  </p>
                </div>
                <Button onClick={handleSignOut} variant="outline" className="w-full rounded-full" disabled={loading}>
                  {loading ? 'Signing out...' : 'Sign out'}
                </Button>
              </div>
            ) : (
              <div className="mt-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                <p className="text-sm text-muted-foreground mb-6 leading-relaxed">
                  Enter your credentials to access the central administration panel.
                </p>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(handleSignIn)} className="space-y-4">
                    <FormField
                      control={form.control}
                      name="email"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Email address</FormLabel>
                          <FormControl>
                            <Input placeholder="admin@nexusid.com" {...field} disabled={loading} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={form.control}
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
                    <Button type="submit" className="w-full rounded-full mt-4" disabled={loading}>
                      {loading ? 'Authenticating...' : 'Sign in to Admin'}
                    </Button>
                  </form>
                </Form>
              </div>
            )}

            <div className="my-6 flex items-center gap-4">
              <Separator className="flex-1" />
              <span className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-mono">secure zone</span>
              <Separator className="flex-1" />
            </div>

            <p className="text-xs text-muted-foreground/70 text-center px-4 leading-relaxed">
              This area is restricted to authorized personnel only. All access attempts are logged.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
