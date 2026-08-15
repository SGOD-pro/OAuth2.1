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
    return <RouteLoader />;
  }

  const role = (session?.user as { role?: string })?.role;
  const isAuthenticated = !!session?.user;

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6 sm:p-12 bg-background relative selection:bg-accent selection:text-accent-foreground">
      {/* Subtle telemetry grid */}
      <div 
        className="fixed inset-0 pointer-events-none opacity-[0.02] -z-10"
        style={{
          backgroundImage: `radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)`,
          backgroundSize: '24px 24px'
        }}
      />

      <div className="w-full max-w-[460px]">
        <Card className="w-full">
          <CardContent className="p-8 sm:p-[34px]">
            <div className="flex items-center gap-3 mb-6">
              <div className="flex h-3.5 gap-0.5 items-center">
                <div className="w-[3px] h-3.5 bg-[#0066B1] -skew-x-12" />
                <div className="w-[3px] h-3.5 bg-[#1C69D4] -skew-x-12" />
                <div className="w-[3px] h-3.5 bg-[#E22718] -skew-x-12" />
              </div>
              <span className="font-mono text-xs uppercase tracking-[0.2em] text-muted-foreground">
                <span className="text-foreground font-medium">SWYRA //</span> M Admin Portal
              </span>
            </div>

            <div className="mb-8">
              <h1 className="font-heading text-[34px] leading-[1.2] tracking-[-0.02em] font-normal text-foreground">
                Console Access
              </h1>
              <p className="font-sans text-sm text-muted-foreground mt-2">
                SWYRA restricted telemetry control surface. M Auth administrative credentials required.
              </p>
            </div>

            {isAuthenticated && role !== 'admin' ? (
              <div className="space-y-6">
                <div className="rounded-[16px] border border-destructive/30 bg-destructive/5 p-5">
                  <h4 className="font-sans text-sm font-medium text-destructive">Access Restricted</h4>
                  <p className="font-sans text-xs text-muted-foreground mt-1">
                    Authenticated account does not possess administrator privileges.
                  </p>
                </div>
                <Button onClick={handleSignOut} variant="outline" className="w-full">
                  Sign Out & Switch Account
                </Button>
              </div>
            ) : (
              <Form {...form}>
                <form onSubmit={form.handleSubmit(handleSignIn)} className="space-y-[21px]">
                  <FormField
                    control={form.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem className="space-y-1">
                        <FormLabel>Admin Identifier</FormLabel>
                        <FormControl>
                          <Input 
                            type="email" 
                            placeholder="admin@swyra.com" 
                            {...field} 
                            disabled={loading} 
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
                      <FormItem className="space-y-1">
                        <FormLabel>Admin Password</FormLabel>
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

                  <Button type="submit" className="w-full mt-4" disabled={loading}>
                    {loading ? 'Authenticating...' : 'Access Telemetry Console'}
                  </Button>
                </form>
              </Form>
            )}

            <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground text-center mt-8">
              M-Series Cryptographic Session Enforcement
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
