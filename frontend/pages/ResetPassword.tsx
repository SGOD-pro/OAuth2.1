import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { Card, CardContent } from '@/components/ui/card';
import { toast } from 'sonner';
import { isStrongPassword } from '@/lib/security';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';

const resetPasswordSchema = z.object({
  password: z.string().min(12, { message: "Password must be at least 12 characters" }),
  confirmPassword: z.string().min(12, { message: "Please confirm your password" }),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

export const ResetPassword: React.FC = () => {
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const form = useForm<z.infer<typeof resetPasswordSchema>>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: {
      password: '',
      confirmPassword: '',
    },
  });

  const handleReset = async (values: z.infer<typeof resetPasswordSchema>) => {
    setLoading(true);

    if (!isStrongPassword(values.password)) {
      form.setError('password', { message: 'Password must include uppercase, lowercase, number, and symbol.' });
      setLoading(false);
      return;
    }

    const token = searchParams.get('token');
    if (!token) {
      toast.error('Invalid or expired reset link.');
      setLoading(false);
      return;
    }

    const { error: authError } = await authClient.resetPassword({
      newPassword: values.password,
      token,
    });

    if (authError) {
      toast.error(authError.message || 'Failed to reset password.');
    } else {
      setSuccess(true);
      toast.success('Password updated successfully!');
      setTimeout(() => navigate('/auth', { viewTransition: true }), 3000);
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6 sm:p-12">
      <div className="w-full max-w-[460px]">
        <Card className="w-full">
          <CardContent className="p-8 sm:p-[34px]">
            <div className="mb-8">
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                  <span className="text-foreground font-medium">SWYRA //</span> M Auth Re-Key
                </span>
                <span className="font-mono text-[10px] uppercase text-accent border border-accent/30 rounded-pill px-2 py-0.5">
                  Re-keying
                </span>
              </div>
              <h1 className="font-heading text-[34px] leading-[1.2] tracking-[-0.02em] font-normal text-foreground">
                Set New Key
              </h1>
            </div>

            {success ? (
              <div className="animate-in fade-in duration-300 space-y-6">
                <div className="rounded-[16px] border border-accent/30 bg-accent/5 p-[21px] text-center backdrop-blur-md">
                  <div className="mx-auto size-10 rounded-full bg-accent/10 flex items-center justify-center text-accent mb-3">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                      <polyline points="22 4 12 14.01 9 11.01" />
                    </svg>
                  </div>
                  <h3 className="font-sans text-sm font-medium text-foreground mb-1">
                    Credentials Re-keyed
                  </h3>
                  <p className="font-sans text-xs text-muted-foreground leading-relaxed">
                    Your master access key has been successfully updated. Redirecting to authentication console...
                  </p>
                </div>
              </div>
            ) : (
              <div className="animate-in fade-in duration-300">
                <p className="font-sans text-sm text-muted-foreground mb-6 leading-relaxed">
                  Establish a hardened passphrase for your telemetry session. Must contain 12+ characters.
                </p>

                <Form {...form}>
                  <form onSubmit={form.handleSubmit(handleReset)} className="space-y-[21px]">
                    <FormField
                      control={form.control}
                      name="password"
                      render={({ field }) => (
                        <FormItem className="space-y-1">
                          <FormLabel>New Access Password</FormLabel>
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
                      control={form.control}
                      name="confirmPassword"
                      render={({ field }) => (
                        <FormItem className="space-y-1">
                          <FormLabel>Confirm Password</FormLabel>
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
                      {loading ? 'Updating Credentials...' : 'Save & Authenticate'}
                    </Button>
                  </form>
                </Form>
              </div>
            )}

            <div className="my-[21px] flex items-center gap-4">
              <Separator className="flex-1" />
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                NAVIGATION
              </span>
              <Separator className="flex-1" />
            </div>

            <Button asChild variant="outline" className="w-full">
              <Link to="/auth" viewTransition>
                Return to Authenticate
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
