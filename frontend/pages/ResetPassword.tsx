import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { toast } from 'sonner';
import { isStrongPassword } from '@/lib/security';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';
import { CheckCircle2, ArrowLeft } from 'lucide-react';

const resetPasswordSchema = z.object({
  password: z.string().min(12, { message: "Password must be at least 12 characters" }),
  confirmPassword: z.string().min(12, { message: "Please confirm your password" }),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

export const ResetPassword: React.FC = () => {
  usePageTitle('Set new password');
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
      toast.success('Password updated successfully');
      setTimeout(() => navigate('/auth'), 2500);
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6 sm:p-12 bg-background">
      <div className="w-full max-w-[460px]">
        <Card className="w-full shadow-lg border-border">
          <CardContent className="p-8 sm:p-[34px]">
            <div className="mb-8">
              <div className="flex items-center justify-between mb-4">
                <BrandMark size="md" />
                <span className="font-mono text-[11px] text-muted-foreground border border-border px-2 py-0.5 rounded-sm">
                  OAuth 2.1
                </span>
              </div>
              <h1 className="font-heading text-[34px] leading-tight font-semibold text-foreground">
                Set new password
              </h1>
              <p className="font-sans text-sm text-muted-foreground mt-2">
                Create a strong password of at least 12 characters.
              </p>
            </div>

            {success ? (
              <div className="space-y-6">
                <div className="rounded-[12px] border border-border bg-secondary/50 p-6 text-center">
                  <div className="mx-auto size-11 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-500 mb-3">
                    <CheckCircle2 className="size-5" />
                  </div>
                  <h3 className="font-heading text-base font-semibold text-foreground mb-1">
                    Password updated
                  </h3>
                  <p className="font-sans text-xs text-muted-foreground leading-relaxed">
                    Your password has been changed. Redirecting to sign in...
                  </p>
                </div>

                <Button asChild variant="outline" className="w-full">
                  <Link to="/auth" className="flex items-center justify-center gap-2">
                    <ArrowLeft className="size-4" /> Go to sign in now
                  </Link>
                </Button>
              </div>
            ) : (
              <div className="space-y-6">
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(handleReset)} className="space-y-4">
                    <FormField
                      control={form.control}
                      name="password"
                      render={({ field }) => (
                        <FormItem className="space-y-1.5">
                          <FormLabel className="text-xs font-medium text-foreground">New password</FormLabel>
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
                        <FormItem className="space-y-1.5">
                          <FormLabel className="text-xs font-medium text-foreground">Confirm new password</FormLabel>
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

                    <div className="pt-2">
                      <Button type="submit" className="w-full h-10" disabled={loading}>
                        {loading ? 'Updating password...' : 'Update password'}
                      </Button>
                    </div>
                  </form>
                </Form>

                <div className="pt-2 border-t border-border text-center">
                  <Link
                    to="/auth"
                    className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <ArrowLeft className="size-3.5" /> Back to sign in
                  </Link>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
