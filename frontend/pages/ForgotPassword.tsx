import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { toast } from 'sonner';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';
import { CheckCircle2, ArrowLeft } from 'lucide-react';

const forgotPasswordSchema = z.object({
  email: z.string().email({ message: "Invalid email address" }),
});

export const ForgotPassword: React.FC = () => {
  usePageTitle('Reset password');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const [submittedEmail, setSubmittedEmail] = useState('');

  const form = useForm<z.infer<typeof forgotPasswordSchema>>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: {
      email: '',
    },
  });

  const handleReset = async (values: z.infer<typeof forgotPasswordSchema>) => {
    setLoading(true);

    const { error: authError } = await authClient.requestPasswordReset({
      email: values.email,
      redirectTo: '/reset-password',
    });

    if (authError) {
      toast.error(authError.message || 'Failed to send reset email.');
    } else {
      setSubmittedEmail(values.email);
      setSuccess(true);
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
                Reset password
              </h1>
              <p className="font-sans text-sm text-muted-foreground mt-2">
                Enter your account email to receive a password reset link.
              </p>
            </div>

            {success ? (
              <div className="space-y-6">
                <div className="rounded-[12px] border border-border bg-secondary/50 p-6 text-center">
                  <div className="mx-auto size-11 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-500 mb-3">
                    <CheckCircle2 className="size-5" />
                  </div>
                  <h3 className="font-heading text-base font-semibold text-foreground mb-1">
                    Reset link sent
                  </h3>
                  <p className="font-sans text-xs text-muted-foreground leading-relaxed">
                    We sent instructions to <br />
                    <span className="font-mono text-foreground font-medium">{submittedEmail}</span>
                  </p>
                </div>

                <Button asChild variant="outline" className="w-full">
                  <Link to="/auth" className="flex items-center justify-center gap-2">
                    <ArrowLeft className="size-4" /> Back to sign in
                  </Link>
                </Button>
              </div>
            ) : (
              <div className="space-y-6">
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(handleReset)} className="space-y-5">
                    <FormField
                      control={form.control}
                      name="email"
                      render={({ field }) => (
                        <FormItem className="space-y-1.5">
                          <FormLabel className="text-xs font-medium text-foreground">Email address</FormLabel>
                          <FormControl>
                            <Input 
                              type="email" 
                              placeholder="name@company.com" 
                              {...field} 
                              disabled={loading} 
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <Button type="submit" className="w-full h-10" disabled={loading}>
                      {loading ? 'Sending link...' : 'Send reset link'}
                    </Button>
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
