import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { toast } from 'sonner';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';

const forgotPasswordSchema = z.object({
  email: z.string().email({ message: "Invalid email address" }),
});

export const ForgotPassword: React.FC = () => {
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
    <div className="w-full max-w-md px-4 mx-auto">
      <div className="glass-card rounded-[22px] p-8 w-full transition-all duration-300 relative overflow-hidden">
        <div className="text-left z-10 relative">
          <div className="flex items-center gap-3 mb-6">
            <div className="h-10 w-10 rounded-2xl border border-white/10 bg-black/10 dark:bg-white/10 flex items-center justify-center backdrop-blur-md">
              <span className="text-sm font-semibold">SW</span>
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground font-mono">Recovery</p>
              <h1 className="text-xl font-semibold text-foreground font-heading">Reset Password</h1>
            </div>
          </div>

          {success ? (
            <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
               <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-6 text-center">
                 <div className="mx-auto h-12 w-12 rounded-full bg-emerald-500/20 flex items-center justify-center mb-4">
                   <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-emerald-500"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></svg>
                 </div>
                 <h3 className="text-lg font-semibold text-emerald-600 dark:text-emerald-400 mb-2">Check your inbox</h3>
                 <p className="text-sm text-emerald-600/80 dark:text-emerald-400/80 leading-relaxed">
                   We've sent a password reset link to <br/>
                   <strong className="font-medium">{submittedEmail}</strong>
                 </p>
               </div>
            </div>
          ) : (
            <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
              <p className="text-sm text-muted-foreground mb-6 leading-relaxed">
                Enter your email address and we'll send you a link to reset your password.
              </p>
              <Form {...form}>
                <form onSubmit={form.handleSubmit(handleReset)} className="space-y-4">
                  <FormField
                    control={form.control}
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
                  <Button type="submit" className="w-full rounded-full mt-2" disabled={loading}>
                    {loading ? 'Sending link...' : 'Send reset link'}
                  </Button>
                </form>
              </Form>
            </div>
          )}

          <div className="my-6 flex items-center gap-4">
            <Separator className="flex-1" />
            <span className="text-xs uppercase tracking-widest text-muted-foreground font-mono">or</span>
            <Separator className="flex-1" />
          </div>

          <Link to="/auth" viewTransition className="block w-full text-center">
            <Button variant="outline" className="w-full rounded-full bg-white/50 dark:bg-black/20 hover:bg-white/80 dark:hover:bg-black/40 border-white/20 backdrop-blur-sm">
               Back to login
            </Button>
          </Link>
        </div>
      </div>
      <p className="text-center mt-6 text-xs text-foreground/50 font-mono tracking-widest uppercase">
        Protected by Nexus Security Policies
      </p>
    </div>
  );
};
