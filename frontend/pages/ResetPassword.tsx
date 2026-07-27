import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
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
      toast.success('Password reset successfully!');
      setTimeout(() => navigate('/auth', { viewTransition: true }), 3000);
    }
    setLoading(false);
  };

  return (
    <div className="w-full max-w-md px-4 mx-auto">
      <div className="glass-card rounded-[22px] p-8 w-full transition-all duration-300 relative overflow-hidden">
        <div className="text-left z-10 relative">
          <div className="flex items-center gap-3 mb-6">
            <div className="h-10 w-10 rounded-2xl border border-white/10 bg-black/10 dark:bg-white/10 flex items-center justify-center backdrop-blur-md">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-foreground"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground font-mono">Security</p>
              <h1 className="text-xl font-semibold text-foreground font-heading">Set new password</h1>
            </div>
          </div>

          {success ? (
            <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
               <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-6 text-center">
                 <div className="mx-auto h-12 w-12 rounded-full bg-emerald-500/20 flex items-center justify-center mb-4">
                   <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-emerald-500"><polyline points="20 6 9 17 4 12" /></svg>
                 </div>
                 <h3 className="text-lg font-semibold text-emerald-600 dark:text-emerald-400 mb-2">Password Updated</h3>
                 <p className="text-sm text-emerald-600/80 dark:text-emerald-400/80 leading-relaxed">
                   Your password has been successfully reset. <br/> Redirecting to sign in...
                 </p>
               </div>
            </div>
          ) : (
            <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
              <p className="text-sm text-muted-foreground mb-6 leading-relaxed">
                Choose a strong password you do not use elsewhere.
              </p>
              <Form {...form}>
                <form onSubmit={form.handleSubmit(handleReset)} className="space-y-4">
                  <FormField
                    control={form.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>New password</FormLabel>
                        <FormControl>
                          <Input type="password" placeholder="••••••••" {...field} disabled={loading} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="confirmPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Confirm password</FormLabel>
                        <FormControl>
                          <Input type="password" placeholder="••••••••" {...field} disabled={loading} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  
                  {/* Visual password strength indicator */}
                  {form.watch('password').length > 0 && (
                    <div className="w-full flex gap-1 mt-2 mb-4">
                      <div className={`h-1 flex-1 rounded-full ${form.watch('password').length > 0 ? 'bg-destructive' : 'bg-border'} transition-colors`} />
                      <div className={`h-1 flex-1 rounded-full ${form.watch('password').length >= 8 ? 'bg-orange-400' : 'bg-border'} transition-colors`} />
                      <div className={`h-1 flex-1 rounded-full ${isStrongPassword(form.watch('password')) ? 'bg-ring' : 'bg-border'} transition-colors`} />
                    </div>
                  )}

                  <Button type="submit" className="w-full rounded-full mt-2" disabled={loading}>
                    {loading ? 'Resetting...' : 'Reset password'}
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
            <Button type="button" variant="outline" className="w-full rounded-full bg-white/50 dark:bg-black/20 hover:bg-white/80 dark:hover:bg-black/40 border-white/20 backdrop-blur-sm">
               Back to sign in
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
