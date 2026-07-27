import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { toast } from 'sonner';

export const Consent: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);

  const clientId = searchParams.get('client_id') || 'Unknown App';
  const rawScope = searchParams.get('scope') || 'openid profile email';
  const scopes = rawScope.split(' ').filter(Boolean);

  const scopeDescriptions: Record<string, { label: string; icon: React.ReactNode }> = {
    openid: { 
      label: 'Verify your identity', 
      icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
    },
    profile: { 
      label: 'Access your basic profile information', 
      icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
    },
    email: { 
      label: 'Read your email address', 
      icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" /><polyline points="22,6 12,13 2,6" /></svg>
    },
    offline_access: { 
      label: 'Maintain access when you are not active', 
      icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary"><path d="M2 12a10 10 0 1 0 20 0 10 10 0 1 0-20 0" /><path d="M12 6v6l4 2" /></svg>
    },
  };

  const handleConsent = async (accept: boolean) => {
    setLoading(true);

    try {
      const { error: consentError } = await authClient.oauth2.consent({
        accept,
        scope: accept ? rawScope : undefined,
      });

      if (consentError) {
        toast.error(consentError.message || 'Consent failed.');
        setLoading(false);
      }
    } catch {
      toast.error('Something went wrong. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md px-4 mx-auto">
      <div className="glass-card rounded-[22px] p-8 w-full transition-all duration-300 relative overflow-hidden">
        <div className="text-left z-10 relative">
          <div className="flex flex-col items-center justify-center text-center mb-8">
            <div className="flex items-center gap-4 mb-6">
               <div className="h-16 w-16 rounded-2xl bg-card border border-border shadow-sm flex items-center justify-center">
                 <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-muted-foreground"><rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" /></svg>
               </div>
               <div className="flex flex-col gap-1 items-center justify-center">
                 <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/30" />
                 <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50" />
                 <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/80" />
               </div>
               <div className="h-16 w-16 rounded-2xl border border-white/10 bg-black/10 dark:bg-white/10 flex items-center justify-center backdrop-blur-md">
                 <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-foreground"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
               </div>
            </div>
            
            <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground font-mono mb-2">Authorization Request</p>
            <h1 className="text-2xl font-semibold text-foreground font-heading leading-tight">
              <span className="text-primary font-bold">{clientId}</span> wants to access your account
            </h1>
          </div>

          <div className="rounded-2xl border border-border/50 bg-muted/20 p-5 mb-8">
            <p className="text-sm font-medium text-foreground mb-4">This application will be able to:</p>
            <ul className="space-y-4 text-sm text-foreground">
              {scopes.map((scope) => {
                const desc = scopeDescriptions[scope] || { 
                  label: scope, 
                  icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" /></svg> 
                };
                return (
                  <li key={scope} className="flex items-start gap-4">
                    <div className="mt-0.5 opacity-80">{desc.icon}</div>
                    <span className="text-muted-foreground leading-relaxed">{desc.label}</span>
                  </li>
                );
              })}
            </ul>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <Button
              type="button"
              variant="outline"
              className="w-full rounded-full bg-white/50 dark:bg-black/20 hover:bg-white/80 dark:hover:bg-black/40 border-white/20 backdrop-blur-sm"
              onClick={() => handleConsent(false)}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button
              type="button"
              className="w-full rounded-full"
              onClick={() => handleConsent(true)}
              disabled={loading}
            >
              {loading ? 'Processing...' : 'Authorize'}
            </Button>
          </div>

          <div className="my-6 flex items-center gap-4">
            <Separator className="flex-1" />
            <span className="text-xs uppercase tracking-widest text-muted-foreground font-mono">notice</span>
            <Separator className="flex-1" />
          </div>

          <p className="text-xs text-muted-foreground text-center px-4 leading-relaxed">
            You can manage or revoke access at any time from your account settings.
          </p>
        </div>
      </div>
      <p className="text-center mt-6 text-xs text-foreground/50 font-mono tracking-widest uppercase">
        Protected by Nexus Security Policies
      </p>
    </div>
  );
};
