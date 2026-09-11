import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { toast } from 'sonner';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';
import { Check, ShieldCheck } from 'lucide-react';

export const Consent: React.FC = () => {
  usePageTitle('Authorize application');
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);

  const clientId = searchParams.get('client_id') || 'Client Application';
  const rawScope = searchParams.get('scope') || 'openid profile email';
  const scopes = rawScope.split(' ').filter(Boolean);

  const scopeDescriptions: Record<string, { label: string; tag: string }> = {
    openid: {
      label: 'Verify your identity and authenticate your session',
      tag: 'Identity'
    },
    profile: {
      label: 'Access your profile information (name and avatar)',
      tag: 'Profile'
    },
    email: {
      label: 'View your verified account email address',
      tag: 'Email'
    },
    offline_access: {
      label: 'Maintain access when you are not actively using the application',
      tag: 'Offline access'
    },
  };

  const handleConsent = async (accept: boolean) => {
    setLoading(true);

    try {
      const oauth_query = searchParams.get('oauth_query') || undefined;
      const res = await authClient.oauth2.consent({
        accept,
        scope: accept ? rawScope : undefined,
        oauth_query,
      });

      if (res?.error) {
        toast.error(res.error.message || 'Consent failed.');
        setLoading(false);
      } else if (res?.data?.url) {
        window.location.assign(res.data.url);
      } else if (res?.data?.redirect) {
        setLoading(false);
      }
    } catch {
      toast.error('Authorization failed. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6 sm:p-12 bg-background">
      <div className="w-full max-w-[520px]">
        {/* Featured consent dialog with selective motorsport accent */}
        <Card accent="motorsport" className="w-full shadow-xl border-border">
          <CardContent className="p-8 sm:p-[34px]">
            <div className="flex items-center justify-between mb-6">
              <BrandMark size="md" />
              <span className="font-mono text-[11px] text-muted-foreground border border-border px-2 py-0.5 rounded-sm">
                OAuth 2.1
              </span>
            </div>

            <div className="mb-6">
              <h1 className="font-heading text-[28px] sm:text-[34px] leading-tight font-semibold text-foreground">
                Authorize application
              </h1>
              <p className="font-sans text-sm text-muted-foreground mt-2">
                <span className="font-mono font-medium text-foreground bg-secondary px-1.5 py-0.5 rounded border border-border">
                  {clientId}
                </span>{' '}
                is requesting permission to access your M Auth account:
              </p>
            </div>

            <div className="rounded-[12px] border border-border bg-secondary/40 p-5 mb-8 space-y-4">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Requested permissions
              </div>

              <div className="space-y-3">
                {scopes.map((scope) => {
                  const info = scopeDescriptions[scope] || {
                    label: `Custom permission: ${scope}`,
                    tag: scope,
                  };

                  return (
                    <div key={scope} className="flex items-start gap-3">
                      <div className="mt-0.5 flex size-4 shrink-0 items-center justify-center rounded bg-primary/10 text-primary border border-primary/20">
                        <Check className="size-2.5" strokeWidth={3} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-foreground">
                            {info.tag}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">
                          {info.label}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <Button
                type="button"
                variant="outline"
                className="h-10"
                onClick={() => handleConsent(false)}
                disabled={loading}
              >
                Deny
              </Button>
              <Button
                type="button"
                className="h-10"
                onClick={() => handleConsent(true)}
                disabled={loading}
              >
                {loading ? 'Authorizing...' : 'Authorize'}
              </Button>
            </div>

            <div className="flex items-center justify-center gap-1.5 text-xs text-muted-foreground mt-6 text-center">
              <ShieldCheck className="size-3.5 text-primary" />
              <span>You can revoke this application's access at any time.</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
