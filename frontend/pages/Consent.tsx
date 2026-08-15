import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { toast } from 'sonner';

export const Consent: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);

  const clientId = searchParams.get('client_id') || 'Client Application';
  const rawScope = searchParams.get('scope') || 'openid profile email';
  const scopes = rawScope.split(' ').filter(Boolean);

  const scopeDescriptions: Record<string, { label: string; tag: string }> = {
    openid: { 
      label: 'Cryptographic identity attestation and token verification', 
      tag: 'OPENID' 
    },
    profile: { 
      label: 'Read telemetry profile (name, avatar, locale preference)', 
      tag: 'PROFILE' 
    },
    email: { 
      label: 'Read primary verified pilot email address', 
      tag: 'EMAIL' 
    },
    offline_access: { 
      label: 'Maintain background refresh telemetry token', 
      tag: 'REFRESH' 
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
    <div className="min-h-screen w-full flex items-center justify-center p-6 sm:p-12">
      <div className="w-full max-w-[520px]">
        <Card className="w-full">
          <CardContent className="p-8 sm:p-[34px]">
            <div className="flex items-center justify-between mb-6">
              <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                <span className="text-foreground font-medium">SWYRA //</span> M Telemetry Grant
              </span>
              <span className="font-mono text-[10px] uppercase text-accent border border-accent/30 rounded-pill px-2.5 py-0.5">
                OAuth 2.1
              </span>
            </div>

            <div className="mb-8">
              <h1 className="font-heading text-[34px] leading-[1.2] tracking-[-0.02em] font-normal text-foreground">
                Authorize Client
              </h1>
              <p className="font-sans text-sm text-muted-foreground mt-2">
                Application <span className="font-mono text-foreground font-medium px-1.5 py-0.5 rounded bg-secondary/80">{clientId}</span> is requesting delegated telemetry scopes:
              </p>
            </div>

            <div className="rounded-[16px] border border-border/60 bg-secondary/30 p-5 mb-8 space-y-4">
              <div className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                Requested Scopes:
              </div>

              <div className="space-y-3">
                {scopes.map((scope) => {
                  const info = scopeDescriptions[scope] || {
                    label: `Custom telemetry permission (${scope})`,
                    tag: scope.toUpperCase(),
                  };

                  return (
                    <div key={scope} className="flex items-start gap-3">
                      <div className="mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-[3px] border border-accent bg-accent/10 text-accent">
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-medium text-foreground tracking-wide">
                            {info.tag}
                          </span>
                        </div>
                        <p className="font-sans text-xs text-muted-foreground mt-0.5 leading-relaxed">
                          {info.label}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => handleConsent(false)}
                disabled={loading}
              >
                Deny Access
              </Button>
              <Button
                type="button"
                onClick={() => handleConsent(true)}
                disabled={loading}
              >
                {loading ? 'Authorizing...' : 'Authorize'}
              </Button>
            </div>

            <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground text-center mt-6">
              SWYRA M-Series Cryptographic Session Enforcement
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
