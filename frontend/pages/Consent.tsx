import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';

/**
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * OAuth Consent Screen
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Shown when a third-party app requests access to a user's data.
 * First-party apps with skip_consent: true bypass this entirely.
 *
 * The OAuth Provider redirects here with:
 *   ?client_id=...&scope=openid+profile+email
 */
export const Consent: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const clientId = searchParams.get('client_id') || 'Unknown App';
  const rawScope = searchParams.get('scope') || 'openid profile email';
  const scopes = rawScope.split(' ').filter(Boolean);

  // Human-readable scope descriptions
  const scopeDescriptions: Record<string, { label: string; icon: string }> = {
    openid: { label: 'Verify your identity', icon: '🔐' },
    profile: { label: 'Access your name and profile picture', icon: '👤' },
    email: { label: 'Read your email address', icon: '📧' },
    offline_access: { label: 'Stay signed in on your behalf', icon: '🔄' },
  };

  const handleConsent = async (accept: boolean) => {
    setLoading(true);
    setError('');

    try {
      const { error: consentError } = await authClient.oauth2.consent({
        accept,
        scope: accept ? rawScope : undefined,
      });

      if (consentError) {
        setError(consentError.message || 'Consent failed.');
        setLoading(false);
      }
      // On success, Better Auth redirects back to the consuming app automatically.
    } catch {
      setError('Something went wrong. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-3xl px-6">
      <GlassSurface
        width="100%"
        height="auto"
        borderRadius={28}
        backgroundOpacity={0.14}
        blur={12}
        saturation={1.6}
        className="w-full max-w-lg mx-auto"
      >
        <div className="w-full px-8 py-10 text-left">
          <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">SWYRA Consent</p>
          <h1 className="mt-3 text-2xl font-semibold text-foreground">Authorize access</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            <span className="text-foreground font-medium">{clientId}</span> wants to access your account.
          </p>

          {error && (
            <div
              className="mt-6 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
              role="alert"
            >
              {error}
            </div>
          )}

          <div className="mt-6 rounded-2xl border border-border/60 bg-background/40 p-4">
            <p className="text-sm font-medium text-foreground">This application will be able to:</p>
            <ul className="mt-4 space-y-3 text-sm text-foreground">
              {scopes.map((scope) => {
                const desc = scopeDescriptions[scope] || { label: scope, icon: '📋' };
                return (
                  <li key={scope} className="flex items-start gap-3">
                    <span className="text-lg" aria-hidden="true">{desc.icon}</span>
                    <span className="text-muted-foreground">{desc.label}</span>
                  </li>
                );
              })}
            </ul>
          </div>

          <div className="mt-6 grid gap-3 sm:grid-cols-2">
            <Button
              type="button"
              className="w-full"
              onClick={() => handleConsent(true)}
              disabled={loading}
            >
              {loading ? 'Processing...' : 'Allow access'}
            </Button>
            <Button
              type="button"
              variant="outline"
              className="w-full"
              onClick={() => handleConsent(false)}
              disabled={loading}
            >
              Deny
            </Button>
          </div>

          <div className="my-6 flex items-center gap-4">
            <Separator className="flex-1" />
            <span className="text-[11px] uppercase tracking-[0.2em] text-muted-foreground">notice</span>
            <Separator className="flex-1" />
          </div>

          <p className="text-xs text-muted-foreground text-center">
            You can revoke access at any time from your account settings.
          </p>
        </div>
      </GlassSurface>
    </div>
  );
};
