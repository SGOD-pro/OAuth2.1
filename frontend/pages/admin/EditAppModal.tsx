import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Badge } from '@/components/ui/badge';
import { csrfHeaders } from '@/lib/csrf';
import { validateClientRedirectUri, validateUri, deriveOrigins } from '@/lib/security';
import { apiFetch } from '@/lib/api';
import { useSession } from '@/lib/auth-client';
import { isSuperAdminUser } from '@/lib/role-predicates';
import type { OAuthClient } from '@/lib/adminStore-types';
import { ClientTagInput } from './ClientTagInput';
import { ClientPolicyControls, ClientSecretOneTimeCard } from './ClientPolicyControls';
import { resolveDisplayPolicy } from './ClientPolicyBadges';
import { ClientAmbiguityBanner, ClientTransitionWarnings } from './EditAppTransitionBanners';

interface EditAppModalProps {
  client: OAuthClient;
  onClose: () => void;
  onSuccess: (client: OAuthClient) => void;
}

export const EditAppModal: React.FC<EditAppModalProps> = ({ client, onClose, onSuccess }) => {
  const { data: session } = useSession();
  const canEditPolicy = isSuperAdminUser((session as { user?: { role?: string; scopedClientId?: string | null } } | null)?.user);
  const initialPolicy = resolveDisplayPolicy(client);

  const initialUris = client.redirect_uris ?? client.redirectUris ?? [];
  const initialOrigins = client.allowed_origins ?? client.allowedOrigins ?? client.metadata?.allowedOrigins ?? [];

  const [redirectUris, setRedirectUris] = useState<string[]>(initialUris);
  const [allowedOrigins, setAllowedOrigins] = useState<string[]>(initialOrigins);
  const [clientType, setClientType] = useState<'public' | 'confidential'>(initialPolicy.clientType);
  const [accessPolicy, setAccessPolicy] = useState<'open' | 'private'>(initialPolicy.accessPolicy);
  const [isDev, setIsDev] = useState<boolean>(initialPolicy.isDev);
  const [skipConsent, setSkipConsent] = useState<boolean>(Boolean(client.skip_consent));
  const [enableEndSession, setEnableEndSession] = useState<boolean>(Boolean(client.enable_end_session));
  const [isActive, setIsActive] = useState<boolean>(!client.disabled);

  const [confirmSecretRevoke, setConfirmSecretRevoke] = useState(false);
  const [confirmWideningOpen, setConfirmWideningOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reasonCodes, setReasonCodes] = useState<string[]>(client.ambiguityReasonCodes || []);
  const [reasons, setReasons] = useState<string[]>(client.ambiguityReasons || []);
  const [generatedSecret, setGeneratedSecret] = useState<string | null>(null);
  const [savedClient, setSavedClient] = useState<OAuthClient | null>(null);
  const [success, setSuccess] = useState(false);

  const needsSecretRevokeConfirm = initialPolicy.clientType === 'confidential' && clientType === 'public' && Boolean(client.hasClientSecret);
  const needsWideningOpenConfirm = initialPolicy.accessPolicy === 'private' && accessPolicy === 'open' && !initialPolicy.isAmbiguous;
  const needsPublicToConfidential = initialPolicy.clientType === 'public' && clientType === 'confidential';

  useEffect(() => {
    let mounted = true;
    apiFetch(`/api/admin/clients/${client.client_id}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!mounted || !data) return;
        const uris = (data.redirect_uris ?? data.redirectUris ?? []) as string[];
        const origins = (data.allowed_origins ?? data.allowedOrigins ?? data.metadata?.allowedOrigins ?? []) as string[];
        if (uris.length > 0) setRedirectUris((prev) => (prev.length === 0 ? uris : prev));
        if (origins.length > 0) setAllowedOrigins((prev) => (prev.length === 0 ? origins : prev));
        if (Array.isArray(data.ambiguityReasonCodes)) setReasonCodes(data.ambiguityReasonCodes);
        if (Array.isArray(data.ambiguityReasons)) setReasons(data.ambiguityReasons);
      })
      .catch(() => {});
    return () => { mounted = false; };
  }, [client.client_id]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (redirectUris.length === 0) { setError('At least one redirect URI is required.'); return; }
    for (const uri of redirectUris) {
      const errMsg = validateClientRedirectUri(uri, isDev);
      if (errMsg) { setError(errMsg); return; }
    }
    for (const origin of allowedOrigins) {
      if (!validateUri(origin)) { setError(`Invalid allowed origin format: "${origin}"`); return; }
    }
    if (needsSecretRevokeConfirm && !confirmSecretRevoke) {
      setError('Confirm client secret revocation before switching to Public client type.');
      return;
    }
    if (needsWideningOpenConfirm && !confirmWideningOpen) {
      setError('Confirm widening access policy from Private to Open before saving.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess(false);

    try {
      const payload: Record<string, unknown> = {
        skip_consent: skipConsent,
        skipConsent,
        enable_end_session: enableEndSession,
        enableEndSession,
        is_active: isActive,
        disabled: !isActive,
        redirect_uris: redirectUris,
        redirectUris,
        ...(allowedOrigins.length > 0 ? { allowed_origins: allowedOrigins, allowedOrigins } : {}),
      };
      if (canEditPolicy) {
        payload.clientType = clientType;
        payload.accessPolicy = accessPolicy;
        payload.isDev = isDev;
        payload.is_dev = isDev;
        payload.isPublic = accessPolicy === 'open';
        payload.is_public = accessPolicy === 'open';
      }

      const res = await apiFetch(`/api/admin/clients/${client.client_id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (Array.isArray((body as { reasonCodes?: string[] }).reasonCodes)) {
          setReasonCodes((body as { reasonCodes: string[] }).reasonCodes);
        }
        if (Array.isArray((body as { reasons?: string[] }).reasons)) {
          setReasons((body as { reasons: string[] }).reasons);
        }
        throw new Error((body as { error?: string; message?: string }).error || (body as { message?: string }).message || `Server returned HTTP ${res.status}`);
      }

      const updated = body as OAuthClient & { client_secret?: string };
      if (updated.client_secret) {
        setSavedClient(updated);
        setGeneratedSecret(updated.client_secret);
      } else {
        setSuccess(true);
        onSuccess(updated);
        setTimeout(() => onClose(), 800);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const canSave = !loading && (!needsSecretRevokeConfirm || confirmSecretRevoke) && (!needsWideningOpenConfirm || confirmWideningOpen);

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[640px] w-full max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-center gap-2 flex-wrap">
            <DialogTitle>Edit {client.client_name}</DialogTitle>
            {initialPolicy.isLegacy && <Badge variant="secondary" className="text-[11px]">Legacy Compatible</Badge>}
            {initialPolicy.isMigrated && <Badge variant="success" className="text-[11px]">Migrated</Badge>}
            {initialPolicy.isAmbiguous && <Badge variant="warning" className="text-[11px]">Ambiguous</Badge>}
          </div>
          <DialogDescription>
            Manage client authentication policy, tenant access boundary, endpoints, and active status.
          </DialogDescription>
        </DialogHeader>

        {generatedSecret && savedClient ? (
          <ClientSecretOneTimeCard
            clientId={savedClient.client_id}
            clientSecret={generatedSecret}
            onDone={() => { onSuccess(savedClient); onClose(); }}
          />
        ) : (
          <form onSubmit={submit} className="space-y-4 py-2">
            <ClientAmbiguityBanner
              isAmbiguous={initialPolicy.isAmbiguous}
              reasonCodes={reasonCodes}
              reasons={reasons}
            />

            {error && (
              <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2.5 font-sans text-xs text-destructive">
                {error}
              </div>
            )}
            {success && (
              <div role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 font-sans text-xs text-emerald-500 dark:text-emerald-400">
                Application configuration updated.
              </div>
            )}

            <div className="space-y-1.5">
              <label htmlFor="edit-redirect-uri" className="font-sans text-xs font-medium text-foreground">Redirect URIs</label>
              <ClientTagInput
                id="edit-redirect-uri"
                tags={redirectUris}
                placeholder={isDev ? 'http://localhost:3000/callback' : 'https://app.example.com/auth/callback'}
                validate={(val) => validateClientRedirectUri(val, isDev)}
                onAdd={(v) => {
                  setRedirectUris((u) => [...u, v]);
                  const derived = deriveOrigins([v]);
                  setAllowedOrigins((o) => Array.from(new Set([...o, ...derived])));
                }}
                onRemove={(v) => setRedirectUris((u) => u.filter((r) => r !== v))}
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="edit-cors-origin" className="font-sans text-xs font-medium text-foreground">Allowed CORS Origins</label>
              <ClientTagInput
                id="edit-cors-origin"
                tags={allowedOrigins}
                placeholder="https://app.example.com"
                validate={(val) => validateUri(val) ? null : 'Enter a valid HTTP or HTTPS origin without wildcards or credentials'}
                onAdd={(v) => setAllowedOrigins((o) => [...o, v])}
                onRemove={(v) => setAllowedOrigins((o) => o.filter((r) => r !== v))}
              />
            </div>

            <ClientPolicyControls
              clientType={clientType}
              accessPolicy={accessPolicy}
              isDev={isDev}
              readOnly={!canEditPolicy}
              onClientTypeChange={(val) => { setClientType(val); setConfirmSecretRevoke(false); }}
              onAccessPolicyChange={(val) => { setAccessPolicy(val); setConfirmWideningOpen(false); }}
              onIsDevChange={setIsDev}
            />

            {!canEditPolicy && (
              <p className="text-xs text-muted-foreground">
                Policy dimensions are read only for scoped administrators. Contact a platform super administrator to change policy.
              </p>
            )}

            <ClientTransitionWarnings
              needsSecretRevokeConfirm={needsSecretRevokeConfirm}
              confirmSecretRevoke={confirmSecretRevoke}
              onConfirmSecretRevokeChange={setConfirmSecretRevoke}
              needsPublicToConfidential={needsPublicToConfidential}
              needsWideningOpenConfirm={needsWideningOpenConfirm}
              confirmWideningOpen={confirmWideningOpen}
              onConfirmWideningOpenChange={setConfirmWideningOpen}
            />

            <div className="rounded-lg border border-border bg-secondary/20 p-3.5 space-y-2.5">
              <label className="flex items-center justify-between gap-4 cursor-pointer text-xs">
                <span className="font-medium text-foreground">Application Active</span>
                <Checkbox checked={isActive} onCheckedChange={(c) => setIsActive(c === true)} />
              </label>
              <label className="flex items-center justify-between gap-4 cursor-pointer text-xs">
                <span className="font-medium text-foreground">Skip User Consent</span>
                <Checkbox checked={skipConsent} onCheckedChange={(c) => setSkipConsent(c === true)} />
              </label>
              <label className="flex items-center justify-between gap-4 cursor-pointer text-xs">
                <span className="font-medium text-foreground">Allow RP-Initiated Sign-Out</span>
                <Checkbox checked={enableEndSession} onCheckedChange={(c) => setEnableEndSession(c === true)} />
              </label>
            </div>

            <DialogFooter className="mt-4">
              <Button type="button" variant="outline" onClick={onClose} disabled={loading} className="h-9">Cancel</Button>
              <Button type="submit" disabled={!canSave} className="h-9">
                {loading ? 'Saving...' : 'Save changes'}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
};
