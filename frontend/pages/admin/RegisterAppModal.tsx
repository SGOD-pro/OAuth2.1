import React, { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { csrfHeaders } from '@/lib/csrf';
import { validateClientRedirectUri, validateUri, deriveOrigins } from '@/lib/security';
import { apiFetch } from '@/lib/api';
import { ClientTagInput } from './ClientTagInput';
import { ClientPolicyControls, ClientSecretOneTimeCard } from './ClientPolicyControls';

interface FormState {
  clientName: string;
  redirectUris: string[];
  allowedOrigins: string[];
  clientType: 'public' | 'confidential';
  accessPolicy: 'open' | 'private';
  isDev: boolean;
  skipConsent: boolean;
  enableEndSession: boolean;
}

export interface CreatedClient {
  client_id: string;
  client_secret?: string;
  client_name?: string;
  redirect_uris?: string[];
  allowed_origins?: string[];
  clientType?: 'public' | 'confidential';
  accessPolicy?: 'open' | 'private';
  classification?: string;
  isAmbiguous?: boolean;
  hasClientSecret?: boolean;
  is_dev?: boolean;
  is_public?: boolean;
  isPublic?: boolean;
  skip_consent?: boolean;
  enable_end_session?: boolean;
  createdAt?: string;
  created_at?: string;
  updatedAt?: string;
  updated_at?: string;
  [key: string]: unknown;
}

interface RegisterAppModalProps {
  onClose: () => void;
  onSuccess: (client: CreatedClient) => void;
}

export const RegisterAppModal: React.FC<RegisterAppModalProps> = ({ onClose, onSuccess }) => {
  const [form, setForm] = useState<FormState>({
    clientName: '',
    redirectUris: [],
    allowedOrigins: [],
    clientType: 'confidential',
    accessPolicy: 'private',
    isDev: false,
    skipConsent: false,
    enableEndSession: true,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [created, setCreated] = useState<CreatedClient | null>(null);

  const canSubmit = Boolean(form.clientName.trim() && form.redirectUris.length > 0 && !loading);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.clientName.trim()) { setError('Application name is required.'); return; }
    if (form.redirectUris.length === 0) { setError('At least one redirect URI is required.'); return; }

    for (const uri of form.redirectUris) {
      const uriErr = validateClientRedirectUri(uri, form.isDev);
      if (uriErr) { setError(uriErr); return; }
    }

    const effectiveOrigins = form.allowedOrigins.length > 0
      ? form.allowedOrigins
      : deriveOrigins(form.redirectUris);

    if (effectiveOrigins.length === 0) {
      setError('At least one allowed origin is required.');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const res = await apiFetch('/api/admin/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
        body: JSON.stringify({
          client_name: form.clientName.trim(),
          redirect_uris: form.redirectUris,
          allowed_origins: effectiveOrigins,
          clientType: form.clientType,
          accessPolicy: form.accessPolicy,
          isDev: form.isDev,
          is_dev: form.isDev,
          isPublic: form.accessPolicy === 'open',
          is_public: form.accessPolicy === 'open',
          skip_consent: form.skipConsent,
          enable_end_session: form.enableEndSession,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = (body as { error?: string; message?: string }).error || (body as { message?: string }).message || `Server returned HTTP ${res.status}`;
        throw new Error(msg);
      }
      setCreated((await res.json()) as CreatedClient);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[640px] w-full max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {created
              ? (created.client_secret ? 'Application credentials generated' : 'Application registered')
              : 'Register application'}
          </DialogTitle>
          <DialogDescription>
            {created
              ? (created.client_secret
                  ? 'Save your client secret securely. It will not be shown again.'
                  : 'Public client registered without a client secret.')
              : 'Register an identity client with independent authentication, access, and callback controls.'}
          </DialogDescription>
        </DialogHeader>

        {created ? (
          <ClientSecretOneTimeCard
            clientId={created.client_id}
            clientSecret={created.client_secret}
            onDone={() => { onSuccess(created); onClose(); }}
          />
        ) : (
          <form onSubmit={submit} className="space-y-4 py-2">
            {error && (
              <div role="alert" className="rounded-[12px] border border-destructive/30 bg-destructive/10 px-4 py-2.5 font-sans text-xs text-destructive">
                {error}
              </div>
            )}

            <div className="space-y-1.5">
              <label htmlFor="register-app-name" className="font-sans text-xs font-medium text-foreground">
                Application Name <span aria-hidden="true" className="text-destructive">*</span>
              </label>
              <Input
                id="register-app-name"
                placeholder="e.g. Customer Portal"
                required
                value={form.clientName}
                onChange={(e) => setForm((f) => ({ ...f, clientName: e.target.value }))}
                className="h-9"
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="register-redirect-uri" className="font-sans text-xs font-medium text-foreground">
                Redirect URIs <span aria-hidden="true" className="text-destructive">*</span>
              </label>
              <ClientTagInput
                id="register-redirect-uri"
                tags={form.redirectUris}
                placeholder={form.isDev ? 'http://localhost:3000/callback' : 'https://app.example.com/auth/callback'}
                validate={(val) => validateClientRedirectUri(val, form.isDev)}
                onAdd={(v) => {
                  setForm((f) => {
                    const nextUris = [...f.redirectUris, v];
                    const derived = deriveOrigins([v]);
                    return { ...f, redirectUris: nextUris, allowedOrigins: Array.from(new Set([...f.allowedOrigins, ...derived])) };
                  });
                }}
                onRemove={(v) => setForm((f) => ({ ...f, redirectUris: f.redirectUris.filter((r) => r !== v) }))}
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label htmlFor="register-cors-origin" className="font-sans text-xs font-medium text-foreground">
                  Allowed CORS Origins <span aria-hidden="true" className="text-destructive">*</span>
                </label>
                {form.redirectUris.length > 0 && (
                  <button
                    type="button"
                    className="font-sans text-[11px] text-primary hover:underline"
                    onClick={() => {
                      const derived = deriveOrigins(form.redirectUris);
                      setForm((f) => ({ ...f, allowedOrigins: Array.from(new Set([...f.allowedOrigins, ...derived])) }));
                    }}
                  >
                    Auto derive from redirect URIs
                  </button>
                )}
              </div>
              <ClientTagInput
                id="register-cors-origin"
                tags={form.allowedOrigins}
                placeholder={form.isDev ? 'http://localhost:3000' : 'https://app.example.com'}
                validate={(val) => validateUri(val) ? null : 'Enter a valid HTTP or HTTPS origin without wildcards or credentials'}
                onAdd={(v) => setForm((f) => ({ ...f, allowedOrigins: [...f.allowedOrigins, v] }))}
                onRemove={(v) => setForm((f) => ({ ...f, allowedOrigins: f.allowedOrigins.filter((o) => o !== v) }))}
              />
            </div>

            <ClientPolicyControls
              clientType={form.clientType}
              accessPolicy={form.accessPolicy}
              isDev={form.isDev}
              onClientTypeChange={(clientType) => setForm((f) => ({ ...f, clientType }))}
              onAccessPolicyChange={(accessPolicy) => setForm((f) => ({ ...f, accessPolicy }))}
              onIsDevChange={(isDev) => setForm((f) => ({ ...f, isDev }))}
            />

            {form.clientType === 'confidential' ? (
              <div className="rounded-lg border border-border bg-secondary/40 px-3.5 py-2.5 text-xs text-muted-foreground">
                A cryptographically secure client secret will be generated and shown once upon submission.
              </div>
            ) : (
              <div className="rounded-lg border border-border bg-secondary/40 px-3.5 py-2.5 text-xs text-muted-foreground">
                Public clients use PKCE S256 on authorization code exchange and do not possess a client secret.
              </div>
            )}

            <div className="rounded-[12px] border border-border bg-secondary/20 p-3.5 space-y-2.5">
              <label className="flex items-center justify-between gap-4 cursor-pointer text-xs">
                <span className="font-medium text-foreground">Skip User Consent (first-party apps)</span>
                <Checkbox checked={form.skipConsent} onCheckedChange={(c) => setForm((f) => ({ ...f, skipConsent: c === true }))} />
              </label>
              <label className="flex items-center justify-between gap-4 cursor-pointer text-xs">
                <span className="font-medium text-foreground">Allow RP-Initiated Sign-Out</span>
                <Checkbox checked={form.enableEndSession} onCheckedChange={(c) => setForm((f) => ({ ...f, enableEndSession: c === true }))} />
              </label>
            </div>

            <DialogFooter className="mt-4">
              <Button type="button" variant="outline" onClick={onClose} disabled={loading} className="h-9">Cancel</Button>
              <Button type="submit" disabled={!canSubmit} className="h-9">
                {loading ? 'Registering...' : 'Register application'}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
};
