import React, { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { csrfHeaders } from '@/lib/csrf';
import { validateUri } from '@/lib/security';
import { apiFetch } from '@/lib/api';

interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris?: string[];
  redirectUris?: string[];
  allowed_origins?: string[];
  allowedOrigins?: string[];
  is_dev?: boolean;
  isDev?: boolean;
  metadata?: {
    allowedOrigins?: string[];
    allowed_origins?: string[];
    isDev?: boolean;
    is_dev?: boolean;
  };
  skip_consent?: boolean;
  skipConsent?: boolean;
  enable_end_session?: boolean;
  enableEndSession?: boolean;
  disabled?: boolean;
  is_active?: boolean;
}

interface EditAppModalProps {
  client: OAuthClient;
  onClose: () => void;
  onSuccess: (client: OAuthClient) => void;
}

const TagInput: React.FC<{
  tags: string[];
  placeholder: string;
  validate: (val: string) => boolean;
  onAdd: (val: string) => void;
  onRemove: (val: string) => void;
}> = ({ tags, placeholder, validate, onAdd, onRemove }) => {
  const [input, setInput] = useState('');
  const [err, setErr] = useState('');

  const add = () => {
    const val = input.trim();
    if (!val) return;
    if (!validate(val)) { setErr('Enter a valid URL without wildcards or credentials'); return; }
    if (tags.includes(val)) { setErr('Already added'); return; }
    onAdd(val);
    setInput('');
    setErr('');
  };

  return (
    <div>
      <div className="flex gap-2">
        <Input
          type="text"
          placeholder={placeholder}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } }}
        />
        <Button type="button" variant="outline" size="sm" onClick={add}>Add</Button>
      </div>
      {err && <p className="mt-1 font-mono text-xs text-destructive">{err}</p>}
      {tags.length > 0 && (
        <div className="mt-2.5 flex flex-wrap gap-1.5">
          {tags.map((t) => (
            <span key={t} className="flex items-center gap-1.5 rounded-pill bg-secondary/80 border border-border px-2.5 py-0.5 font-mono text-xs text-foreground">
              {t}
              <button type="button" className="text-muted-foreground hover:text-foreground ml-1" onClick={() => onRemove(t)} aria-label={`Remove ${t}`}>
                ×
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

export const EditAppModal: React.FC<EditAppModalProps> = ({ client, onClose, onSuccess }) => {
  const initialRedirectUris = client.redirect_uris ?? client.redirectUris ?? [];
  const initialAllowedOrigins =
    client.allowed_origins ??
    client.allowedOrigins ??
    client.metadata?.allowedOrigins ??
    client.metadata?.allowed_origins ??
    [];

  const [redirectUris, setRedirectUris] = useState<string[]>(initialRedirectUris);
  const [allowedOrigins, setAllowedOrigins] = useState<string[]>(initialAllowedOrigins);
  const [isDev, setIsDev] = useState<boolean>(
    client.is_dev ?? client.isDev ?? client.metadata?.isDev ?? client.metadata?.is_dev ?? false
  );
  const [skipConsent, setSkipConsent] = useState<boolean>(
    client.skip_consent ?? client.skipConsent ?? false
  );
  const [enableEndSession, setEnableEndSession] = useState<boolean>(
    client.enable_end_session ?? client.enableEndSession ?? false
  );
  const [isActive, setIsActive] = useState<boolean>(
    client.is_active ?? !client.disabled
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (redirectUris.length === 0) {
      setError('At least one redirect URI is required.');
      return;
    }
    if (allowedOrigins.length === 0) {
      setError('At least one allowed CORS origin is required.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess(false);

    try {
      const res = await apiFetch(`/api/admin/clients/${client.client_id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          ...csrfHeaders(),
        },
        body: JSON.stringify({
          redirect_uris: redirectUris,
          redirectUris: redirectUris,
          allowed_origins: allowedOrigins,
          allowedOrigins: allowedOrigins,
          is_dev: isDev,
          isDev: isDev,
          skip_consent: skipConsent,
          skipConsent: skipConsent,
          enable_end_session: enableEndSession,
          enableEndSession: enableEndSession,
          is_active: isActive,
          disabled: !isActive,
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = (body as { error?: string; message?: string }).error || (body as { error?: string; message?: string }).message || `Server returned HTTP ${res.status}`;
        throw new Error(msg);
      }

      const updatedClient = await res.json();
      setSuccess(true);
      onSuccess(updatedClient);
      setTimeout(() => onClose(), 1200);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[620px] w-full">
        <DialogHeader>
          <DialogTitle>Edit {client.client_name}</DialogTitle>
          <DialogDescription>
            Modify OAuth 2.1 client endpoints, active status, and CORS parameters.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={submit} className="space-y-4 py-2">
          {error && (
            <div className="rounded-[16px] border border-destructive/30 bg-destructive/10 px-4 py-2.5 font-mono text-xs text-destructive">
              {error}
            </div>
          )}
          {success && (
            <div className="rounded-[16px] border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 font-mono text-xs text-emerald-400">
              Telemetry configuration updated.
            </div>
          )}

          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <label className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                Redirect URIs
              </label>
              <span className="font-sans text-[11px] text-muted-foreground">
                OAuth callback endpoints
              </span>
            </div>
            <TagInput
              tags={redirectUris}
              placeholder="https://app.domain.com/auth/callback"
              validate={validateUri}
              onAdd={(v) => setRedirectUris((u) => [...u, v])}
              onRemove={(v) => setRedirectUris((u) => u.filter((r) => r !== v))}
            />
          </div>

          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <label className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                Allowed CORS Origins
              </label>
              <span className="font-sans text-[11px] text-muted-foreground">
                Web app origin(s) permitted for browser requests
              </span>
            </div>
            <TagInput
              tags={allowedOrigins}
              placeholder="https://app.domain.com"
              validate={validateUri}
              onAdd={(v) => setAllowedOrigins((o) => [...o, v])}
              onRemove={(v) => setAllowedOrigins((o) => o.filter((r) => r !== v))}
            />
            {allowedOrigins.length === 0 && (
              <p className="font-sans text-[11px] text-amber-400/90 mt-1">
                Notice: At least one allowed origin is required for SPAs and browser-based clients to make cross-origin token requests.
              </p>
            )}
          </div>

          <div className="rounded-[16px] border border-border/60 bg-secondary/30 p-4 space-y-3">
            <label className="flex items-start justify-between gap-4 cursor-pointer">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-sans text-xs font-medium text-foreground block">
                    Development Mode
                  </span>
                  <span className="rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[9px]">
                    DEV / LOCALHOST
                  </span>
                </div>
                <span className="font-sans text-[11px] text-muted-foreground">
                  Allows loopback URLs (http://localhost, http://127.0.0.1) for local testing.
                </span>
              </div>
              <Checkbox
                checked={isDev}
                onCheckedChange={(checked) => setIsDev(checked === true)}
              />
            </label>

            <label className="flex items-start justify-between gap-4 cursor-pointer">
              <div>
                <span className="font-sans text-xs font-medium text-foreground block">
                  Application Active
                </span>
                <span className="font-sans text-[11px] text-muted-foreground">
                  Disable to reject token requests immediately.
                </span>
              </div>
              <Checkbox
                checked={isActive}
                onCheckedChange={(checked) => setIsActive(checked === true)}
              />
            </label>

            <label className="flex items-start justify-between gap-4 cursor-pointer">
              <div>
                <span className="font-sans text-xs font-medium text-foreground block">
                  Bypass Consent Screen
                </span>
                <span className="font-sans text-[11px] text-muted-foreground">
                  Skip scope approval for first-party clients.
                </span>
              </div>
              <Checkbox
                checked={skipConsent}
                onCheckedChange={(checked) => setSkipConsent(checked === true)}
              />
            </label>

            <label className="flex items-start justify-between gap-4 cursor-pointer">
              <div>
                <span className="font-sans text-xs font-medium text-foreground block">
                  Allow Remote End-Session
                </span>
                <span className="font-sans text-[11px] text-muted-foreground">
                  Allow RP-initiated logout triggers.
                </span>
              </div>
              <Checkbox
                checked={enableEndSession}
                onCheckedChange={(checked) => setEnableEndSession(checked === true)}
              />
            </label>
          </div>

          <DialogFooter className="mt-4">
            <Button type="button" variant="outline" onClick={onClose} disabled={loading}>
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Saving...' : 'Save Changes'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};
