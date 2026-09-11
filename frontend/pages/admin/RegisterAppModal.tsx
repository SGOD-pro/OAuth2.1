import React, { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { csrfHeaders } from '@/lib/csrf';
import { validateUri } from '@/lib/security';
import { apiFetch } from '@/lib/api';

interface FormState {
  clientName: string;
  redirectUris: string[];
  allowedOrigins: string[];
  isDev: boolean;
  skipConsent: boolean;
  enableEndSession: boolean;
}

interface CreatedClient {
  client_id: string;
  client_secret: string;
}

interface RegisterAppModalProps {
  onClose: () => void;
  onSuccess: (client: CreatedClient) => void;
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
    if (!validate(val)) {
      setErr('Enter a valid URL without wildcards or credentials');
      return;
    }
    if (tags.includes(val)) {
      setErr('Already added');
      return;
    }
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
          className="h-9"
        />
        <Button type="button" variant="outline" size="sm" onClick={add} className="h-9 px-3">
          Add
        </Button>
      </div>
      {err && <p className="mt-1 font-sans text-xs text-destructive">{err}</p>}
      {tags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {tags.map((t) => (
            <span key={t} className="flex items-center gap-1.5 rounded-md bg-secondary border border-border px-2.5 py-0.5 font-mono text-xs text-foreground">
              {t}
              <button 
                type="button" 
                className="text-muted-foreground hover:text-foreground ml-1" 
                onClick={() => onRemove(t)} 
                aria-label={`Remove ${t}`}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

export const RegisterAppModal: React.FC<RegisterAppModalProps> = ({ onClose, onSuccess }) => {
  const [form, setForm] = useState<FormState>({
    clientName: '',
    redirectUris: [],
    allowedOrigins: [],
    isDev: false,
    skipConsent: false,
    enableEndSession: true,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [created, setCreated] = useState<CreatedClient | null>(null);
  const [copied, setCopied] = useState<'id' | 'secret' | null>(null);
  const [secretCopied, setSecretCopied] = useState(false);

  const copy = async (text: string, which: 'id' | 'secret') => {
    await navigator.clipboard.writeText(text);
    setCopied(which);
    if (which === 'secret') setSecretCopied(true);
    setTimeout(() => setCopied(null), 2000);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.clientName.trim()) { setError('Application name is required.'); return; }
    if (form.redirectUris.length === 0) { setError('At least one redirect URI is required.'); return; }
    if (form.allowedOrigins.length === 0) { setError('At least one allowed origin is required.'); return; }

    setLoading(true);
    setError('');

    try {
      const res = await apiFetch('/api/admin/clients', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...csrfHeaders(),
        },
        body: JSON.stringify({
          client_name: form.clientName.trim(),
          redirect_uris: form.redirectUris,
          allowed_origins: form.allowedOrigins,
          is_dev: form.isDev,
          skip_consent: form.skipConsent,
          enable_end_session: form.enableEndSession,
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = (body as { error?: string; message?: string }).error || (body as { error?: string; message?: string }).message || `Server returned HTTP ${res.status}`;
        throw new Error(msg);
      }

      const data = await res.json() as CreatedClient;
      setCreated(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent 
        className="sm:max-w-[620px] w-full"
        accent={created ? "motorsport" : "none"}
      >
        <DialogHeader>
          <DialogTitle>
            {created ? 'Application credentials generated' : 'Register application'}
          </DialogTitle>
          <DialogDescription>
            {created
              ? 'Save your client secret securely. It will not be shown again.'
              : 'Register an identity client to issue OAuth 2.1 authorization codes and access tokens.'}
          </DialogDescription>
        </DialogHeader>

        {created ? (
          <div className="space-y-4 py-2">
            <div className="rounded-[12px] border border-border bg-secondary/40 p-4">
              <span className="font-sans text-xs font-medium text-muted-foreground block mb-1.5">
                Client ID
              </span>
              <div className="flex items-center justify-between gap-3">
                <code className="font-mono text-xs text-foreground break-all">{created.client_id}</code>
                <Button size="sm" variant="outline" className="h-8 px-2.5 text-xs shrink-0 rounded-md" onClick={() => void copy(created.client_id, 'id')}>
                  {copied === 'id' ? 'Copied' : 'Copy'}
                </Button>
              </div>
            </div>

            <div className="rounded-[12px] border border-border bg-secondary/40 p-4">
              <span className="font-sans text-xs font-medium text-muted-foreground block mb-1.5">
                Client Secret
              </span>
              <div className="flex items-center justify-between gap-3">
                <code className="font-mono text-xs text-foreground break-all">
                  {secretCopied ? "••••••••••••••••••••••••••••••••" : created.client_secret}
                </code>
                <Button size="sm" variant="outline" className="h-8 px-2.5 text-xs shrink-0 rounded-md" onClick={() => void copy(created.client_secret, 'secret')}>
                  {copied === 'secret' ? 'Copied' : 'Copy secret'}
                </Button>
              </div>
            </div>

            <div className="rounded-[12px] border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs text-amber-500 dark:text-amber-300">
              <strong>Security notice:</strong> Client secrets are hashed at rest and cannot be retrieved once you close this dialog.
            </div>

            <DialogFooter className="mt-4">
              <Button
                className="w-full h-9 rounded-md"
                disabled={!secretCopied}
                onClick={() => { onSuccess(created); onClose(); }}
              >
                {secretCopied ? 'Done' : 'Copy secret to proceed'}
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={submit} className="space-y-4 py-2">
            {error && (
              <div className="rounded-[12px] border border-destructive/30 bg-destructive/10 px-4 py-2.5 font-sans text-xs text-destructive">
                {error}
              </div>
            )}

            <div className="space-y-1.5">
              <label className="font-sans text-xs font-medium text-foreground">
                Application Name <span className="text-destructive">*</span>
              </label>
              <Input
                placeholder="e.g. Customer Portal"
                required
                value={form.clientName}
                onChange={(e) => setForm((f) => ({ ...f, clientName: e.target.value }))}
                className="h-9"
              />
            </div>

            <div className="space-y-1.5">
              <label className="font-sans text-xs font-medium text-foreground">
                Redirect URIs <span className="text-destructive">*</span>
              </label>
              <TagInput
                tags={form.redirectUris}
                placeholder="https://app.example.com/auth/callback"
                validate={validateUri}
                onAdd={(v) => setForm((f) => ({ ...f, redirectUris: [...f.redirectUris, v] }))}
                onRemove={(v) => setForm((f) => ({ ...f, redirectUris: f.redirectUris.filter((r) => r !== v) }))}
              />
            </div>

            <div className="space-y-1.5">
              <label className="font-sans text-xs font-medium text-foreground">
                Allowed CORS Origins <span className="text-destructive">*</span>
              </label>
              <TagInput
                tags={form.allowedOrigins}
                placeholder="https://app.example.com"
                validate={validateUri}
                onAdd={(v) => setForm((f) => ({ ...f, allowedOrigins: [...f.allowedOrigins, v] }))}
                onRemove={(v) => setForm((f) => ({ ...f, allowedOrigins: f.allowedOrigins.filter((o) => o !== v) }))}
              />
            </div>

            <div className="rounded-[12px] border border-border bg-secondary/30 p-4 space-y-3">
              <label className="flex items-start justify-between gap-4 cursor-pointer">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-sans text-xs font-medium text-foreground block">
                      Development Mode
                    </span>
                    <span className="rounded bg-amber-500/20 text-amber-600 dark:text-amber-400 border border-amber-500/30 px-1.5 py-0.2 font-sans text-[10px] font-medium">
                      Dev
                    </span>
                  </div>
                  <span className="font-sans text-xs text-muted-foreground">
                    Allows loopback URLs (http://localhost, http://127.0.0.1) for local testing.
                  </span>
                </div>
                <Checkbox
                  checked={form.isDev}
                  onCheckedChange={(checked) => setForm((f) => ({ ...f, isDev: checked === true }))}
                />
              </label>

              <label className="flex items-start justify-between gap-4 cursor-pointer">
                <div>
                  <span className="font-sans text-xs font-medium text-foreground block">
                    Skip User Consent
                  </span>
                  <span className="font-sans text-xs text-muted-foreground">
                    Automatically grant requested scopes for first-party applications.
                  </span>
                </div>
                <Checkbox
                  checked={form.skipConsent}
                  onCheckedChange={(checked) => setForm((f) => ({ ...f, skipConsent: checked === true }))}
                />
              </label>

              <label className="flex items-start justify-between gap-4 cursor-pointer">
                <div>
                  <span className="font-sans text-xs font-medium text-foreground block">
                    Allow Remote Sign-Out
                  </span>
                  <span className="font-sans text-xs text-muted-foreground">
                    Enables OIDC RP-initiated sign-out requests.
                  </span>
                </div>
                <Checkbox
                  checked={form.enableEndSession}
                  onCheckedChange={(checked) => setForm((f) => ({ ...f, enableEndSession: checked === true }))}
                />
              </label>
            </div>

            <DialogFooter className="mt-4">
              <Button type="button" variant="outline" onClick={onClose} disabled={loading} className="h-9">
                Cancel
              </Button>
              <Button type="submit" disabled={loading} className="h-9">
                {loading ? 'Registering...' : 'Register application'}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
};
