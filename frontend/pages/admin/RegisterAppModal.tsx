import React, { useRef, useState } from 'react';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { Checkbox } from '@/components/ui/checkbox';
import { csrfHeaders } from '@/lib/csrf';

interface RegisterAppModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

interface FormState {
  clientName: string;
  redirectUris: string[];
  allowedOrigins: string[];
  skipConsent: boolean;
  enableEndSession: boolean;
}

interface CreatedClient {
  client_id: string;
  client_secret: string;
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
      setErr('Must start with http:// or https://');
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
        />
        <Button type="button" variant="outline" onClick={add}>
          Add
        </Button>
      </div>
      {err && <p className="mt-1 text-xs text-destructive">{err}</p>}
      {tags.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {tags.map((t) => (
            <span key={t} className="flex items-center gap-2 rounded-full bg-white/10 px-3 py-1 text-xs text-foreground">
              {t}
              <button type="button" className="text-muted-foreground hover:text-foreground" onClick={() => onRemove(t)} aria-label={`Remove ${t}`}>
                ×
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

const validateUri = (val: string) => val.startsWith('http://') || val.startsWith('https://');

export const RegisterAppModal: React.FC<RegisterAppModalProps> = ({ onClose, onSuccess }) => {
  const [form, setForm] = useState<FormState>({
    clientName: '',
    redirectUris: [],
    allowedOrigins: [],
    skipConsent: true,
    enableEndSession: true,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [created, setCreated] = useState<CreatedClient | null>(null);
  const [copied, setCopied] = useState<'id' | 'secret' | null>(null);
  const [secretVisible, setSecretVisible] = useState(true);
  const [secretCopied, setSecretCopied] = useState(false);

  const overlayRef = useRef<HTMLDivElement>(null);

  const handleBackdrop = (e: React.MouseEvent) => {
    if (e.target === overlayRef.current) onClose();
  };

  const copy = async (text: string, which: 'id' | 'secret') => {
    await navigator.clipboard.writeText(text);
    setCopied(which);
    setTimeout(() => setCopied(null), 2000);
  };

  const copySecret = async () => {
    if (!created?.client_secret) return;
    await navigator.clipboard.writeText(created.client_secret);
    setCopied('secret');
    setSecretCopied(true);
    setTimeout(() => {
      setSecretVisible(false);
    }, 3000);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.clientName.trim()) { setError('App name is required.'); return; }
    if (form.redirectUris.length === 0) { setError('At least one redirect URI is required.'); return; }
    if (form.allowedOrigins.length === 0) { setError('At least one allowed origin is required.'); return; }

    setLoading(true);
    setError('');

    try {
      const res = await fetch('/api/admin/clients', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...csrfHeaders(),
        },
        body: JSON.stringify({
          client_name: form.clientName.trim(),
          redirect_uris: form.redirectUris,
          allowed_origins: form.allowedOrigins,
          skip_consent: form.skipConsent,
          enable_end_session: form.enableEndSession,
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error((body as { message?: string }).message || `HTTP ${res.status}`);
      }

      const data = await res.json() as CreatedClient;
      setCreated(data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/40 p-4" ref={overlayRef} onClick={handleBackdrop}>
      <GlassSurface
        width="100%"
        height="auto"
        borderRadius={22}
        backgroundOpacity={0.16}
        blur={12}
        saturation={1.6}
        className="w-full max-w-xl"
      >
        <div className="px-6 py-6 w-full text-left bg-muted/80 backdrop-blur-md rounded-2xl">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">
              {created ? 'Application Registered' : 'Register New Application'}
            </h2>
            <button className="text-muted-foreground hover:text-foreground" onClick={onClose} aria-label="Close">
              ×
            </button>
          </div>

          {created ? (
            <div className="mt-6 space-y-4">
              <div className="rounded-2xl border border-border/60 bg-background/40 p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Client ID</p>
                <div className="mt-2 flex items-center justify-between gap-3">
                  <code className="text-xs text-foreground/80 break-all">{created.client_id}</code>
                  <Button size="sm" variant="outline" onClick={() => void copy(created.client_id, 'id')}>
                    {copied === 'id' ? 'Copied' : 'Copy'}
                  </Button>
                </div>
              </div>

              <div className="rounded-2xl border border-border/60 bg-background/40 p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Client Secret</p>
                <div className="mt-2 flex items-center justify-between gap-3">
                  <code className="text-xs text-foreground/80 break-all">
                    {secretVisible && !secretCopied
                      ? created.client_secret
                      : secretCopied
                      ? "••••••••••••••••••••••••••••••••"
                      : "[ copied & hidden ]"
                    }
                  </code>
                  <Button size="sm" variant="outline" onClick={() => void copySecret()}>
                    {copied === 'secret' ? 'Copied' : 'Copy'}
                  </Button>
                </div>
              </div>

              <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-200">
                <strong>Save your client secret now.</strong>
                <p className="mt-1 text-amber-200/80">
                  It will never be shown again. If lost, you must rotate the secret.
                </p>
              </div>

              <Button
                className="w-full"
                disabled={!secretCopied}
                onClick={() => { onSuccess(); onClose(); }}
              >
                {secretCopied ? 'Done' : 'Copy secret before closing'}
              </Button>
            </div>
          ) : (
            <form onSubmit={submit} className="mt-6 space-y-5">
              {error && (
                <div className="rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                  {error}
                </div>
              )}

              <div className="space-y-2">
                <label htmlFor="reg-app-name" className="text-sm font-medium text-foreground">
                  App name <span className="text-destructive">*</span>
                </label>
                <Input
                  id="reg-app-name"
                  type="text"
                  placeholder="My Application"
                  required
                  value={form.clientName}
                  onChange={(e) => setForm((f) => ({ ...f, clientName: e.target.value }))}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">
                  Redirect URIs <span className="text-destructive">*</span>
                </label>
                <TagInput
                  tags={form.redirectUris}
                  placeholder="https://yourapp.com/auth/callback"
                  validate={validateUri}
                  onAdd={(v) => setForm((f) => ({ ...f, redirectUris: [...f.redirectUris, v] }))}
                  onRemove={(v) => setForm((f) => ({ ...f, redirectUris: f.redirectUris.filter((r) => r !== v) }))}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">
                  Allowed origins <span className="text-destructive">*</span>
                </label>
                <TagInput
                  tags={form.allowedOrigins}
                  placeholder="https://yourapp.com"
                  validate={validateUri}
                  onAdd={(v) => setForm((f) => ({ ...f, allowedOrigins: [...f.allowedOrigins, v] }))}
                  onRemove={(v) => setForm((f) => ({ ...f, allowedOrigins: f.allowedOrigins.filter((o) => o !== v) }))}
                />
              </div>

              <div className="rounded-2xl border border-border/60 bg-background/40 p-4 space-y-4">
                <label className="flex items-start justify-between gap-4 text-sm text-foreground">
                  <span>
                    Skip consent screen for users
                    <span className="mt-1 block text-xs text-muted-foreground">
                      Enable for your own apps. Disable for third-party apps.
                    </span>
                  </span>
                  <Checkbox
                    checked={form.skipConsent}
                    onCheckedChange={(checked) => setForm((f) => ({ ...f, skipConsent: checked === true }))}
                  />
                </label>

                <label className="flex items-start justify-between gap-4 text-sm text-foreground">
                  <span>
                    Allow consuming app to trigger logout
                    <span className="mt-1 block text-xs text-muted-foreground">
                      Enables remote session termination via end_session_endpoint.
                    </span>
                  </span>
                  <Checkbox
                    checked={form.enableEndSession}
                    onCheckedChange={(checked) => setForm((f) => ({ ...f, enableEndSession: checked === true }))}
                  />
                </label>
              </div>

              <Separator />

              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? 'Registering...' : 'Register application'}
              </Button>
            </form>
          )}
        </div>
      </GlassSurface>
    </div>
  );
};
