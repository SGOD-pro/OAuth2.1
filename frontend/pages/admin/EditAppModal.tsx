import React, { useRef, useState } from 'react';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';

interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  allowed_origins?: string[];
  skip_consent: boolean;
  enable_end_session: boolean;
  disabled?: boolean;
}

interface EditAppModalProps {
  client: OAuthClient;
  onClose: () => void;
  onSuccess: () => void;
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
    if (!validate(val)) { setErr('Must start with http:// or https://'); return; }
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
        <Button type="button" variant="outline" onClick={add}>Add</Button>
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

export const EditAppModal: React.FC<EditAppModalProps> = ({ client, onClose, onSuccess }) => {
  const [redirectUris, setRedirectUris] = useState<string[]>(client.redirect_uris ?? []);
  const [allowedOrigins, setAllowedOrigins] = useState<string[]>(client.allowed_origins ?? []);
  const [skipConsent, setSkipConsent] = useState(client.skip_consent);
  const [enableEndSession, setEnableEndSession] = useState(client.enable_end_session);
  const [isActive, setIsActive] = useState(!client.disabled);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const overlayRef = useRef<HTMLDivElement>(null);

  const handleBackdrop = (e: React.MouseEvent) => { if (e.target === overlayRef.current) onClose(); };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess(false);

    try {
      const res = await fetch(`/api/admin/clients/${client.client_id}`, {
        method: 'PATCH',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: redirectUris,
          allowed_origins: allowedOrigins,
          skip_consent: skipConsent,
          enable_end_session: enableEndSession,
          is_active: isActive,
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error((body as { message?: string }).message || `HTTP ${res.status}`);
      }

      setSuccess(true);
      onSuccess();
      setTimeout(() => onClose(), 1500);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" ref={overlayRef} onClick={handleBackdrop}>
      <GlassSurface
        width="100%"
        height="auto"
        borderRadius={22}
        backgroundOpacity={0.16}
        blur={12}
        saturation={1.6}
        className="w-full max-w-xl"
      >
        <div className="px-6 py-6 text-left bg-muted/80 w-full">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">Edit {client.client_name}</h2>
            <button className="text-muted-foreground hover:text-foreground" onClick={onClose} aria-label="Close">×</button>
          </div>

          <form onSubmit={submit} className="mt-6 space-y-5">
            {error && (
              <div className="rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                {error}
              </div>
            )}
            {success && (
              <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
                Saved! Closing...
              </div>
            )}

            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">
                Client ID <span className="text-xs text-muted-foreground">(read-only)</span>
              </label>
              <Input type="text" value={client.client_id} readOnly className="opacity-60" />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Redirect URIs</label>
              <TagInput
                tags={redirectUris}
                placeholder="https://yourapp.com/auth/callback"
                validate={validateUri}
                onAdd={(v) => setRedirectUris((r) => [...r, v])}
                onRemove={(v) => setRedirectUris((r) => r.filter((x) => x !== v))}
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Allowed origins</label>
              <TagInput
                tags={allowedOrigins}
                placeholder="https://yourapp.com"
                validate={validateUri}
                onAdd={(v) => setAllowedOrigins((o) => [...o, v])}
                onRemove={(v) => setAllowedOrigins((o) => o.filter((x) => x !== v))}
              />
            </div>

            <div className="rounded-2xl border border-border/60 bg-background/40 p-4 space-y-4">
              <label className="flex items-center justify-between gap-4 text-sm text-foreground">
                <span>Skip consent screen</span>
                <Checkbox checked={skipConsent} onCheckedChange={(checked) => setSkipConsent(checked === true)} />
              </label>
              <label className="flex items-center justify-between gap-4 text-sm text-foreground">
                <span>Allow remote logout</span>
                <Checkbox checked={enableEndSession} onCheckedChange={(checked) => setEnableEndSession(checked === true)} />
              </label>
              <label className="flex items-center justify-between gap-4 text-sm text-foreground">
                <span>Active</span>
                <Checkbox checked={isActive} onCheckedChange={(checked) => setIsActive(checked === true)} />
              </label>
            </div>

            <Separator />

            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Saving...' : 'Save changes'}
            </Button>
          </form>
        </div>
      </GlassSurface>
    </div>
  );
};
