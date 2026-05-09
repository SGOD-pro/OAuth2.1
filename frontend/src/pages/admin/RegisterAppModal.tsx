import React, { useRef, useState } from 'react';

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
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <input
          type="text"
          className="admin-input"
          style={{ flex: 1 }}
          placeholder={placeholder}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } }}
        />
        <button type="button" className="btn-secondary" style={{ padding: '0 1rem' }} onClick={add}>
          Add
        </button>
      </div>
      {err && <p style={{ color: '#ef4444', fontSize: '0.8rem', marginTop: '0.25rem' }}>{err}</p>}
      {tags.length > 0 && (
        <div className="tag-list">
          {tags.map((t) => (
            <span key={t} className="tag">
              {t}
              <button type="button" className="tag-remove" onClick={() => onRemove(t)} aria-label={`Remove ${t}`}>×</button>
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

  const overlayRef = useRef<HTMLDivElement>(null);

  const handleBackdrop = (e: React.MouseEvent) => {
    if (e.target === overlayRef.current) onClose();
  };

  const copy = async (text: string, which: 'id' | 'secret') => {
    await navigator.clipboard.writeText(text);
    setCopied(which);
    setTimeout(() => setCopied(null), 2000);
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
        headers: { 'Content-Type': 'application/json' },
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
    <div className="modal-overlay" ref={overlayRef} onClick={handleBackdrop}>
      <div className="modal glass-surface">
        <div className="modal-header">
          <h2>{created ? '✓ Application Registered' : 'Register New Application'}</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">×</button>
        </div>

        {created ? (
          <div className="modal-success-panel">
            <div className="credential-row">
              <label>Client ID</label>
              <div className="credential-value">
                <code>{created.client_id}</code>
                <button className="copy-btn" onClick={() => void copy(created.client_id, 'id')}>
                  {copied === 'id' ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="credential-row">
              <label>Client Secret</label>
              <div className="credential-value">
                <code>{created.client_secret}</code>
                <button className="copy-btn" onClick={() => void copy(created.client_secret, 'secret')}>
                  {copied === 'secret' ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="secret-warning">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              <div>
                <strong>Save your client secret now.</strong>
                <p>It will never be shown again. If lost, you must rotate the secret.</p>
              </div>
            </div>

            <button
              className="btn-primary"
              style={{ marginTop: '1.5rem' }}
              onClick={() => { onSuccess(); onClose(); }}
            >
              Done
            </button>
          </div>
        ) : (
          <form onSubmit={submit} className="modal-form">
            {error && (
              <div className="auth-error">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                {error}
              </div>
            )}

            <div className="form-field">
              <label htmlFor="reg-app-name">App Name <span style={{ color: '#ef4444' }}>*</span></label>
              <input
                id="reg-app-name"
                type="text"
                className="admin-input"
                placeholder="My Application"
                required
                value={form.clientName}
                onChange={(e) => setForm((f) => ({ ...f, clientName: e.target.value }))}
              />
            </div>

            <div className="form-field">
              <label>Redirect URIs <span style={{ color: '#ef4444' }}>*</span></label>
              <TagInput
                tags={form.redirectUris}
                placeholder="https://yourapp.com/auth/callback"
                validate={validateUri}
                onAdd={(v) => setForm((f) => ({ ...f, redirectUris: [...f.redirectUris, v] }))}
                onRemove={(v) => setForm((f) => ({ ...f, redirectUris: f.redirectUris.filter((r) => r !== v) }))}
              />
            </div>

            <div className="form-field">
              <label>Allowed Origins <span style={{ color: '#ef4444' }}>*</span></label>
              <TagInput
                tags={form.allowedOrigins}
                placeholder="https://yourapp.com"
                validate={validateUri}
                onAdd={(v) => setForm((f) => ({ ...f, allowedOrigins: [...f.allowedOrigins, v] }))}
                onRemove={(v) => setForm((f) => ({ ...f, allowedOrigins: f.allowedOrigins.filter((o) => o !== v) }))}
              />
            </div>

            <div className="form-field">
              <label className="toggle-label">
                <div className="toggle-text">
                  <span>Skip consent screen for users</span>
                  <small>Enable for your own apps. Disable for third-party apps.</small>
                </div>
                <input
                  type="checkbox"
                  className="toggle-input"
                  checked={form.skipConsent}
                  onChange={(e) => setForm((f) => ({ ...f, skipConsent: e.target.checked }))}
                />
                <span className="toggle-track" />
              </label>
            </div>

            <div className="form-field">
              <label className="toggle-label">
                <div className="toggle-text">
                  <span>Allow consuming app to trigger logout</span>
                  <small>Enables remote session termination via end_session_endpoint.</small>
                </div>
                <input
                  type="checkbox"
                  className="toggle-input"
                  checked={form.enableEndSession}
                  onChange={(e) => setForm((f) => ({ ...f, enableEndSession: e.target.checked }))}
                />
                <span className="toggle-track" />
              </label>
            </div>

            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? (
                <><span className="loading-spinner" style={{ width: 16, height: 16, borderWidth: 2, display: 'inline-block', marginRight: 8 }} />Registering...</>
              ) : 'Register Application'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};
