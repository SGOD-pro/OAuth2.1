import React, { useRef, useState } from 'react';

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
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <input type="text" className="admin-input" style={{ flex: 1 }} placeholder={placeholder}
          value={input} onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } }} />
        <button type="button" className="btn-secondary" style={{ padding: '0 1rem' }} onClick={add}>Add</button>
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
    <div className="modal-overlay" ref={overlayRef} onClick={handleBackdrop}>
      <div className="modal glass-surface">
        <div className="modal-header">
          <h2>Edit {client.client_name}</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">×</button>
        </div>

        <form onSubmit={submit} className="modal-form">
          {error && (
            <div className="auth-error">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
              {error}
            </div>
          )}
          {success && (
            <div className="auth-success">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              Saved! Closing...
            </div>
          )}

          <div className="form-field">
            <label>Client ID <small style={{ opacity: 0.5 }}>(read-only)</small></label>
            <input type="text" className="admin-input" value={client.client_id} readOnly style={{ opacity: 0.6, cursor: 'not-allowed' }} />
          </div>

          <div className="form-field">
            <label>Redirect URIs</label>
            <TagInput tags={redirectUris} placeholder="https://yourapp.com/auth/callback" validate={validateUri}
              onAdd={(v) => setRedirectUris((r) => [...r, v])} onRemove={(v) => setRedirectUris((r) => r.filter((x) => x !== v))} />
          </div>

          <div className="form-field">
            <label>Allowed Origins</label>
            <TagInput tags={allowedOrigins} placeholder="https://yourapp.com" validate={validateUri}
              onAdd={(v) => setAllowedOrigins((o) => [...o, v])} onRemove={(v) => setAllowedOrigins((o) => o.filter((x) => x !== v))} />
          </div>

          <div className="form-field">
            <label className="toggle-label">
              <div className="toggle-text"><span>Skip consent screen</span></div>
              <input type="checkbox" className="toggle-input" checked={skipConsent} onChange={(e) => setSkipConsent(e.target.checked)} />
              <span className="toggle-track" />
            </label>
          </div>

          <div className="form-field">
            <label className="toggle-label">
              <div className="toggle-text"><span>Allow remote logout</span></div>
              <input type="checkbox" className="toggle-input" checked={enableEndSession} onChange={(e) => setEnableEndSession(e.target.checked)} />
              <span className="toggle-track" />
            </label>
          </div>

          <div className="form-field">
            <label className="toggle-label">
              <div className="toggle-text"><span>Active</span></div>
              <input type="checkbox" className="toggle-input" checked={isActive} onChange={(e) => setIsActive(e.target.checked)} />
              <span className="toggle-track" />
            </label>
          </div>

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Saving...' : 'Save Changes'}
          </button>
        </form>
      </div>
    </div>
  );
};
