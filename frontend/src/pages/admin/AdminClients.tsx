import React, { useEffect, useState } from 'react';
import { AdminLayout } from './AdminLayout';
import { RegisterAppModal } from './RegisterAppModal';
import { EditAppModal } from './EditAppModal';

interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  allowed_origins?: string[];
  skip_consent: boolean;
  enable_end_session: boolean;
  disabled?: boolean;
}

const JWKS_URL = import.meta.env.VITE_AUTH_URL
  ? `${import.meta.env.VITE_AUTH_URL}/.well-known/jwks.json`
  : 'https://auth.yourdomain.com/.well-known/jwks.json';

const AUTH_ISSUER = import.meta.env.VITE_AUTH_URL ?? 'https://auth.yourdomain.com';

/**
 * /admin/clients — Registered Applications
 */
export const AdminClients: React.FC = () => {
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showRegister, setShowRegister] = useState(false);
  const [editClient, setEditClient] = useState<OAuthClient | null>(null);
  const [selectedClient, setSelectedClient] = useState<OAuthClient | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<OAuthClient | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchClients = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch('/api/admin/clients', { credentials: 'include' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json() as OAuthClient[];
      setClients(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void fetchClients(); }, []);

  const handleDelete = async (client: OAuthClient) => {
    setDeletingId(client.client_id);
    try {
      const res = await fetch(`/api/admin/clients/${client.client_id}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setClients((c) => c.filter((x) => x.client_id !== client.client_id));
      if (selectedClient?.client_id === client.client_id) setSelectedClient(null);
    } catch {
      // keep list unchanged on error
    } finally {
      setDeletingId(null);
      setConfirmDelete(null);
    }
  };

  const copyClientId = async (id: string) => {
    await navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <AdminLayout>
      <div className="admin-page-header">
        <h1 className="admin-page-title">Registered Applications</h1>
        <button className="btn-primary" style={{ padding: '0.6rem 1.25rem' }} onClick={() => setShowRegister(true)}>
          + Register New App
        </button>
      </div>

      {error && (
        <div className="auth-error" style={{ marginBottom: '1rem' }}>
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          {error}
          <button className="btn-secondary" style={{ marginLeft: 'auto', padding: '0.25rem 0.75rem', fontSize: '0.85rem' }} onClick={() => void fetchClients()}>Retry</button>
        </div>
      )}

      {/* Confirm delete dialog */}
      {confirmDelete && (
        <div className="modal-overlay">
          <div className="modal glass-surface" style={{ maxWidth: 400 }}>
            <h3 style={{ marginBottom: '0.75rem' }}>Delete {confirmDelete.client_name}?</h3>
            <p style={{ opacity: 0.7, marginBottom: '1.5rem' }}>This cannot be undone.</p>
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button className="btn-primary" style={{ background: '#ef4444', flex: 1 }}
                disabled={deletingId === confirmDelete.client_id}
                onClick={() => void handleDelete(confirmDelete)}>
                {deletingId === confirmDelete.client_id ? 'Deleting...' : 'Delete'}
              </button>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setConfirmDelete(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <div className="glass-surface" style={{ padding: '2rem', textAlign: 'center' }}>
          <div className="loading-spinner" style={{ margin: '0 auto' }} />
        </div>
      ) : clients.length === 0 ? (
        <div className="glass-surface empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.4, margin: '0 auto 1rem' }}>
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
          </svg>
          <p style={{ opacity: 0.6, marginBottom: '1rem' }}>No applications registered yet.</p>
          <button className="btn-primary" onClick={() => setShowRegister(true)}>Register New App</button>
        </div>
      ) : (
        <div className="glass-surface" style={{ overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="admin-table">
              <thead>
                <tr>
                  <th>App Name</th>
                  <th>Client ID</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((c) => (
                  <tr
                    key={c.client_id}
                    className={selectedClient?.client_id === c.client_id ? 'row-selected' : ''}
                    onClick={() => setSelectedClient((s) => s?.client_id === c.client_id ? null : c)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td style={{ fontWeight: 500 }}>{c.client_name}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <code style={{ fontSize: '0.8rem', opacity: 0.8 }}>
                          {c.client_id.slice(0, 8)}...
                        </code>
                        <button
                          className="copy-btn"
                          title={copiedId === c.client_id ? 'Copied!' : 'Copy Client ID'}
                          onClick={(e) => { e.stopPropagation(); void copyClientId(c.client_id); }}
                        >
                          {copiedId === c.client_id ? '✓' : (
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                            </svg>
                          )}
                        </button>
                      </div>
                    </td>
                    <td>
                      {c.disabled ? (
                        <span className="badge badge-red">Inactive</span>
                      ) : (
                        <span className="badge badge-green">Active</span>
                      )}
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <button className="btn-secondary" style={{ padding: '0.3rem 0.75rem', fontSize: '0.85rem' }}
                          onClick={() => setEditClient(c)}>Edit</button>
                        <button className="btn-secondary" style={{ padding: '0.3rem 0.75rem', fontSize: '0.85rem', borderColor: 'rgba(239,68,68,0.3)', color: '#ef4444' }}
                          onClick={() => setConfirmDelete(c)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Integration guide — shown when a client row is selected */}
          {selectedClient && (
            <div className="integration-guide glass-surface">
              <h3 style={{ marginBottom: '1rem' }}>Integrate {selectedClient.client_name}</h3>
              <p style={{ opacity: 0.7, marginBottom: '1rem', fontSize: '0.9rem' }}>
                Add to your consuming app's <code>.env</code>:
              </p>
              <pre className="code-block">{`JWKS_URL=${JWKS_URL}\nAUTH_ISSUER=${AUTH_ISSUER}\nCLIENT_ID=${selectedClient.client_id}`}</pre>
              <button
                className="copy-btn"
                style={{ marginTop: '0.75rem' }}
                onClick={() => {
                  void navigator.clipboard.writeText(
                    `JWKS_URL=${JWKS_URL}\nAUTH_ISSUER=${AUTH_ISSUER}\nCLIENT_ID=${selectedClient.client_id}`,
                  );
                }}
              >
                Copy .env block
              </button>
              <p style={{ opacity: 0.6, marginTop: '1.5rem', marginBottom: '0.5rem', fontSize: '0.9rem' }}>Verify tokens (Node.js):</p>
              <pre className="code-block">{`import { createRemoteJWKSet, jwtVerify } from 'jose'\nconst JWKS = createRemoteJWKSet(new URL(process.env.JWKS_URL))\nconst { payload } = await jwtVerify(token, JWKS, {\n  issuer: process.env.AUTH_ISSUER,\n  audience: process.env.CLIENT_ID\n})`}</pre>
            </div>
          )}
        </div>
      )}

      {showRegister && (
        <RegisterAppModal
          onClose={() => setShowRegister(false)}
          onSuccess={() => void fetchClients()}
        />
      )}
      {editClient && (
        <EditAppModal
          client={editClient}
          onClose={() => setEditClient(null)}
          onSuccess={() => void fetchClients()}
        />
      )}
    </AdminLayout>
  );
};
