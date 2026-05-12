import React, { useEffect, useState, useCallback } from 'react';
import { AdminLayout } from './AdminLayout';
import { RegisterAppModal } from './RegisterAppModal';
import { EditAppModal } from './EditAppModal';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';

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

  const fetchClients = useCallback(async () => {
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
  }, []);

  useEffect(() => { void fetchClients(); }, [fetchClients]);

  const handleDelete = useCallback(async (client: OAuthClient) => {
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
  }, [selectedClient]);

  const copyClientId = useCallback(async (id: string) => {
    await navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }, []);

  return (
    <AdminLayout>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Admin</p>
          <h1 className="mt-2 text-2xl font-semibold text-foreground">Registered applications</h1>
        </div>
        <Button onClick={() => setShowRegister(true)}>+ Register new app</Button>
      </div>

      {error && (
        <div className="mt-6 flex items-center gap-4 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          <span>{error}</span>
          <Button size="sm" variant="outline" className="ml-auto" onClick={() => void fetchClients()}>
            Retry
          </Button>
        </div>
      )}

      {confirmDelete && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 p-4">
          <GlassSurface
            width="100%"
            height="auto"
            borderRadius={20}
            backgroundOpacity={0.18}
            blur={12}
            saturation={1.6}
            className="w-full max-w-sm"
          >
            <div className="px-6 py-6 text-left">
              <h3 className="text-lg font-semibold text-foreground">Delete {confirmDelete.client_name}?</h3>
              <p className="mt-2 text-sm text-muted-foreground">This cannot be undone.</p>
              <div className="mt-6 flex gap-3">
                <Button
                  className="flex-1"
                  variant="destructive"
                  disabled={deletingId === confirmDelete.client_id}
                  onClick={() => void handleDelete(confirmDelete)}
                >
                  {deletingId === confirmDelete.client_id ? 'Deleting...' : 'Delete'}
                </Button>
                <Button className="flex-1" variant="outline" onClick={() => setConfirmDelete(null)}>
                  Cancel
                </Button>
              </div>
            </div>
          </GlassSurface>
        </div>
      )}

      {loading ? (
        <GlassSurface
          width="100%"
          height="auto"
          borderRadius={20}
          backgroundOpacity={0.1}
          blur={10}
          saturation={1.6}
          className="mt-6 w-full"
        >
          <div className="px-6 py-10 text-center">
            <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-white/30 border-t-white" />
          </div>
        </GlassSurface>
      ) : clients.length === 0 ? (
        <GlassSurface
          width="100%"
          height="auto"
          borderRadius={20}
          backgroundOpacity={0.1}
          blur={10}
          saturation={1.6}
          className="mt-6 w-full"
        >
          <div className="px-6 py-10 text-center">
            <p className="text-sm text-muted-foreground">No applications registered yet.</p>
            <Button className="mt-6" onClick={() => setShowRegister(true)}>
              Register new app
            </Button>
          </div>
        </GlassSurface>
      ) : (
        <GlassSurface
          width="100%"
          height="auto"
          borderRadius={20}
          backgroundOpacity={0.1}
          blur={10}
          saturation={1.6}
          className="mt-6 w-full"
        >
          <div className="overflow-x-auto w-full">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                <tr>
                  <th className="px-6 py-4">App name</th>
                  <th className="px-6 py-4">Client ID</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Actions</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((c) => (
                  <tr
                    key={c.client_id}
                    className={`border-t border-white/5 transition ${
                      selectedClient?.client_id === c.client_id ? 'bg-white/10' : 'hover:bg-white/5'
                    }`}
                    onClick={() => setSelectedClient((s) => (s?.client_id === c.client_id ? null : c))}
                  >
                    <td className="px-6 py-4 font-medium text-foreground">{c.client_name}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <code className="text-xs text-muted-foreground">
                          {c.client_id.slice(0, 8)}...
                        </code>
                        <button
                          type="button"
                          className="rounded-full border border-white/10 px-2 py-1 text-xs text-muted-foreground hover:text-foreground"
                          title={copiedId === c.client_id ? 'Copied!' : 'Copy Client ID'}
                          onClick={(e) => {
                            e.stopPropagation();
                            void copyClientId(c.client_id);
                          }}
                        >
                          {copiedId === c.client_id ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`rounded-full px-2 py-1 text-xs ${
                          c.disabled
                            ? 'bg-rose-500/15 text-rose-200'
                            : 'bg-emerald-500/15 text-emerald-200'
                        }`}
                      >
                        {c.disabled ? 'Inactive' : 'Active'}
                      </span>
                    </td>
                    <td className="px-6 py-4" onClick={(e) => e.stopPropagation()}>
                      <div className="flex gap-2">
                        <Button size="sm" variant="outline" onClick={() => setEditClient(c)}>
                          Edit
                        </Button>
                        <Button size="sm" variant="destructive" onClick={() => setConfirmDelete(c)}>
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {selectedClient && (
            <div className="border-t border-white/5 px-6 py-6">
              <h3 className="text-lg font-semibold text-foreground">
                Integrate {selectedClient.client_name}
              </h3>
              <p className="mt-2 text-sm text-muted-foreground">
                Add to your consuming app's <code>.env</code>:
              </p>
              <pre className="mt-4 rounded-2xl bg-black/30 p-4 text-xs text-foreground/80">{`JWKS_URL=${JWKS_URL}\nAUTH_ISSUER=${AUTH_ISSUER}\nCLIENT_ID=${selectedClient.client_id}`}</pre>
              <Button
                size="sm"
                variant="outline"
                className="mt-3"
                onClick={() => {
                  void navigator.clipboard.writeText(
                    `JWKS_URL=${JWKS_URL}\nAUTH_ISSUER=${AUTH_ISSUER}\nCLIENT_ID=${selectedClient.client_id}`,
                  );
                }}
              >
                Copy .env block
              </Button>
              <p className="mt-6 text-sm text-muted-foreground">Verify tokens (Node.js):</p>
              <pre className="mt-3 rounded-2xl bg-black/30 p-4 text-xs text-foreground/80">{`import { createRemoteJWKSet, jwtVerify } from 'jose'\nconst JWKS = createRemoteJWKSet(new URL(process.env.JWKS_URL))\nconst { payload } = await jwtVerify(token, JWKS, {\n  issuer: process.env.AUTH_ISSUER,\n  audience: process.env.CLIENT_ID\n})`}</pre>
            </div>
          )}
        </GlassSurface>
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
