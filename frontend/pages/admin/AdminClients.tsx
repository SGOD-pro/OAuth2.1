import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { RegisterAppModal } from './RegisterAppModal';
import { EditAppModal } from './EditAppModal';
import { AdminClientsToolbar } from './AdminClientsToolbar';
import { AdminClientsTable } from './AdminClientsTable';
import { resolveDisplayPolicy } from './ClientPolicyBadges';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { csrfHeaders } from '@/lib/csrf';
import { toast } from 'sonner';
import { apiFetch } from '@/lib/api';
import { useAdminStore, type OAuthClient } from '@/lib/adminStore';
import { usePageTitle } from '@/hooks/usePageTitle';
import { RotateCcw, Filter } from 'lucide-react';

export const AdminClients: React.FC = () => {
  usePageTitle('Applications');

  const { data, loading } = useAdminStore((state) => state.clients);
  const fetchClients = useAdminStore((state) => state.fetchClients);
  const deleteClientLocal = useAdminStore((state) => state.deleteClientLocal);
  const addClientLocal = useAdminStore((state) => state.addClientLocal);
  const updateClientLocal = useAdminStore((state) => state.updateClientLocal);

  const clients = useMemo(() => data || [], [data]);
  const [showRegister, setShowRegister] = useState(false);
  const [editClient, setEditClient] = useState<OAuthClient | null>(null);
  const [selectedClient, setSelectedClient] = useState<OAuthClient | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<OAuthClient | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [envFilter, setEnvFilter] = useState<'all' | 'prod' | 'dev'>('all');
  const [accessFilter, setAccessFilter] = useState<'all' | 'open' | 'private'>('all');
  const [typeFilter, setTypeFilter] = useState<'all' | 'confidential' | 'public'>('all');
  const [ambiguousOnly, setAmbiguousOnly] = useState(false);
  const [hasAdminsOnly, setHasAdminsOnly] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchTerm), 250);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  const hasActiveFilters = Boolean(searchTerm.trim() || envFilter !== 'all' || accessFilter !== 'all' || typeFilter !== 'all' || ambiguousOnly || hasAdminsOnly);
  const resetFilters = useCallback(() => {
    setSearchTerm(''); setDebouncedSearch('');
    setEnvFilter('all'); setAccessFilter('all'); setTypeFilter('all');
    setAmbiguousOnly(false); setHasAdminsOnly(false); setCurrentPage(1);
  }, []);

  const filteredClients = useMemo(() => {
    return clients.filter((c) => {
      if (debouncedSearch.trim()) {
        const q = debouncedSearch.trim().toLowerCase();
        if (!c.client_name?.toLowerCase().includes(q) && !c.client_id?.toLowerCase().includes(q)) return false;
      }
      const p = resolveDisplayPolicy(c);
      if (envFilter === 'prod' && p.isDev) return false;
      if (envFilter === 'dev' && !p.isDev) return false;
      if (accessFilter !== 'all' && p.accessPolicy !== accessFilter) return false;
      if (typeFilter !== 'all' && p.clientType !== typeFilter) return false;
      if (ambiguousOnly && !p.isAmbiguous) return false;
      if (hasAdminsOnly && !(c.has_custom_admins || c.hasCustomAdmins || c.adminEmail || c.adminUserId)) return false;
      return true;
    }).sort((a, b) => (new Date(b.createdAt || b.created_at || 0).getTime() || 0) - (new Date(a.createdAt || a.created_at || 0).getTime() || 0));
  }, [clients, debouncedSearch, envFilter, accessFilter, typeFilter, ambiguousOnly, hasAdminsOnly]);

  const totalItems = filteredClients.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  useEffect(() => { setCurrentPage(1); }, [debouncedSearch, envFilter, accessFilter, typeFilter, ambiguousOnly, hasAdminsOnly, pageSize]);
  useEffect(() => { if (currentPage > totalPages) setCurrentPage(totalPages); }, [currentPage, totalPages]);
  useEffect(() => { void fetchClients(); }, [fetchClients]);

  const paginatedClients = useMemo(() => filteredClients.slice((currentPage - 1) * pageSize, currentPage * pageSize), [filteredClients, currentPage, pageSize]);

  const handleDelete = useCallback(async (client: OAuthClient) => {
    setDeletingId(client.client_id);
    try {
      const res = await apiFetch(`/api/admin/clients/${client.client_id}`, { method: 'DELETE', headers: { ...csrfHeaders() } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      deleteClientLocal(client.client_id);
      if (selectedClient?.client_id === client.client_id) setSelectedClient(null);
      toast.success(`${client.client_name} removed from registry.`);
    } catch (err) {
      toast.error(`Failed to delete client: ${String(err)}`);
    } finally {
      setDeletingId(null); setConfirmDelete(null);
    }
  }, [selectedClient, deleteClientLocal]);

  const copyClientId = useCallback(async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(id);
    } catch {
      // Clipboard API may be unavailable outside secure browser contexts.
    }
    setCopiedId(id);
    toast.success('Client ID copied to clipboard');
    setTimeout(() => setCopiedId(null), 2000);
  }, []);

  return (
    <div className="flex flex-col flex-1">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 sm:mb-8">
        <div>
          <h1 className="font-heading text-2xl sm:text-[34px] font-semibold text-foreground tracking-tight leading-tight">Applications</h1>
          <p className="mt-1 font-sans text-sm text-muted-foreground">Manage registered OAuth 2.1 clients, policies, redirect URIs, and credentials.</p>
        </div>
        <Button onClick={() => setShowRegister(true)} className="h-9 px-4 self-start sm:self-auto shrink-0">Create application</Button>
      </div>

      <Dialog open={!!confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(null)}>
        <DialogContent className="sm:max-w-[480px] w-full">
          <DialogHeader>
            <DialogTitle>Revoke application</DialogTitle>
            <DialogDescription>
              Are you sure you want to revoke <span className="font-mono font-medium text-foreground">{confirmDelete?.client_name}</span>? Active tokens will be invalidated immediately.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
            <Button variant="destructive" onClick={() => confirmDelete && void handleDelete(confirmDelete)} disabled={deletingId === confirmDelete?.client_id}>
              {deletingId === confirmDelete?.client_id ? 'Revoking...' : 'Revoke'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {loading && clients.length === 0 ? (
        <div className="p-16 text-center flex flex-col items-center justify-center text-muted-foreground">
          <div className="size-7 animate-spin rounded-full border-2 border-primary border-t-transparent mb-3" />
          <span className="font-sans text-xs text-muted-foreground">Loading applications...</span>
        </div>
      ) : clients.length === 0 ? (
        <Card className="w-full"><CardContent className="p-12 text-center flex flex-col items-center justify-center">
          <h3 className="font-heading text-lg font-medium text-foreground mb-1">No applications registered</h3>
          <p className="font-sans text-sm text-muted-foreground mb-6">Register your first OAuth 2.1 client to issue credentials and authorize users.</p>
          <Button onClick={() => setShowRegister(true)}>Create application</Button>
        </CardContent></Card>
      ) : (
        <div className="w-full space-y-4">
          <AdminClientsToolbar
            clients={clients} filteredCount={filteredClients.length}
            searchTerm={searchTerm} setSearchTerm={setSearchTerm}
            envFilter={envFilter} setEnvFilter={setEnvFilter}
            accessFilter={accessFilter} setAccessFilter={setAccessFilter}
            typeFilter={typeFilter} setTypeFilter={setTypeFilter}
            ambiguousOnly={ambiguousOnly} setAmbiguousOnly={setAmbiguousOnly}
            hasAdminsOnly={hasAdminsOnly} setHasAdminsOnly={setHasAdminsOnly}
            hasActiveFilters={hasActiveFilters} resetFilters={resetFilters}
          />
          {filteredClients.length === 0 ? (
            <Card className="w-full"><CardContent className="p-12 text-center flex flex-col items-center justify-center">
              <div className="size-12 rounded-lg bg-secondary border border-border flex items-center justify-center text-muted-foreground mb-4"><Filter className="size-5" /></div>
              <h3 className="font-heading text-lg font-medium text-foreground mb-1">No matching applications</h3>
              <p className="font-sans text-sm text-muted-foreground mb-4">No registered applications match your current search and filter settings.</p>
              <Button variant="outline" size="sm" onClick={resetFilters} className="gap-1.5"><RotateCcw className="size-3.5" /> Reset filters</Button>
            </CardContent></Card>
          ) : (
            <AdminClientsTable
              clients={paginatedClients} totalItems={totalItems}
              currentPage={currentPage} setCurrentPage={setCurrentPage}
              pageSize={pageSize} setPageSize={setPageSize} totalPages={totalPages}
              selectedClient={selectedClient} setSelectedClient={setSelectedClient}
              copiedId={copiedId} copyClientId={copyClientId}
              onEdit={setEditClient} onDelete={setConfirmDelete}
            />
          )}
        </div>
      )}

      {showRegister && (
        <RegisterAppModal
          onClose={() => setShowRegister(false)}
          onSuccess={(created) => {
            setShowRegister(false);
            if (created?.client_id) {
              addClientLocal({
                ...(created as unknown as OAuthClient),
                client_id: created.client_id,
                client_name: created.client_name || 'Application',
                redirect_uris: created.redirect_uris || [],
                allowed_origins: created.allowed_origins || [],
                disabled: false,
                skip_consent: Boolean(created.skip_consent),
                enable_end_session: created.enable_end_session !== false,
              });
            }
            void fetchClients(true);
          }}
        />
      )}

      {editClient && (
        <EditAppModal
          client={editClient}
          onClose={() => setEditClient(null)}
          onSuccess={(updated) => {
            setEditClient(null);
            if (updated?.client_id) updateClientLocal(updated);
            void fetchClients(true);
          }}
        />
      )}
    </div>
  );
};
