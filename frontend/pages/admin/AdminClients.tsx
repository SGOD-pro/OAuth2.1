import React, { useEffect, useState, useCallback } from 'react';
import { AdminLayout } from './AdminLayout';
import { RegisterAppModal } from './RegisterAppModal';
import { EditAppModal } from './EditAppModal';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { csrfHeaders } from '@/lib/csrf';
import { toast } from 'sonner';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

import { useAdminStore, type OAuthClient } from '@/lib/adminStore';

const JWKS_URL = import.meta.env.VITE_AUTH_URL
  ? `${import.meta.env.VITE_AUTH_URL}/.well-known/jwks.json`
  : 'https://auth.yourdomain.com/.well-known/jwks.json';

const AUTH_ISSUER = import.meta.env.VITE_AUTH_URL ?? 'https://auth.yourdomain.com';

export const AdminClients: React.FC = () => {
  const { data, loading } = useAdminStore((state) => state.clients);
  const fetchClients = useAdminStore((state) => state.fetchClients);
  const deleteClientLocal = useAdminStore((state) => state.deleteClientLocal);
  const addClientLocal = useAdminStore((state) => state.addClientLocal);
  const updateClientLocal = useAdminStore((state) => state.updateClientLocal);
  
  const clients = data || [];

  const [showRegister, setShowRegister] = useState(false);
  const [editClient, setEditClient] = useState<OAuthClient | null>(null);
  const [selectedClient, setSelectedClient] = useState<OAuthClient | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<OAuthClient | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => { void fetchClients(); }, [fetchClients]);

  const handleDelete = useCallback(async (client: OAuthClient) => {
    setDeletingId(client.client_id);
    try {
      const res = await fetch(`/api/admin/clients/${client.client_id}`, {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          ...csrfHeaders(),
        },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      deleteClientLocal(client.client_id);
      if (selectedClient?.client_id === client.client_id) setSelectedClient(null);
      toast.success(`${client.client_name} has been deleted.`);
    } catch (err) {
      toast.error(`Failed to delete client: ${String(err)}`);
    } finally {
      setDeletingId(null);
      setConfirmDelete(null);
    }
  }, [selectedClient]);

  const copyClientId = useCallback(async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(id);
    setCopiedId(id);
    toast.success('Client ID copied to clipboard');
    setTimeout(() => setCopiedId(null), 2000);
  }, []);

  return (
    <AdminLayout>
      <div className="flex flex-wrap items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-foreground font-heading">Applications</h1>
          <p className="mt-2 text-sm text-muted-foreground">Manage OAuth 2.1 clients and integrations.</p>
        </div>
        <Button onClick={() => setShowRegister(true)} className="rounded-full shadow-sm">
          <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
          Register New App
        </Button>
      </div>

      <Dialog open={!!confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(null)}>
        <DialogContent className="sm:max-w-md border-border bg-card/80 backdrop-blur-xl">
          <DialogHeader>
            <DialogTitle>Delete Application</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete <span className="font-semibold text-foreground">{confirmDelete?.client_name}</span>? This action cannot be undone and will break existing integrations.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
            <Button 
              variant="destructive" 
              onClick={() => confirmDelete && void handleDelete(confirmDelete)}
              disabled={deletingId === confirmDelete?.client_id}
            >
              {deletingId === confirmDelete?.client_id ? 'Deleting...' : 'Confirm Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card className="bg-card/50 backdrop-blur-md border-border/50 shadow-sm overflow-hidden">
        {loading && clients.length === 0 ? (
          <div className="px-6 py-16 text-center flex flex-col items-center justify-center text-muted-foreground">
            <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-primary/30 border-t-primary mb-4" />
            Loading applications...
          </div>
        ) : clients.length === 0 ? (
          <div className="px-6 py-16 text-center flex flex-col items-center justify-center">
            <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center text-primary mb-4">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /></svg>
            </div>
            <h3 className="text-lg font-medium text-foreground mb-1">No applications yet</h3>
            <p className="text-sm text-muted-foreground mb-6">Register your first application to get started.</p>
            <Button onClick={() => setShowRegister(true)} className="rounded-full">Register Application</Button>
          </div>
        ) : (
          <div className="w-full">
            <Table>
              <TableHeader className="bg-muted/50">
                <TableRow className="border-border/50 hover:bg-transparent">
                  <TableHead className="w-[30%]">App Name</TableHead>
                  <TableHead className="w-[30%]">Client ID</TableHead>
                  <TableHead className="w-[20%]">Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {clients.map((c) => (
                  <TableRow 
                    key={c.client_id}
                    className={`cursor-pointer transition-colors border-border/50 ${selectedClient?.client_id === c.client_id ? 'bg-primary/5 hover:bg-primary/10' : 'hover:bg-muted/50'}`}
                    onClick={() => setSelectedClient((s) => (s?.client_id === c.client_id ? null : c))}
                  >
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-3">
                        <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center text-primary font-bold text-xs uppercase">
                          {c.client_name.substring(0, 2)}
                        </div>
                        {c.client_name}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <code className="text-xs bg-muted px-2 py-1 rounded-md text-muted-foreground">
                          {c.client_id.slice(0, 8)}...{c.client_id.slice(-4)}
                        </code>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-6 w-6 rounded-md hover:bg-background" onClick={(e) => copyClientId(c.client_id, e)}>
                              {copiedId === c.client_id ? (
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-emerald-500"><polyline points="20 6 9 17 4 12" /></svg>
                              ) : (
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                              )}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent side="top">Copy full ID</TooltipContent>
                        </Tooltip>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={c.disabled ? 'destructive' : 'default'} className={c.disabled ? 'bg-destructive/10 text-destructive hover:bg-destructive/20 border-destructive/20' : 'bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20 border-emerald-500/20'}>
                        {c.disabled ? 'Inactive' : 'Active'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex justify-end gap-2">
                        <Button size="sm" variant="outline" className="h-8" onClick={() => setEditClient(c)}>
                          Edit
                        </Button>
                        <Button size="sm" variant="ghost" className="h-8 text-destructive hover:text-destructive hover:bg-destructive/10" onClick={() => setConfirmDelete(c)}>
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            
            {selectedClient && (
              <div className="border-t border-border/50 bg-muted/20 px-6 py-6 animate-in slide-in-from-top-2">
                <h3 className="text-sm font-semibold text-foreground uppercase tracking-widest mb-4 flex items-center gap-2">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary"><polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" /></svg>
                  Integration Guide
                </h3>
                
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <p className="text-sm text-muted-foreground mb-2">
                      Add to your consuming app's <code className="text-xs bg-muted px-1 py-0.5 rounded">.env</code>:
                    </p>
                    <div className="relative group">
                      <pre className="rounded-lg bg-black/80 dark:bg-black/40 p-4 text-xs text-green-400 font-mono overflow-x-auto border border-border/50 shadow-inner">
{`JWKS_URL=${JWKS_URL}
AUTH_ISSUER=${AUTH_ISSUER}
CLIENT_ID=${selectedClient.client_id}`}
                      </pre>
                      <Button
                        size="icon"
                        variant="secondary"
                        className="absolute top-2 right-2 h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                        onClick={() => {
                          void navigator.clipboard.writeText(`JWKS_URL=${JWKS_URL}\nAUTH_ISSUER=${AUTH_ISSUER}\nCLIENT_ID=${selectedClient.client_id}`);
                          toast.success('Environment variables copied');
                        }}
                      >
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                      </Button>
                    </div>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground mb-2">Verify tokens (Node.js):</p>
                    <div className="relative group">
                      <pre className="rounded-lg bg-black/80 dark:bg-black/40 p-4 text-xs text-sky-300 font-mono overflow-x-auto border border-border/50 shadow-inner">
{`import { createRemoteJWKSet, jwtVerify } from 'jose'

const JWKS = createRemoteJWKSet(
  new URL(process.env.JWKS_URL)
)

const { payload } = await jwtVerify(token, JWKS, {
  issuer: process.env.AUTH_ISSUER,
  audience: process.env.CLIENT_ID
})`}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </Card>

      {showRegister && (
        <RegisterAppModal
          onClose={() => setShowRegister(false)}
          onSuccess={(newClient) => {
            if (newClient) addClientLocal(newClient);
          }}
        />
      )}
      {editClient && (
        <EditAppModal
          client={editClient}
          onClose={() => setEditClient(null)}
          onSuccess={(updatedClient) => {
            if (updatedClient) updateClientLocal(updatedClient);
          }}
        />
      )}
    </AdminLayout>
  );
};
