import React, { useEffect, useState, useCallback } from 'react';
import { AdminLayout } from './AdminLayout';
import { RegisterAppModal } from './RegisterAppModal';
import { EditAppModal } from './EditAppModal';
import { AppAdminManager } from './ProvisionAdminModal';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { csrfHeaders } from '@/lib/csrf';
import { toast } from 'sonner';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { apiFetch } from '@/lib/api';
import { useAdminStore, type OAuthClient } from '@/lib/adminStore';
import { usePageTitle } from '@/hooks/usePageTitle';

const AUTH_ISSUER = import.meta.env.VITE_AUTH_URL ?? 'https://auth.yourdomain.com';

export const AdminClients: React.FC = () => {
  usePageTitle('Applications');

  const { data, loading } = useAdminStore((state) => state.clients);
  const fetchClients = useAdminStore((state) => state.fetchClients);
  const deleteClientLocal = useAdminStore((state) => state.deleteClientLocal);
  
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
      const res = await apiFetch(`/api/admin/clients/${client.client_id}`, {
        method: 'DELETE',
        headers: {
          ...csrfHeaders(),
        },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      deleteClientLocal(client.client_id);
      if (selectedClient?.client_id === client.client_id) setSelectedClient(null);
      toast.success(`${client.client_name} removed from registry.`);
    } catch (err) {
      toast.error(`Failed to delete client: ${String(err)}`);
    } finally {
      setDeletingId(null);
      setConfirmDelete(null);
    }
  }, [selectedClient, deleteClientLocal]);

  const copyClientId = useCallback(async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(id);
    setCopiedId(id);
    toast.success('Client ID copied to clipboard');
    setTimeout(() => setCopiedId(null), 2000);
  }, []);

  return (
    <AdminLayout>
      <div className="flex flex-col flex-1">
        {/* Header section */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 sm:mb-8">
          <div>
            <h1 className="font-heading text-2xl sm:text-[34px] font-semibold text-foreground tracking-tight leading-tight">
              Applications
            </h1>
            <p className="mt-1 font-sans text-sm text-muted-foreground">
              Manage registered OAuth 2.1 client applications, redirect URIs, and credentials.
            </p>
          </div>

          <Button onClick={() => setShowRegister(true)} className="h-9 px-4 self-start sm:self-auto shrink-0">
            <svg className="mr-1.5 size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            Create application
          </Button>
        </div>

        <Dialog open={!!confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(null)}>
          <DialogContent className="sm:max-w-[480px] w-full">
            <DialogHeader>
              <DialogTitle>Revoke application</DialogTitle>
              <DialogDescription>
                Are you sure you want to revoke <span className="font-mono font-medium text-foreground">{confirmDelete?.client_name}</span>? All issued access tokens, refresh tokens, and active sessions will be invalidated immediately.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter className="mt-4">
              <Button variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
              <Button 
                variant="destructive" 
                onClick={() => confirmDelete && void handleDelete(confirmDelete)}
                disabled={deletingId === confirmDelete?.client_id}
              >
                {deletingId === confirmDelete?.client_id ? 'Revoking...' : 'Revoke application'}
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
          <Card className="w-full">
            <CardContent className="p-12 text-center flex flex-col items-center justify-center">
              <div className="size-12 rounded-lg bg-secondary border border-border flex items-center justify-center text-muted-foreground mb-4">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="3" width="7" height="7" />
                  <rect x="14" y="3" width="7" height="7" />
                  <rect x="14" y="14" width="7" height="7" />
                  <rect x="3" y="14" width="7" height="7" />
                </svg>
              </div>
              <h3 className="font-heading text-lg font-medium text-foreground mb-1">No applications registered</h3>
              <p className="font-sans text-sm text-muted-foreground mb-6">
                Register your first OAuth 2.1 client to issue credentials and authorize users.
              </p>
              <Button onClick={() => setShowRegister(true)}>Create application</Button>
            </CardContent>
          </Card>
        ) : (
          <div className="w-full space-y-4">
            <div className="border border-border rounded-[12px] overflow-hidden bg-card">
              <Table>
                <TableHeader className="bg-secondary/40 border-b border-border">
                  <TableRow>
                    <TableHead className="w-[32%] text-xs font-medium uppercase tracking-wider text-muted-foreground">Application</TableHead>
                    <TableHead className="w-[36%] text-xs font-medium uppercase tracking-wider text-muted-foreground">Client ID</TableHead>
                    <TableHead className="w-[16%] text-xs font-medium uppercase tracking-wider text-muted-foreground">Status</TableHead>
                    <TableHead className="text-right text-xs font-medium uppercase tracking-wider text-muted-foreground">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {clients.map((c) => {
                    const isSelected = selectedClient?.client_id === c.client_id;

                    return (
                      <React.Fragment key={c.client_id}>
                        <TableRow 
                          className={`cursor-pointer transition-colors border-b border-border/70 ${isSelected ? 'bg-secondary/60' : 'hover:bg-secondary/30'}`}
                          onClick={() => setSelectedClient((s) => (s?.client_id === c.client_id ? null : c))}
                        >
                          <TableCell className="font-medium py-3.5">
                            <div className="flex items-center gap-3">
                              <div className="size-8 rounded-md bg-secondary border border-border flex items-center justify-center font-mono text-xs text-foreground font-semibold uppercase shrink-0">
                                {c.client_name.substring(0, 2)}
                              </div>
                              <span className="font-sans font-medium text-foreground text-sm">{c.client_name}</span>
                            </div>
                          </TableCell>
                          <TableCell className="py-3.5">
                            <div className="flex items-center gap-1.5">
                              <code className="font-mono text-xs bg-secondary/70 px-2 py-1 rounded-md text-muted-foreground border border-border">
                                {c.client_id.slice(0, 8)}...{c.client_id.slice(-4)}
                              </code>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button 
                                    variant="ghost" 
                                    size="icon" 
                                    className="size-7 rounded-md text-muted-foreground hover:text-foreground" 
                                    onClick={(e) => copyClientId(c.client_id, e)}
                                    aria-label="Copy Client ID"
                                  >
                                    {copiedId === c.client_id ? (
                                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="text-emerald-500">
                                        <polyline points="20 6 9 17 4 12" />
                                      </svg>
                                    ) : (
                                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                                      </svg>
                                    )}
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent side="top">Copy Client ID</TooltipContent>
                              </Tooltip>
                            </div>
                          </TableCell>
                          <TableCell className="py-3.5">
                            <div className="flex items-center gap-1.5">
                              <Badge variant={c.disabled ? 'destructive' : 'success'}>
                                {c.disabled ? 'Suspended' : 'Active'}
                              </Badge>
                              <Badge 
                                variant="outline" 
                                className={c.is_dev ? 'bg-amber-500/10 text-amber-500 border-amber-500/30 text-[11px]' : 'bg-primary/10 text-primary border-primary/30 text-[11px]'}
                              >
                                {c.is_dev ? 'Dev' : 'Prod'}
                              </Badge>
                              <Badge 
                                variant="outline" 
                                className={c.is_public !== false && (c as Record<string, unknown>).isPublic !== false ? 'bg-sky-500/10 text-sky-500 border-sky-500/30 text-[11px]' : 'bg-purple-500/10 text-purple-500 border-purple-500/30 text-[11px]'}
                              >
                                {c.is_public !== false && (c as Record<string, unknown>).isPublic !== false ? 'Public' : 'Private'}
                              </Badge>
                            </div>
                          </TableCell>
                          <TableCell className="text-right py-3.5" onClick={(e) => e.stopPropagation()}>
                            <div className="flex justify-end gap-1.5">
                              <Button 
                                size="sm" 
                                variant="outline" 
                                className="h-8 px-2.5 text-xs rounded-md"
                                onClick={() => setEditClient(c)}
                              >
                                Edit
                              </Button>
                              <Button 
                                size="sm" 
                                variant="ghost" 
                                className="h-8 px-2.5 text-xs rounded-md text-destructive hover:text-destructive hover:bg-destructive/10" 
                                onClick={() => setConfirmDelete(c)}
                              >
                                Revoke
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>

                        {isSelected && (
                          <TableRow className="bg-secondary/20 hover:bg-secondary/20 border-b border-border">
                            <TableCell colSpan={4} className="p-5 sm:p-6 whitespace-normal">
                              <div className="space-y-5">
                                <div className="flex items-center justify-between pb-3 border-b border-border">
                                  <div className="flex items-center gap-2">
                                    <span className="font-heading text-sm font-medium text-foreground">
                                      Configuration for {c.client_name}
                                    </span>
                                  </div>
                                </div>

                                <div className="grid lg:grid-cols-2 gap-4 sm:gap-6">
                                  <div className="space-y-1.5">
                                    <span className="font-sans text-xs font-medium text-muted-foreground block">
                                      Redirect URIs ({ (c.redirect_uris ?? c.redirectUris ?? []).length })
                                    </span>
                                    <div className="flex flex-wrap gap-1.5 p-3 rounded-md bg-background border border-border min-h-[42px]">
                                      {(c.redirect_uris ?? c.redirectUris ?? []).length > 0 ? (
                                        (c.redirect_uris ?? c.redirectUris ?? []).map((uri) => (
                                          <code key={uri} className="font-mono text-xs bg-secondary px-2 py-0.5 rounded text-foreground border border-border/60">
                                            {uri}
                                          </code>
                                        ))
                                      ) : (
                                        <span className="font-sans text-xs text-muted-foreground italic">No redirect URIs configured</span>
                                      )}
                                    </div>
                                  </div>

                                  <div className="space-y-1.5">
                                    <span className="font-sans text-xs font-medium text-muted-foreground block">
                                      Allowed CORS Origins ({ (c.allowed_origins ?? c.allowedOrigins ?? c.metadata?.allowedOrigins ?? []).length })
                                    </span>
                                    <div className="flex flex-wrap gap-1.5 p-3 rounded-md bg-background border border-border min-h-[42px]">
                                      {(c.allowed_origins ?? c.allowedOrigins ?? c.metadata?.allowedOrigins ?? []).length > 0 ? (
                                        (c.allowed_origins ?? c.allowedOrigins ?? c.metadata?.allowedOrigins ?? []).map((origin) => (
                                          <code key={origin} className="font-mono text-xs bg-secondary px-2 py-0.5 rounded text-primary border border-primary/20">
                                            {origin}
                                          </code>
                                        ))
                                      ) : (
                                        <span className="font-sans text-xs text-muted-foreground italic">No allowed origins configured</span>
                                      )}
                                    </div>
                                  </div>
                                </div>

                                <div className="grid lg:grid-cols-2 gap-4 sm:gap-6 pt-1">
                                  <div className="space-y-1.5">
                                    <span className="font-sans text-xs font-medium text-muted-foreground block">
                                      Authorize Endpoint
                                    </span>
                                    <pre className="p-3 rounded-md bg-background border border-border text-xs font-mono text-foreground break-all whitespace-pre-wrap">
                                      {AUTH_ISSUER}/api/auth/oauth2/authorize?client_id={c.client_id}&response_type=code&redirect_uri=YOUR_CALLBACK&scope=openid profile email
                                    </pre>
                                  </div>

                                  <div className="space-y-1.5">
                                    <span className="font-sans text-xs font-medium text-muted-foreground block">
                                      Token Exchange Endpoint
                                    </span>
                                    <pre className="p-3 rounded-md bg-background border border-border text-xs font-mono text-foreground break-all whitespace-pre-wrap">
                                      POST {AUTH_ISSUER}/api/auth/oauth2/token
                                    </pre>
                                  </div>
                                </div>

                                <div className="border-t border-border pt-4">
                                  <AppAdminManager
                                    clientId={c.client_id}
                                    clientName={c.client_name}
                                    allowedOrigins={c.allowed_origins ?? c.allowedOrigins ?? c.metadata?.allowedOrigins ?? []}
                                    redirectUris={c.redirect_uris ?? c.redirectUris ?? []}
                                  />
                                </div>
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </React.Fragment>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </div>
        )}

        {showRegister && (
          <RegisterAppModal
            onClose={() => setShowRegister(false)}
            onSuccess={() => {
              setShowRegister(false);
              void fetchClients();
            }}
          />
        )}

        {editClient && (
          <EditAppModal
            client={editClient}
            onClose={() => setEditClient(null)}
            onSuccess={() => {
              setEditClient(null);
              void fetchClients();
            }}
          />
        )}
      </div>
    </AdminLayout>
  );
};
