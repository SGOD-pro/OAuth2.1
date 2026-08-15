import React, { useEffect, useState, useCallback } from 'react';
import { AdminLayout } from './AdminLayout';
import { RegisterAppModal } from './RegisterAppModal';
import { EditAppModal } from './EditAppModal';
import { ProvisionAdminModal } from './ProvisionAdminModal';
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

const AUTH_ISSUER = import.meta.env.VITE_AUTH_URL ?? 'https://auth.yourdomain.com';

export const AdminClients: React.FC = () => {
  const { data, loading } = useAdminStore((state) => state.clients);
  const fetchClients = useAdminStore((state) => state.fetchClients);
  const deleteClientLocal = useAdminStore((state) => state.deleteClientLocal);
  
  const clients = data || [];

  const [showRegister, setShowRegister] = useState(false);
  const [showProvisionAdmin, setShowProvisionAdmin] = useState(false);
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
        <div className="flex flex-wrap items-end justify-between gap-4 mb-8">
          <div>
            <span className="font-mono text-xs uppercase tracking-[0.2em] text-accent mb-1 block">
              OAuth 2.1 Registry
            </span>
            <h1 className="font-heading text-3xl sm:text-[42px] leading-[1.1] font-normal text-foreground">
              Client Applications
            </h1>
            <p className="mt-2 font-sans text-sm text-muted-foreground">
              Manage registered applications, client secrets, allowed scopes, and telemetry bindings.
            </p>
          </div>

          <Button onClick={() => setShowRegister(true)} className="h-10 px-5">
            <svg className="mr-2 size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            Register Application
          </Button>
        </div>

        <Dialog open={!!confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(null)}>
          <DialogContent className="sm:max-w-[480px] w-full">
            <DialogHeader>
              <DialogTitle>Revoke Application</DialogTitle>
              <DialogDescription>
                Are you certain you want to revoke <span className="font-mono font-semibold text-foreground">{confirmDelete?.client_name}</span>? All issued telemetry tokens and active sessions will be invalidated immediately.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter className="mt-4">
              <Button variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
              <Button 
                variant="destructive" 
                onClick={() => confirmDelete && void handleDelete(confirmDelete)}
                disabled={deletingId === confirmDelete?.client_id}
              >
                {deletingId === confirmDelete?.client_id ? 'Revoking...' : 'Confirm Revoke'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {loading && clients.length === 0 ? (
          <div className="p-16 text-center flex flex-col items-center justify-center text-muted-foreground">
            <div className="size-8 animate-spin rounded-full border-2 border-accent border-t-transparent mb-4" />
            <span className="font-mono text-xs uppercase tracking-wider">Loading Registry Telemetry...</span>
          </div>
        ) : clients.length === 0 ? (
          <Card className="w-full">
            <CardContent className="p-12 text-center flex flex-col items-center justify-center">
              <div className="size-14 rounded-full bg-secondary flex items-center justify-center text-muted-foreground mb-4">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="3" width="7" height="7" />
                  <rect x="14" y="3" width="7" height="7" />
                  <rect x="14" y="14" width="7" height="7" />
                  <rect x="3" y="14" width="7" height="7" />
                </svg>
              </div>
              <h3 className="font-heading text-xl font-normal text-foreground mb-1">No Applications Registered</h3>
              <p className="font-sans text-sm text-muted-foreground mb-6">Register your first OAuth 2.1 client to activate telemetry tokens.</p>
              <Button onClick={() => setShowRegister(true)}>Register Application</Button>
            </CardContent>
          </Card>
        ) : (
          <div className="w-full space-y-4">
            <div className="border border-border/50 rounded-[16px] overflow-hidden bg-card/40 backdrop-blur-xl">
              <Table>
                <TableHeader className="bg-secondary/30">
                  <TableRow>
                    <TableHead className="w-[30%]">Application Name</TableHead>
                    <TableHead className="w-[30%]">Client Identifier</TableHead>
                    <TableHead className="w-[20%]">Status</TableHead>
                    <TableHead className="text-right">Telemetry Controls</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {clients.map((c, index) => {
                    const isSelected = selectedClient?.client_id === c.client_id;
                    const delayStyle = { animationDelay: `${(index + 1) * 75}ms` };

                    return (
                      <React.Fragment key={c.client_id}>
                        <TableRow 
                          style={delayStyle}
                          className={`cursor-pointer transition-colors animate-in fade-in slide-in-from-bottom-2 duration-500 ${isSelected ? 'bg-secondary/70' : ''}`}
                          onClick={() => setSelectedClient((s) => (s?.client_id === c.client_id ? null : c))}
                        >
                          <TableCell className="font-medium">
                            <div className="flex items-center gap-3">
                              <div className="size-8 rounded-md bg-secondary border border-border flex items-center justify-center font-mono text-xs text-foreground font-semibold uppercase">
                                {c.client_name.substring(0, 2)}
                              </div>
                              <span className="font-sans font-medium text-foreground">{c.client_name}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <code className="font-mono text-xs bg-secondary/80 px-2 py-1 rounded text-muted-foreground border border-border/50">
                                {c.client_id.slice(0, 8)}...{c.client_id.slice(-4)}
                              </code>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button 
                                    variant="ghost" 
                                    size="icon-xs" 
                                    className="h-6 w-6 rounded text-muted-foreground hover:text-foreground" 
                                    onClick={(e) => copyClientId(c.client_id, e)}
                                  >
                                    {copiedId === c.client_id ? (
                                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="text-emerald-500">
                                        <polyline points="20 6 9 17 4 12" />
                                      </svg>
                                    ) : (
                                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
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
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Badge variant={c.disabled ? 'destructive' : 'success'}>
                                {c.disabled ? 'SUSPENDED' : 'ACTIVE'}
                              </Badge>
                              <Badge 
                                variant="outline" 
                                className={c.is_dev ? 'bg-amber-500/10 text-amber-400 border-amber-500/30 font-mono text-[10px]' : 'bg-blue-500/10 text-blue-400 border-blue-500/30 font-mono text-[10px]'}
                              >
                                {c.is_dev ? 'DEV' : 'PROD'}
                              </Badge>
                            </div>
                          </TableCell>
                          <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                            <div className="flex justify-end gap-2">
                              <Button 
                                size="xs" 
                                variant="outline" 
                                onClick={() => setEditClient(c)}
                              >
                                Edit Config
                              </Button>
                              <Button 
                                size="xs" 
                                variant="ghost" 
                                className="text-destructive hover:text-destructive hover:bg-destructive/10" 
                                onClick={() => setConfirmDelete(c)}
                              >
                                Revoke
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>

                        {isSelected && (
                          <TableRow className="bg-secondary/20 hover:bg-secondary/20 border-b border-border/60">
                            <TableCell colSpan={4} className="p-6 whitespace-normal">
                              <div className="animate-in fade-in slide-in-from-top-2 duration-300 space-y-6">
                                <div className="flex items-center justify-between">
                                  <div className="flex items-center gap-2">
                                    <span className="font-mono text-xs uppercase tracking-wider text-accent font-medium">
                                      Application Configuration //
                                    </span>
                                    <span className="font-mono text-xs text-foreground font-semibold">{c.client_name}</span>
                                  </div>

                                  {c.adminEmail ? (
                                    <div className="flex items-center gap-2">
                                      <Badge variant="outline" className="font-mono text-[10px]">
                                        Admin: {c.adminEmail}
                                      </Badge>
                                    </div>
                                  ) : (
                                    <Button size="xs" variant="outline" onClick={() => setShowProvisionAdmin(true)}>
                                      Provision Admin
                                    </Button>
                                  )}
                                </div>

                                <div className="grid lg:grid-cols-2 gap-6 pt-2">
                                  <div className="space-y-3">
                                    <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground block">
                                      1. Authorize Endpoint URL:
                                    </span>
                                    <pre className="p-3.5 rounded-lg bg-background/80 border border-border text-[11px] font-mono text-foreground break-all whitespace-pre-wrap">
                                      {AUTH_ISSUER}/api/auth/oauth2/authorize?client_id={c.client_id}&response_type=code&redirect_uri=YOUR_CALLBACK&scope=openid profile email
                                    </pre>
                                  </div>

                                  <div className="space-y-3">
                                    <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground block">
                                      2. Token Exchange Endpoint:
                                    </span>
                                    <pre className="p-3.5 rounded-lg bg-background/80 border border-border text-[11px] font-mono text-foreground break-all whitespace-pre-wrap">
                                      POST {AUTH_ISSUER}/api/auth/oauth2/token
                                    </pre>
                                  </div>
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

        {showProvisionAdmin && selectedClient && (
          <ProvisionAdminModal
            clientId={selectedClient.client_id}
            clientName={selectedClient.client_name}
            onClose={() => setShowProvisionAdmin(false)}
            onSuccess={() => {
              setShowProvisionAdmin(false);
              void fetchClients();
            }}
          />
        )}
      </div>
    </AdminLayout>
  );
};
