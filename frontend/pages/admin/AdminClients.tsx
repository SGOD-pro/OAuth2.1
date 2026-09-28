import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { AdminLayout } from './AdminLayout';
import { RegisterAppModal } from './RegisterAppModal';
import { EditAppModal } from './EditAppModal';
import { AppAdminManager } from './ProvisionAdminModal';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
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
import { Search, X, RotateCcw, Filter, ShieldCheck } from 'lucide-react';
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
const AUTH_ISSUER = import.meta.env.VITE_AUTH_URL ?? 'https://auth.yourdomain.com';

export const AdminClients: React.FC = () => {
  usePageTitle('Applications');

  const { data, loading } = useAdminStore((state) => state.clients);
  const fetchClients = useAdminStore((state) => state.fetchClients);
  const deleteClientLocal = useAdminStore((state) => state.deleteClientLocal);
  const addClientLocal = useAdminStore((state) => state.addClientLocal);

  const rawClients = data;
  const clients = useMemo(() => rawClients || [], [rawClients]);

  const [showRegister, setShowRegister] = useState(false);
  const [editClient, setEditClient] = useState<OAuthClient | null>(null);
  const [selectedClient, setSelectedClient] = useState<OAuthClient | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<OAuthClient | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Search and filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [envFilter, setEnvFilter] = useState<'all' | 'prod' | 'dev'>('all');
  const [accessFilter, setAccessFilter] = useState<'all' | 'public' | 'private'>('all');
  const [hasAdminsOnly, setHasAdminsOnly] = useState(false);

  // Debounce search term by 250ms
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchTerm);
    }, 250);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  const hasActiveFilters = Boolean(
    searchTerm.trim() ||
    envFilter !== 'all' ||
    accessFilter !== 'all' ||
    hasAdminsOnly
  );

  const resetFilters = useCallback(() => {
    setSearchTerm('');
    setDebouncedSearch('');
    setEnvFilter('all');
    setAccessFilter('all');
    setHasAdminsOnly(false);
  }, []);

  // Compute filtered clients based on debounced search and active filters
  const filteredClients = useMemo(() => {
    const list = clients.filter((c) => {
      // 1. Search filter: match name or client_id
      if (debouncedSearch.trim()) {
        const query = debouncedSearch.trim().toLowerCase();
        const nameMatch = c.client_name?.toLowerCase().includes(query);
        const idMatch = c.client_id?.toLowerCase().includes(query);
        if (!nameMatch && !idMatch) return false;
      }

      // 2. Environment filter: prod vs dev
      const isDev = Boolean(c.is_dev || c.isDev);
      if (envFilter === 'prod' && isDev) return false;
      if (envFilter === 'dev' && !isDev) return false;

      // 3. Access mode filter: public vs private
      const isPublic = c.is_public !== false && c.isPublic !== false;
      if (accessFilter === 'public' && !isPublic) return false;
      if (accessFilter === 'private' && isPublic) return false;

      // 4. Assigned custom admins filter
      if (hasAdminsOnly) {
        const hasCustomAdmins = Boolean(
          c.has_custom_admins ||
          c.hasCustomAdmins ||
          c.adminEmail ||
          c.adminUserId
        );
        if (!hasCustomAdmins) return false;
      }

      return true;
    });

    // Last registered app always on top (sort by created time descending)
    return list.sort((a, b) => {
      const timeA = a.createdAt ? new Date(a.createdAt).getTime() : (a.created_at ? new Date(a.created_at).getTime() : 0);
      const timeB = b.createdAt ? new Date(b.createdAt).getTime() : (b.created_at ? new Date(b.created_at).getTime() : 0);
      return timeB - timeA;
    });
  }, [clients, debouncedSearch, envFilter, accessFilter, hasAdminsOnly]);

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
            {/* Search and Filter Toolbar */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 p-3 rounded-[12px] bg-card border border-border shadow-2xs">
              <div className="flex flex-1 flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
                {/* Search Box with Debouncing */}
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-4 text-muted-foreground pointer-events-none" />
                  <Input
                    type="text"
                    placeholder="Search by name or client ID..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-8.5 pr-8 h-9 text-xs"
                    aria-label="Search applications"
                  />
                  {searchTerm && (
                    <button
                      type="button"
                      onClick={() => setSearchTerm('')}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-0.5 rounded cursor-pointer"
                      aria-label="Clear search text"
                    >
                      <X className="size-3.5" />
                    </button>
                  )}
                </div>

                {/* Filter by Environment: Prod vs Dev */}
                <div className="relative shrink-0">



                  <Select value={envFilter} onValueChange={(e) => setEnvFilter(e as 'all' | 'prod' | 'dev')}>
                    <SelectTrigger className="w-full max-w-48">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectLabel>Fruits</SelectLabel>
                        <SelectItem value="all">All environments</SelectItem>
                        <SelectItem value="prod">Production only</SelectItem>
                        <SelectItem value="dev">Development only</SelectItem>

                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2.5 text-muted-foreground">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="6 9 12 15 18 9" />
                    </svg>
                  </div>
                </div>

                <div className="relative shrink-0">
                  <Select value={accessFilter} onValueChange={(e) => setAccessFilter(e as 'all' | 'public' | 'private')}>
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectLabel>Fruits</SelectLabel>
                        <SelectItem value="all">All access modes</SelectItem>
                        <SelectItem value="public">Public access</SelectItem>
                        <SelectItem value="private">Private access</SelectItem>

                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2.5 text-muted-foreground">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="6 9 12 15 18 9" />
                    </svg>
                  </div>
                </div>

                {/* Checkbox: Assigned custom admins */}
                <label className="flex items-center gap-2 px-3 py-1.5 rounded-md border border-border bg-secondary/20 hover:bg-secondary/40 cursor-pointer text-xs font-medium text-foreground select-none shrink-0 h-9 transition-colors">
                  <Checkbox
                    checked={hasAdminsOnly}
                    onCheckedChange={(checked) => setHasAdminsOnly(Boolean(checked))}
                  />
                  <span>Assigned custom admins</span>
                </label>
              </div>

              {/* Status & Reset Toolbar Actions */}
              <div className="flex items-center justify-between lg:justify-end gap-3 shrink-0 pt-2 lg:pt-0 border-t lg:border-t-0 border-border/50">
                <span className="text-xs text-muted-foreground font-mono">
                  Showing {filteredClients.length} of {clients.length} app{clients.length === 1 ? '' : 's'}
                </span>
                {hasActiveFilters && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={resetFilters}
                    className="h-8 px-2.5 text-xs text-muted-foreground hover:text-foreground gap-1.5"
                  >
                    <RotateCcw className="size-3" />
                    Reset
                  </Button>
                )}
              </div>
            </div>

            {filteredClients.length === 0 ? (
              <Card className="w-full">
                <CardContent className="p-12 text-center flex flex-col items-center justify-center">
                  <div className="size-12 rounded-lg bg-secondary border border-border flex items-center justify-center text-muted-foreground mb-4">
                    <Filter className="size-5" />
                  </div>
                  <h3 className="font-heading text-lg font-medium text-foreground mb-1">No matching applications</h3>
                  <p className="font-sans text-sm text-muted-foreground mb-4 max-w-sm">
                    No registered applications match your current search and filter settings.
                  </p>
                  <Button variant="outline" size="sm" onClick={resetFilters} className="gap-1.5">
                    <RotateCcw className="size-3.5" />
                    Reset filters
                  </Button>
                </CardContent>
              </Card>
            ) : (
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
                    {filteredClients.map((c) => {
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
                              <div className="flex items-center gap-1.5 flex-wrap">
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
                                  className={c.is_public !== false && c.isPublic !== false ? 'bg-sky-500/10 text-sky-500 border-sky-500/30 text-[11px]' : 'bg-purple-500/10 text-purple-500 border-purple-500/30 text-[11px]'}
                                >
                                  {c.is_public !== false && c.isPublic !== false ? 'Public' : 'Private'}
                                </Badge>
                                {Boolean(c.has_custom_admins || c.hasCustomAdmins || c.adminEmail || c.adminUserId) && (
                                  <Badge
                                    variant="outline"
                                    className="bg-emerald-500/10 text-emerald-500 border-emerald-500/30 text-[11px] flex items-center gap-1"
                                    title="Custom application administrators assigned"
                                  >
                                    <ShieldCheck className="size-3" />
                                    Admin
                                  </Badge>
                                )}
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
                                        Redirect URIs ({(c.redirect_uris ?? c.redirectUris ?? []).length})
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
                                        Allowed CORS Origins ({(c.allowed_origins ?? c.allowedOrigins ?? c.metadata?.allowedOrigins ?? []).length})
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
                  client_id: created.client_id,
                  client_name: created.client_name || 'Application',
                  redirect_uris: created.redirect_uris || [],
                  allowed_origins: created.allowed_origins || [],
                  disabled: false,
                  is_dev: Boolean(created.is_dev || created.isDev),
                  is_public: created.is_public !== false && created.isPublic !== false,
                  isPublic: created.is_public !== false && created.isPublic !== false,
                  skip_consent: Boolean(created.skip_consent || created.skipConsent),
                  enable_end_session: created.enable_end_session !== false && created.enableEndSession !== false,
                  createdAt: created.createdAt || created.created_at || new Date().toISOString(),
                  created_at: created.createdAt || created.created_at || new Date().toISOString(),
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
