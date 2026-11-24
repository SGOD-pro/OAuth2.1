import React from 'react';
import { AppAdminManager } from './ProvisionAdminModal';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Pagination, PaginationContent, PaginationEllipsis, PaginationItem, PaginationLink, PaginationNext, PaginationPrevious } from '@/components/ui/pagination';
import { ShieldCheck } from 'lucide-react';
import type { OAuthClient } from '@/lib/adminStore-types';
import { ClientPolicyBadges } from './ClientPolicyBadges';

const AUTH_ISSUER = import.meta.env.VITE_AUTH_URL ?? 'https://auth.yourdomain.com';

function formatAppDate(isoString?: string | Date) {
  if (!isoString) return { dateStr: '—', timeStr: '', fullIso: '' };
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return { dateStr: '—', timeStr: '', fullIso: '' };
    return {
      dateStr: d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }),
      timeStr: d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }),
      fullIso: d.toISOString(),
    };
  } catch {
    return { dateStr: '—', timeStr: '', fullIso: '' };
  }
}

interface AdminClientsTableProps {
  clients: OAuthClient[];
  totalItems: number;
  currentPage: number;
  setCurrentPage: React.Dispatch<React.SetStateAction<number>>;
  pageSize: number;
  setPageSize: (n: number) => void;
  totalPages: number;
  selectedClient: OAuthClient | null;
  setSelectedClient: React.Dispatch<React.SetStateAction<OAuthClient | null>>;
  copiedId: string | null;
  copyClientId: (id: string, e: React.MouseEvent) => void;
  onEdit: (client: OAuthClient) => void;
  onDelete: (client: OAuthClient) => void;
}

export const AdminClientsTable: React.FC<AdminClientsTableProps> = ({
  clients, totalItems, currentPage, setCurrentPage, pageSize, setPageSize, totalPages,
  selectedClient, setSelectedClient, copiedId, copyClientId, onEdit, onDelete,
}) => {
  const getPageNumbers = () => {
    if (totalPages <= 5) return Array.from({ length: totalPages }, (_, i) => i + 1);
    const pages: (number | 'ellipsis')[] = [1];
    if (currentPage > 3) pages.push('ellipsis');
    for (let i = Math.max(2, currentPage - 1); i <= Math.min(totalPages - 1, currentPage + 1); i++) pages.push(i);
    if (currentPage < totalPages - 2) pages.push('ellipsis');
    pages.push(totalPages);
    return pages;
  };

  return (
    <div className="space-y-4">
      <div className="md:hidden space-y-3">
        {clients.map((c) => {
          const isSelected = selectedClient?.client_id === c.client_id;
          const { dateStr, timeStr } = formatAppDate(c.createdAt || c.created_at);
          return (
            <Card key={c.client_id} className={`transition-colors border border-border cursor-pointer ${isSelected ? 'bg-secondary/40 ring-1 ring-border' : 'bg-card'}`} onClick={() => setSelectedClient((s) => (s?.client_id === c.client_id ? null : c))}>
              <CardContent className="p-4 space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 space-y-1.5">
                    <h3 className="font-sans font-medium text-foreground text-sm truncate">{c.client_name}</h3>
                    <ClientPolicyBadges client={c} />
                  </div>
                  <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${c.disabled ? 'text-destructive' : 'text-emerald-600 dark:text-emerald-400'}`}>
                    <span className={`size-1.5 rounded-full ${c.disabled ? 'bg-destructive' : 'bg-emerald-500'}`} />
                    {c.disabled ? 'Disabled' : 'Active'}
                  </span>
                </div>
                <div className="flex items-center justify-between pt-1 text-xs text-muted-foreground">
                  <span>{dateStr} {timeStr}</span>
                  <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                    <Button size="sm" variant="outline" className="h-8 px-2.5 text-xs rounded-md" onClick={() => onEdit(c)}>Edit</Button>
                    <Button size="sm" variant="ghost" className="h-8 px-2.5 text-xs rounded-md text-destructive hover:bg-destructive/10" onClick={() => onDelete(c)}>Revoke</Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="hidden md:block border border-border rounded-[12px] overflow-hidden bg-card">
        <Table>
          <TableHeader className="bg-secondary/40 border-b border-border">
            <TableRow>
              <TableHead className="w-[24%] text-xs font-medium text-muted-foreground">Application</TableHead>
              <TableHead className="w-[20%] text-xs font-medium text-muted-foreground">Client ID</TableHead>
              <TableHead className="w-[30%] text-xs font-medium text-muted-foreground">Policy & Status</TableHead>
              <TableHead className="w-[12%] text-xs font-medium text-muted-foreground">Created</TableHead>
              <TableHead className="text-right text-xs font-medium text-muted-foreground">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {clients.map((c) => {
              const isSelected = selectedClient?.client_id === c.client_id;
              const { dateStr, timeStr, fullIso } = formatAppDate(c.createdAt || c.created_at);
              return (
                <React.Fragment key={c.client_id}>
                  <TableRow className={`cursor-pointer transition-colors border-b border-border/70 ${isSelected ? 'bg-secondary/60' : 'hover:bg-secondary/30'}`} onClick={() => setSelectedClient((s) => (s?.client_id === c.client_id ? null : c))}>
                    <TableCell className="font-medium py-3.5">
                      <div className="flex items-center gap-3">
                        <div className="size-9 rounded-xl bg-secondary border border-border flex items-center justify-center font-mono text-xs text-foreground font-semibold uppercase shrink-0">
                          {c.client_name.substring(0, 2)}
                        </div>
                        <div className="min-w-0">
                          <span className="font-sans font-medium text-foreground text-sm block truncate">{c.client_name}</span>
                          <span className={`inline-flex items-center gap-1 text-[11px] font-medium ${c.disabled ? 'text-destructive' : 'text-emerald-600 dark:text-emerald-400'}`}>
                            <span className={`size-1.5 rounded-full ${c.disabled ? 'bg-destructive' : 'bg-emerald-500'}`} />
                            {c.disabled ? 'Disabled' : 'Active'}
                          </span>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="py-3.5">
                      <div className="flex items-center gap-1.5">
                        <code className="font-mono text-xs bg-secondary/70 px-2 py-1 rounded-md text-muted-foreground border border-border">
                          {c.client_id.slice(0, 8)}...{c.client_id.slice(-4)}
                        </code>
                        <Button variant="ghost" size="icon" className="size-7 rounded-md text-muted-foreground hover:text-foreground" onClick={(e) => copyClientId(c.client_id, e)} aria-label="Copy Client ID">
                          {copiedId === c.client_id ? '✓' : '⧉'}
                        </Button>
                      </div>
                    </TableCell>
                    <TableCell className="py-3.5">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <ClientPolicyBadges client={c} />
                        {Boolean(c.has_custom_admins || c.hasCustomAdmins || c.adminEmail || c.adminUserId) && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="inline-flex items-center gap-1 rounded-full border border-border px-2 py-0.5 text-[11px] text-muted-foreground">
                                <ShieldCheck className="size-3" /> Admins
                              </span>
                            </TooltipTrigger>
                            <TooltipContent side="top">Assigned custom app admins</TooltipContent>
                          </Tooltip>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="py-3.5">
                      {dateStr === '—' ? <span className="text-muted-foreground text-xs">—</span> : (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <div className="flex flex-col text-xs cursor-default">
                              <span className="font-medium text-foreground whitespace-nowrap">{dateStr}</span>
                              <span className="text-[11px] text-muted-foreground whitespace-nowrap">{timeStr}</span>
                            </div>
                          </TooltipTrigger>
                          <TooltipContent side="top" className="text-xs">Registered: {fullIso}</TooltipContent>
                        </Tooltip>
                      )}
                    </TableCell>
                    <TableCell className="text-right py-3.5" onClick={(e) => e.stopPropagation()}>
                      <div className="flex justify-end gap-1.5">
                        <Button size="sm" variant="outline" className="h-8 px-2.5 text-xs rounded-md" onClick={() => onEdit(c)}>Edit</Button>
                        <Button size="sm" variant="ghost" className="h-8 px-2.5 text-xs rounded-md text-destructive hover:bg-destructive/10" onClick={() => onDelete(c)}>Revoke</Button>
                      </div>
                    </TableCell>
                  </TableRow>

                  {isSelected && (
                    <TableRow className="bg-secondary/20 hover:bg-secondary/20 border-b border-border">
                      <TableCell colSpan={5} className="p-5 whitespace-normal">
                        <div className="space-y-4">
                          <div className="grid lg:grid-cols-2 gap-4">
                            <div>
                              <span className="font-sans text-xs font-medium text-muted-foreground block mb-1">Redirect URIs</span>
                              <div className="flex flex-wrap gap-1.5 p-2.5 rounded-md bg-background border border-border">
                                {(c.redirect_uris ?? c.redirectUris ?? []).map((uri) => (
                                  <code key={uri} className="font-mono text-xs bg-secondary px-2 py-0.5 rounded">{uri}</code>
                                ))}
                              </div>
                            </div>
                            <div>
                              <span className="font-sans text-xs font-medium text-muted-foreground block mb-1">Authorize Endpoint</span>
                              <pre className="p-2.5 rounded-md bg-background border border-border text-xs font-mono break-all whitespace-pre-wrap">
                                {AUTH_ISSUER}/api/auth/oauth2/authorize?client_id={c.client_id}&response_type=code
                              </pre>
                            </div>
                          </div>
                          <div className="border-t border-border pt-4">
                            <AppAdminManager
                              clientId={c.client_id}
                              clientName={c.client_name}
                              allowedOrigins={c.allowed_origins ?? c.allowedOrigins ?? []}
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

        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-3.5 border-t border-border bg-card">
          <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
            <span>Showing {totalItems > 0 ? (currentPage - 1) * pageSize + 1 : 0} to {Math.min(currentPage * pageSize, totalItems)} of {totalItems}</span>
            <Select value={String(pageSize)} onValueChange={(v) => { setPageSize(Number(v)); setCurrentPage(1); }}>
              <SelectTrigger className="h-8 w-[70px] text-xs"><SelectValue /></SelectTrigger>
              <SelectContent side="top">
                <SelectItem value="5">5</SelectItem><SelectItem value="10">10</SelectItem>
                <SelectItem value="25">25</SelectItem><SelectItem value="50">50</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {totalPages > 1 && (
            <Pagination className="mx-0 w-auto justify-end">
              <PaginationContent>
                <PaginationItem><PaginationPrevious onClick={() => setCurrentPage((p) => Math.max(1, p - 1))} disabled={currentPage === 1} /></PaginationItem>
                {getPageNumbers().map((p, i) => p === 'ellipsis' ? <PaginationItem key={`e-${i}`}><PaginationEllipsis /></PaginationItem> : (
                  <PaginationItem key={p}><PaginationLink isActive={currentPage === p} onClick={() => setCurrentPage(p)} className="cursor-pointer">{p}</PaginationLink></PaginationItem>
                ))}
                <PaginationItem><PaginationNext onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} /></PaginationItem>
              </PaginationContent>
            </Pagination>
          )}
        </div>
      </div>
    </div>
  );
};
