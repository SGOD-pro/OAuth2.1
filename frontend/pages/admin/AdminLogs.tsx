import React, { useEffect, useRef, useState, useMemo } from 'react';
import { AdminLayout } from './AdminLayout';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { useAdminStore, type LogEntry } from '@/lib/adminStore';
import { usePageTitle } from '@/hooks/usePageTitle';

const PAGE_SIZE = 20;

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return iso;
  }
}

function getActionVariant(action: string) {
  const lower = action.toLowerCase();
  if (lower.includes('fail') || lower.includes('error') || lower.includes('denied') || lower.includes('revoke')) return 'destructive';
  if (lower.includes('login') || lower.includes('success') || lower.includes('auth')) return 'success';
  if (lower.includes('create') || lower.includes('register')) return 'accent';
  return 'secondary';
}

function formatActionLabel(action: string): string {
  return action
    .replace(/_/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export const AdminLogs: React.FC = () => {
  usePageTitle('Audit logs');

  const { data, loading } = useAdminStore((state) => state.logs);
  const fetchLogs = useAdminStore((state) => state.fetchLogs);
  
  const logs: LogEntry[] = useMemo(() => {
    if (Array.isArray(data)) return data;
    if (data && typeof data === 'object') {
      const d = data as unknown as { logs?: LogEntry[]; sessions?: LogEntry[]; audits?: LogEntry[] };
      if (Array.isArray(d.logs)) return d.logs;
      if (Array.isArray(d.sessions) || Array.isArray(d.audits)) {
        return [...(d.sessions || []), ...(d.audits || [])];
      }
    }
    return [];
  }, [data]);
  
  const [filtered, setFiltered] = useState(logs);
  const [page, setPage] = useState(0);
  const [actionFilter, setActionFilter] = useState('all');
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    void fetchLogs();
    intervalRef.current = setInterval(() => { void fetchLogs(true); }, 30_000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchLogs]);

  useEffect(() => {
    const f = actionFilter === 'all' ? logs : logs.filter((l) => l.action === actionFilter);
    setFiltered(f);
    setPage(0);
  }, [logs, actionFilter]);

  const actionTypes = useMemo(
    () => ['all', ...Array.from(new Set(logs.map((l) => l.action)))],
    [logs]
  );
  const pageCount = useMemo(() => Math.ceil(filtered.length / PAGE_SIZE) || 1, [filtered.length]);
  const pageRows = useMemo(
    () => filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [filtered, page]
  );
  const startEntry = filtered.length === 0 ? 0 : page * PAGE_SIZE + 1;
  const endEntry = Math.min((page + 1) * PAGE_SIZE, filtered.length);

  return (
    <AdminLayout>
      <div className="flex flex-col flex-1">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 sm:mb-8">
          <div>
            <h1 className="font-heading text-2xl sm:text-[34px] font-semibold text-foreground tracking-tight leading-tight">
              Audit logs
            </h1>
            <p className="mt-1 font-sans text-sm text-muted-foreground">
              Review sign-in attempts, authorization events, and administrative security actions.
            </p>
          </div>
          
          <div className="flex items-center gap-2.5 self-start sm:self-auto">
            <div className="relative">
              <select
                aria-label="Filter events by action"
                className="appearance-none rounded-md border border-border bg-card px-3 py-1.5 pr-8 font-sans text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary cursor-pointer h-9"
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
              >
                {actionTypes.map((a) => (
                  <option key={a} value={a} className="bg-background text-foreground">
                    {a === 'all' ? 'All actions' : formatActionLabel(a)}
                  </option>
                ))}
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2.5 text-muted-foreground">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </div>
            </div>
            
            <Button 
              variant="outline" 
              size="icon" 
              onClick={() => void fetchLogs(true)} 
              disabled={loading} 
              className="h-9 w-9 rounded-md shrink-0"
              aria-label="Refresh logs"
            >
              <svg className={`size-3.5 ${loading ? 'animate-spin' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" />
                <path d="M21 3v5h-5" />
              </svg>
            </Button>
          </div>
        </div>

        {loading && logs.length === 0 ? (
          <div className="p-16 text-center flex flex-col items-center justify-center text-muted-foreground">
            <div className="size-7 animate-spin rounded-full border-2 border-primary border-t-transparent mb-3" />
            <span className="font-sans text-xs text-muted-foreground">Loading audit logs...</span>
          </div>
        ) : filtered.length === 0 ? (
          <Card className="w-full">
            <CardContent className="p-12 text-center flex flex-col items-center justify-center">
              <p className="font-sans text-sm text-muted-foreground">No audit logs found matching filter criteria.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="border border-border rounded-[12px] overflow-hidden bg-card flex flex-col flex-1">
            <Table>
              <TableHeader className="bg-secondary/40 border-b border-border">
                <TableRow>
                  <TableHead className="w-[210px] text-xs font-medium uppercase tracking-wider text-muted-foreground">Timestamp</TableHead>
                  <TableHead className="text-xs font-medium uppercase tracking-wider text-muted-foreground">User / Subject</TableHead>
                  <TableHead className="w-[200px] text-xs font-medium uppercase tracking-wider text-muted-foreground">Action</TableHead>
                  <TableHead className="w-[160px] text-right text-xs font-medium uppercase tracking-wider text-muted-foreground">IP Address</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pageRows.map((log, index) => {
                  return (
                    <TableRow 
                      key={index} 
                      className="hover:bg-secondary/30 transition-colors border-b border-border/70"
                    >
                      <TableCell className="font-mono text-xs text-muted-foreground py-3">
                        {formatDate(log.createdAt)}
                      </TableCell>
                      <TableCell className="py-3">
                        {log.userEmail ? (
                          <div className="flex items-center gap-2.5">
                            <div className="size-6 rounded-full bg-secondary border border-border flex items-center justify-center font-mono text-[10px] font-semibold text-foreground uppercase shrink-0">
                              {log.userEmail.charAt(0)}
                            </div>
                            <span className="font-sans text-sm font-medium text-foreground">{log.userEmail}</span>
                          </div>
                        ) : (
                          <code className="font-mono text-xs bg-secondary px-2 py-0.5 rounded border border-border text-muted-foreground">
                            {log.userId?.slice(0, 16)}...
                          </code>
                        )}
                      </TableCell>
                      <TableCell className="py-3">
                        <Badge variant={getActionVariant(log.action)}>
                          {formatActionLabel(log.action)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right py-3">
                        <code className="font-mono text-xs text-muted-foreground">
                          {log.ipAddress ?? '—'}
                        </code>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>

            <div className="flex items-center justify-between border-t border-border bg-secondary/20 px-5 py-3 mt-auto">
              <span className="font-sans text-xs text-muted-foreground">
                Showing <span className="text-foreground font-medium">{startEntry}</span> to <span className="text-foreground font-medium">{endEntry}</span> of <span className="text-foreground font-medium">{filtered.length}</span> events
              </span>
              <div className="flex gap-2">
                <Button 
                  size="sm" 
                  variant="outline" 
                  className="h-8 px-2.5 text-xs rounded-md"
                  disabled={page === 0} 
                  onClick={() => setPage((p) => p - 1)}
                >
                  Previous
                </Button>
                <Button 
                  size="sm" 
                  variant="outline" 
                  className="h-8 px-2.5 text-xs rounded-md"
                  disabled={page >= pageCount - 1} 
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AdminLayout>
  );
};
