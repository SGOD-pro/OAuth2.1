import React, { useEffect, useRef, useState, useMemo } from 'react';
import { AdminLayout } from './AdminLayout';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { useAdminStore } from '@/lib/adminStore';

const PAGE_SIZE = 20;

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  });
}

function getActionColor(action: string) {
  if (action.includes('fail') || action.includes('error')) return 'destructive';
  if (action.includes('login') || action.includes('success')) return 'default';
  if (action.includes('create') || action.includes('register')) return 'secondary';
  return 'outline';
}

export const AdminLogs: React.FC = () => {
  const { data, loading } = useAdminStore((state) => state.logs);
  const fetchLogs = useAdminStore((state) => state.fetchLogs);
  
  const logs = data || [];
  
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
  const pageCount = useMemo(() => Math.ceil(filtered.length / PAGE_SIZE), [filtered.length]);
  const pageRows = useMemo(
    () => filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [filtered, page]
  );
  const startEntry = filtered.length === 0 ? 0 : page * PAGE_SIZE + 1;
  const endEntry = Math.min((page + 1) * PAGE_SIZE, filtered.length);

  return (
    <AdminLayout>
      <div className="flex flex-wrap items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-foreground font-heading">Audit Logs</h1>
          <p className="mt-2 text-sm text-muted-foreground">Review system activity and security events.</p>
        </div>
        
        <div className="flex items-center gap-3">
          <div className="relative">
            <select
              className="appearance-none rounded-full border border-border/50 bg-card/50 backdrop-blur-sm px-4 py-2 pr-8 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all shadow-sm cursor-pointer"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
            >
              {actionTypes.map((a) => (
                <option key={a} value={a} className="bg-background">{a === 'all' ? 'All Actions' : a}</option>
              ))}
            </select>
            <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-muted-foreground">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9" /></svg>
            </div>
          </div>
          
          <Button variant="outline" size="icon" onClick={() => void fetchLogs(true)} disabled={loading} className="rounded-full h-9 w-9">
            <svg className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" /><path d="M21 3v5h-5" /></svg>
          </Button>
        </div>
      </div>

      <Card className="bg-card/50 backdrop-blur-md border-border/50 shadow-sm overflow-hidden flex flex-col h-[calc(100vh-12rem)]">
        {loading && logs.length === 0 ? (
          <div className="p-6 flex-1 flex flex-col items-center justify-center text-muted-foreground">
             <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary/30 border-t-primary mb-4" />
             Loading logs...
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-6 flex-1 flex flex-col items-center justify-center">
            <div className="h-12 w-12 rounded-full bg-muted flex items-center justify-center text-muted-foreground mb-4">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" /></svg>
            </div>
            <p className="text-sm text-muted-foreground">No logs found matching your criteria.</p>
          </div>
        ) : (
          <>
            <div className="flex-1 overflow-auto w-full">
              <Table>
                <TableHeader className="bg-muted/50 sticky top-0 z-10 shadow-sm">
                  <TableRow className="border-border/50 hover:bg-transparent">
                    <TableHead className="w-[180px]">Timestamp</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead className="w-[200px]">Action</TableHead>
                    <TableHead className="w-[150px] text-right">IP Address</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pageRows.map((log, i) => (
                    <TableRow key={i} className="border-border/50 hover:bg-muted/30">
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground font-mono">
                        {formatDate(log.createdAt)}
                      </TableCell>
                      <TableCell className="max-w-xs truncate">
                        {log.userEmail ? (
                          <div className="flex items-center gap-2">
                             <div className="h-6 w-6 rounded-full bg-primary/10 text-primary flex items-center justify-center text-[10px] font-bold uppercase">
                               {log.userEmail.charAt(0)}
                             </div>
                             <span className="font-medium text-sm">{log.userEmail}</span>
                          </div>
                        ) : (
                          <code className="text-xs bg-muted px-2 py-1 rounded text-muted-foreground">
                            {log.userId?.slice(0, 16)}...
                          </code>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={getActionColor(log.action) as any} className="font-mono text-[10px] uppercase tracking-wider">
                          {log.action}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <code className="text-xs text-muted-foreground font-mono">
                          {log.ipAddress ?? '—'}
                        </code>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="flex items-center justify-between border-t border-border/50 bg-card/80 px-6 py-4 mt-auto">
              <span className="text-xs text-muted-foreground">
                Showing <span className="font-medium text-foreground">{startEntry}</span> to <span className="font-medium text-foreground">{endEntry}</span> of <span className="font-medium text-foreground">{filtered.length}</span> entries
              </span>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage((p) => p - 1)} className="h-8">
                  Previous
                </Button>
                <Button size="sm" variant="outline" disabled={page >= pageCount - 1} onClick={() => setPage((p) => p + 1)} className="h-8">
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>
    </AdminLayout>
  );
};
