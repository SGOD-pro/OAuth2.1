import React, { useEffect, useRef, useState, useMemo } from 'react';
import { AdminLayout } from './AdminLayout';
import { Card, CardContent } from '@/components/ui/card';
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

function getActionVariant(action: string) {
  if (action.includes('fail') || action.includes('error') || action.includes('denied')) return 'destructive';
  if (action.includes('login') || action.includes('success') || action.includes('auth')) return 'success';
  if (action.includes('create') || action.includes('register')) return 'accent';
  return 'secondary';
}

export const AdminLogs: React.FC = () => {
  const { data, loading } = useAdminStore((state) => state.logs);
  const fetchLogs = useAdminStore((state) => state.fetchLogs);
  
  const logs = useMemo(() => data || [], [data]);
  
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
      <div className="flex flex-col flex-1">
        <div className="flex flex-wrap items-end justify-between gap-4 mb-8">
          <div>
            <span className="font-mono text-xs uppercase tracking-[0.2em] text-accent mb-1 block">
              Audit Telemetry Stream
            </span>
            <h1 className="font-heading text-3xl sm:text-[42px] leading-[1.1] font-normal text-foreground">
              Security Audit Logs
            </h1>
            <p className="mt-2 font-sans text-sm text-muted-foreground">
              Immutable telemetry log stream of cryptographic events, sign-in attempts, and administrative actions.
            </p>
          </div>
          
          <div className="flex items-center gap-3">
            <div className="relative">
              <select
                className="appearance-none rounded-pill border border-border bg-card/60 backdrop-blur-md px-4 py-2 pr-8 font-mono text-xs uppercase tracking-wider text-foreground focus:outline-none focus:ring-1 focus:ring-accent cursor-pointer"
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
              >
                {actionTypes.map((a) => (
                  <option key={a} value={a} className="bg-background text-foreground">
                    {a === 'all' ? 'ALL ACTIONS' : a.toUpperCase()}
                  </option>
                ))}
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-muted-foreground">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </div>
            </div>
            
            <Button 
              variant="outline" 
              size="icon-sm" 
              onClick={() => void fetchLogs(true)} 
              disabled={loading} 
              className="h-9 w-9 rounded-full"
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
            <div className="size-8 animate-spin rounded-full border-2 border-accent border-t-transparent mb-4" />
            <span className="font-mono text-xs uppercase tracking-wider">Synchronizing Security Logs...</span>
          </div>
        ) : filtered.length === 0 ? (
          <Card className="w-full">
            <CardContent className="p-12 text-center flex flex-col items-center justify-center">
              <p className="font-sans text-sm text-muted-foreground">No telemetry logs found matching filter criteria.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="border border-border/50 rounded-[16px] overflow-hidden bg-card/40 backdrop-blur-xl flex flex-col flex-1">
            <Table>
              <TableHeader className="bg-secondary/30">
                <TableRow>
                  <TableHead className="w-[200px]">Timestamp (UTC)</TableHead>
                  <TableHead>Principal Identity</TableHead>
                  <TableHead className="w-[220px]">Event Action</TableHead>
                  <TableHead className="w-[160px] text-right">Origin IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pageRows.map((log, index) => {
                  const delayStyle = { animationDelay: `${(index % 10 + 1) * 50}ms` };
                  return (
                    <TableRow 
                      key={index} 
                      style={delayStyle}
                      className="animate-in fade-in slide-in-from-bottom-2 duration-500 hover:bg-secondary/40"
                    >
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {formatDate(log.createdAt)}
                      </TableCell>
                      <TableCell>
                        {log.userEmail ? (
                          <div className="flex items-center gap-2.5">
                            <div className="size-6 rounded-full bg-secondary border border-border flex items-center justify-center font-mono text-[10px] font-bold text-foreground uppercase">
                              {log.userEmail.charAt(0)}
                            </div>
                            <span className="font-sans text-sm font-medium text-foreground">{log.userEmail}</span>
                          </div>
                        ) : (
                          <code className="font-mono text-xs bg-secondary/80 px-2 py-0.5 rounded text-muted-foreground">
                            {log.userId?.slice(0, 16)}...
                          </code>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={getActionVariant(log.action)}>
                          {log.action}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <code className="font-mono text-xs text-muted-foreground">
                          {log.ipAddress ?? '—'}
                        </code>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>

            <div className="flex items-center justify-between border-t border-border/50 bg-secondary/20 px-6 py-3.5 mt-auto">
              <span className="font-mono text-xs text-muted-foreground">
                Displaying <span className="text-foreground font-medium">{startEntry}</span> – <span className="text-foreground font-medium">{endEntry}</span> of <span className="text-foreground font-medium">{filtered.length}</span> telemetry records
              </span>
              <div className="flex gap-2">
                <Button 
                  size="xs" 
                  variant="outline" 
                  disabled={page === 0} 
                  onClick={() => setPage((p) => p - 1)}
                >
                  Previous
                </Button>
                <Button 
                  size="xs" 
                  variant="outline" 
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
