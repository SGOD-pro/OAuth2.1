import React, { useEffect, useRef, useState, useMemo } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useAdminStore, type LogEntry } from '@/lib/adminStore';
import { usePageTitle } from '@/hooks/usePageTitle';
import { RotateCcw } from 'lucide-react';

const PAGE_SIZE = 20;

function formatDate(iso: string | null | undefined): { local: string; utc: string } {
  if (!iso) return { local: 'Unknown', utc: '' };
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return { local: 'Unknown', utc: '' };
    const local = d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
      timeZoneName: 'short',
    });
    return { local, utc: d.toUTCString() };
  } catch {
    return { local: 'Unknown', utc: '' };
  }
}

function getActionVariant(action: string): 'destructive' | 'secondary' {
  const lower = action.toLowerCase();
  if (lower.includes('fail') || lower.includes('error') || lower.includes('denied') || lower.includes('revoke')) {
    return 'destructive';
  }
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

    const startInterval = () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      intervalRef.current = setInterval(() => {
        if (document.visibilityState !== 'hidden') {
          void fetchLogs(true);
        }
      }, 30_000);
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void fetchLogs(true);
        startInterval();
      } else if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };

    startInterval();
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
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
        
        <div className="flex items-center gap-2.5 self-start sm:self-auto flex-wrap">
          <span className="hidden md:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-pill text-[11px] font-sans text-muted-foreground bg-secondary/40 border border-border">
            <RotateCcw className="size-3 text-muted-foreground" />
            30s auto refresh
          </span>
          <Select value={actionFilter} onValueChange={(val) => setActionFilter(val)}>
            <SelectTrigger className="w-[180px] h-9 text-xs">
              <SelectValue placeholder="All actions" />
            </SelectTrigger>
            <SelectContent>
              {actionTypes.map((a) => (
                <SelectItem key={a} value={a} className="text-xs">
                  {a === 'all' ? 'All actions' : formatActionLabel(a)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          
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
            <p className="font-sans text-sm text-muted-foreground">No events match this filter.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="border border-border rounded-[12px] overflow-hidden bg-card flex flex-col flex-1">
          <Table>
            <TableHeader className="bg-secondary/40 border-b border-border">
              <TableRow>
                <TableHead className="w-[230px] text-xs font-medium text-muted-foreground">Timestamp</TableHead>
                <TableHead className="text-xs font-medium text-muted-foreground">Subject</TableHead>
                <TableHead className="w-[200px] text-xs font-medium text-muted-foreground">Action</TableHead>
                <TableHead className="w-[160px] text-right text-xs font-medium text-muted-foreground">IP address</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pageRows.map((log, index) => {
                const { local, utc } = formatDate(log.createdAt);
                const isSystemAccount = !log.userEmail || log.userEmail.toLowerCase().includes('system') || log.userEmail.toLowerCase().includes('engine');
                return (
                  <TableRow 
                    key={index} 
                    className="hover:bg-secondary/30 transition-colors border-b border-border/70"
                  >
                    <TableCell className="font-mono text-xs text-muted-foreground py-3" title={utc}>
                      {local}
                    </TableCell>
                    <TableCell className="py-3">
                      {log.userEmail ? (
                        <div className="flex items-center gap-2.5">
                          {isSystemAccount ? (
                            <div className="size-6 rounded-full bg-secondary border border-border flex items-center justify-center text-muted-foreground shrink-0">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <circle cx="12" cy="12" r="3" />
                                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                              </svg>
                            </div>
                          ) : (
                            <div className="size-6 rounded-full bg-secondary border border-border flex items-center justify-center font-mono text-[10px] font-semibold text-foreground uppercase shrink-0">
                              {log.userEmail.charAt(0)}
                            </div>
                          )}
                          <span className="font-sans text-sm font-medium text-foreground">{log.userEmail}</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2.5">
                          <div className="size-6 rounded-full bg-secondary border border-border flex items-center justify-center text-muted-foreground shrink-0">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <circle cx="12" cy="12" r="3" />
                              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                            </svg>
                          </div>
                          <code className="font-mono text-xs bg-secondary px-2 py-0.5 rounded border border-border text-muted-foreground">
                            {log.userId?.slice(0, 16)}...
                          </code>
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="py-3">
                      <Badge variant={getActionVariant(log.action)}>
                        {formatActionLabel(log.action)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right py-3">
                      <code className="font-mono text-xs text-muted-foreground">
                        {log.ipAddress && log.ipAddress.toLowerCase() !== 'unknown' ? log.ipAddress : 'Unknown'}
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
  );
};
