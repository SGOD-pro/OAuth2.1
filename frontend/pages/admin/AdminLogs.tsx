import React, { useEffect, useRef, useState, useMemo } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
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
import { RotateCcw, Search, X } from 'lucide-react';

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

function getEventOutcome(log: LogEntry): { label: string; variant: 'success' | 'destructive' | 'outline' } {
  if (log.outcome) {
    const lower = log.outcome.toLowerCase();
    if (lower.includes('fail') || lower.includes('denied') || lower.includes('error')) {
      return { label: 'Failed', variant: 'destructive' };
    }
    return { label: 'Success', variant: 'success' };
  }
  const actionLower = log.action.toLowerCase();
  if (actionLower.includes('fail') || actionLower.includes('denied') || actionLower.includes('error')) {
    return { label: 'Failed', variant: 'destructive' };
  }
  if (actionLower.includes('sign_in') || actionLower.includes('session') || actionLower.includes('client') || actionLower.includes('admin')) {
    return { label: 'Success', variant: 'success' };
  }
  return { label: 'Unknown', variant: 'outline' };
}

function getEventContext(log: LogEntry, isSystem: boolean): string {
  if (log.appName) return log.appName;
  if (log.applicationName) return log.applicationName;
  if (log.clientId) return log.clientId;
  if (log.action.includes('admin') || isSystem) {
    return 'Console';
  }
  return 'Unknown';
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
  
  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  const [actionFilter, setActionFilter] = useState('all');
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchTerm), 200);
    return () => clearTimeout(t);
  }, [searchTerm]);

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

  const filtered = useMemo(() => {
    return logs.filter((log) => {
      if (actionFilter !== 'all' && log.action !== actionFilter) {
        return false;
      }
      if (debouncedSearch.trim()) {
        const query = debouncedSearch.trim().toLowerCase();
        const emailMatch = log.userEmail?.toLowerCase().includes(query);
        const userMatch = log.userId?.toLowerCase().includes(query);
        const actionMatch = log.action?.toLowerCase().includes(query);
        const ipMatch = log.ipAddress?.toLowerCase().includes(query);
        if (!emailMatch && !userMatch && !actionMatch && !ipMatch) {
          return false;
        }
      }
      return true;
    });
  }, [logs, actionFilter, debouncedSearch]);

  useEffect(() => {
    setPage(0);
  }, [actionFilter, debouncedSearch, pageSize]);

  const actionTypes = useMemo(
    () => ['all', ...Array.from(new Set(logs.map((l) => l.action)))],
    [logs]
  );
  const pageCount = useMemo(() => Math.ceil(filtered.length / pageSize) || 1, [filtered.length, pageSize]);
  const pageRows = useMemo(
    () => filtered.slice(page * pageSize, (page + 1) * pageSize),
    [filtered, page, pageSize]
  );
  const startEntry = filtered.length === 0 ? 0 : page * pageSize + 1;
  const endEntry = Math.min((page + 1) * pageSize, filtered.length);

  return (
    <div className="flex flex-col flex-1">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 sm:mb-8">
        <div>
          <h1 className="font-heading text-2xl sm:text-[34px] font-semibold text-foreground tracking-tight leading-tight">
            Audit logs
          </h1>
          <p className="mt-1 font-sans text-sm text-muted-foreground">
            Review sign in attempts, authorization events, and administrative security actions.
          </p>
        </div>
        
        <div className="flex items-center gap-2.5 self-start sm:self-auto flex-wrap">
          <span className="hidden md:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-pill text-[11px] font-sans text-muted-foreground bg-secondary/40 border border-border">
            <RotateCcw className="size-3 text-muted-foreground" />
            30s auto refresh
          </span>

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

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 rounded-xl bg-card border border-border shadow-2xs mb-4">
        <div className="flex flex-1 flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-4 text-muted-foreground pointer-events-none" />
            <Input
              type="text"
              placeholder="Search by user, action, IP..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8.5 pr-8 h-9 text-xs"
              aria-label="Search audit logs"
            />
            {searchTerm && (
              <button
                type="button"
                onClick={() => setSearchTerm('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-0.5 rounded cursor-pointer"
                aria-label="Clear search"
              >
                <X className="size-3.5" />
              </button>
            )}
          </div>

          <Select value={actionFilter} onValueChange={(val) => setActionFilter(val)}>
            <SelectTrigger className="w-full sm:w-[180px] h-9 text-xs">
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

          <Select value={String(pageSize)} onValueChange={(val) => setPageSize(Number(val))}>
            <SelectTrigger className="w-full sm:w-[110px] h-9 text-xs">
              <SelectValue placeholder="Page size" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="10" className="text-xs">10 rows</SelectItem>
              <SelectItem value="20" className="text-xs">20 rows</SelectItem>
              <SelectItem value="50" className="text-xs">50 rows</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <span className="font-mono text-xs text-muted-foreground text-right shrink-0">
          {filtered.length} event{filtered.length === 1 ? '' : 's'}
        </span>
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
        <div className="space-y-4">
          {/* Mobile Events List (< md) */}
          <div className="md:hidden space-y-3">
            {pageRows.map((log, index) => {
              const { local, utc } = formatDate(log.createdAt);
              const isSystemAccount = !log.userEmail || log.userEmail.toLowerCase().includes('system') || log.userEmail.toLowerCase().includes('engine');
              const outcome = getEventOutcome(log);
              const context = getEventContext(log, isSystemAccount);

              return (
                <Card key={index} className="border border-border bg-card">
                  <CardContent className="p-4 space-y-2.5">
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className="font-mono text-muted-foreground" title={utc}>
                        {local}
                      </span>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <Badge variant={outcome.variant === 'success' ? 'success' : outcome.variant === 'destructive' ? 'destructive' : 'outline'} className="text-[10px]">
                          {outcome.label}
                        </Badge>
                        <Badge variant={getActionVariant(log.action)} className="text-[10px]">
                          {formatActionLabel(log.action)}
                        </Badge>
                      </div>
                    </div>

                    <div className="flex items-center justify-between gap-2 pt-1 text-xs">
                      <div className="flex items-center gap-2 min-w-0">
                        <div className="size-6 rounded-full bg-secondary border border-border flex items-center justify-center font-mono text-[10px] font-semibold text-foreground uppercase shrink-0">
                          {isSystemAccount ? 'S' : (log.userEmail ? log.userEmail.charAt(0) : 'U')}
                        </div>
                        <span className="font-medium text-foreground truncate">
                          {log.userEmail || log.userId || 'Unknown'}
                        </span>
                      </div>
                      <span className="text-muted-foreground shrink-0">{context}</span>
                    </div>

                    <div className="flex items-center justify-between pt-1 border-t border-border text-[11px] font-mono text-muted-foreground">
                      <span>IP Address:</span>
                      <span>{log.ipAddress && log.ipAddress.toLowerCase() !== 'unknown' ? log.ipAddress : 'Unknown'}</span>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* Desktop Table (>= md) */}
          <div className="hidden md:block border border-border rounded-xl overflow-hidden bg-card">
            <Table>
              <TableHeader className="bg-secondary/40 border-b border-border">
                <TableRow>
                  <TableHead className="w-[210px] text-xs font-medium text-muted-foreground">Timestamp</TableHead>
                  <TableHead className="text-xs font-medium text-muted-foreground">Subject</TableHead>
                  <TableHead className="w-[180px] text-xs font-medium text-muted-foreground">Event</TableHead>
                  <TableHead className="w-[110px] text-xs font-medium text-muted-foreground">Outcome</TableHead>
                  <TableHead className="w-[120px] text-xs font-medium text-muted-foreground">Context</TableHead>
                  <TableHead className="w-[140px] text-right text-xs font-medium text-muted-foreground">IP address</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pageRows.map((log, index) => {
                  const { local, utc } = formatDate(log.createdAt);
                  const isSystemAccount = !log.userEmail || log.userEmail.toLowerCase().includes('system') || log.userEmail.toLowerCase().includes('engine');
                  const outcome = getEventOutcome(log);
                  const context = getEventContext(log, isSystemAccount);

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
                          <div className="flex items-center gap-2.5 min-w-0">
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
                            <span className="font-sans text-sm font-medium text-foreground truncate">{log.userEmail}</span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2.5">
                            <div className="size-6 rounded-full bg-secondary border border-border flex items-center justify-center text-muted-foreground shrink-0">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <circle cx="12" cy="12" r="3" />
                                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                              </svg>
                            </div>
                            <code className="font-mono text-xs bg-secondary px-2 py-0.5 rounded border border-border text-muted-foreground truncate">
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
                      <TableCell className="py-3">
                        <Badge 
                          variant={outcome.variant === 'success' ? 'success' : outcome.variant === 'destructive' ? 'destructive' : 'outline'}
                          className="text-[11px]"
                        >
                          {outcome.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="py-3 font-sans text-xs text-muted-foreground">
                        {context}
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
          </div>

          {/* Pagination */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 border border-border rounded-xl bg-card px-5 py-3">
            <span className="font-sans text-xs text-muted-foreground">
              Showing <span className="text-foreground font-medium">{startEntry}</span> to <span className="text-foreground font-medium">{endEntry}</span> of <span className="text-foreground font-medium">{filtered.length}</span> events
            </span>
            <div className="flex gap-2">
              <Button 
                size="sm" 
                variant="outline" 
                className="h-8 px-3 text-xs rounded-md"
                disabled={page === 0} 
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </Button>
              <Button 
                size="sm" 
                variant="outline" 
                className="h-8 px-3 text-xs rounded-md"
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
