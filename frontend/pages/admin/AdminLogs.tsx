import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import { AdminLayout } from './AdminLayout';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';

interface LogEntry {
  userId: string;
  userEmail: string | null;
  action: string;
  ipAddress: string | null;
  createdAt: string;
}

const PAGE_SIZE = 20;

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  });
}

export const AdminLogs: React.FC = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [filtered, setFiltered] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(0);
  const [actionFilter, setActionFilter] = useState('all');
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchLogs = useCallback(async () => {
    try {
      const res = await fetch('/api/admin/logs', { credentials: 'include' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: LogEntry[] = await res.json();
      setLogs(data);
      setError('');
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchLogs();
    intervalRef.current = setInterval(() => { void fetchLogs(); }, 30_000);
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
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Admin</p>
          <h1 className="mt-2 text-2xl font-semibold text-foreground">Logs</h1>
        </div>
        <select
          className="rounded-2xl border border-white/10 bg-white/10 px-3 py-2 text-sm text-foreground"
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
        >
          {actionTypes.map((a) => (
            <option key={a} value={a}>{a === 'all' ? 'All Actions' : a}</option>
          ))}
        </select>
      </div>

      {error && (
        <div className="mt-6 flex items-center gap-4 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          Failed to load logs.
          <Button
            size="sm"
            variant="outline"
            className="ml-auto"
            onClick={() => { setLoading(true); void fetchLogs(); }}
          >
            Retry
          </Button>
        </div>
      )}

      <GlassSurface
        width="100%"
        height="auto"
        borderRadius={20}
        backgroundOpacity={0.1}
        blur={10}
        saturation={1.6}
        className="mt-6 w-full block!"
      >
        {loading ? (
          <div className="px-6 py-8">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="mb-3 h-10 rounded-2xl bg-white/10" />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="px-6 py-10 text-center text-sm text-muted-foreground">
            No logs available yet.
          </div>
        ) : (
          <div className="w-full h-full">
            <div className="overflow-x-auto w-full">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                  <tr>
                    <th className="px-6 py-4">Time</th>
                    <th className="px-6 py-4">User</th>
                    <th className="px-6 py-4">Action</th>
                    <th className="px-6 py-4">IP Address</th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map((log, i) => (
                    <tr key={i} className="border-t border-white/5">
                      <td className="px-6 py-4 whitespace-nowrap text-xs text-muted-foreground">
                        {formatDate(log.createdAt)}
                      </td>
                      <td className="px-6 py-4 max-w-55 truncate">
                        {log.userEmail ?? (
                          <code className="text-xs text-muted-foreground">
                            {log.userId?.slice(0, 16)}...
                          </code>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <span className="rounded-full bg-sky-500/15 px-2 py-1 text-xs text-sky-200">
                          {log.action}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <code className="text-xs text-muted-foreground">
                          {log.ipAddress ?? '—'}
                        </code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-4 border-t border-white/5 px-6 py-4 text-sm">
              <span className="text-muted-foreground">
                Showing {startEntry}–{endEntry} of {filtered.length} entries
              </span>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </Button>
                <Button size="sm" variant="outline" disabled={page >= pageCount - 1} onClick={() => setPage((p) => p + 1)}>
                  Next
                </Button>
              </div>
            </div>
          </div>       
        )}
      </GlassSurface>
    </AdminLayout>
  );
};
