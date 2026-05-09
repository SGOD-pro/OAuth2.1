import React, { useEffect, useRef, useState } from 'react';
import { AdminLayout } from './AdminLayout';

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

  const fetchLogs = async () => {
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
  };

  useEffect(() => {
    void fetchLogs();
    intervalRef.current = setInterval(() => { void fetchLogs(); }, 30_000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []);

  useEffect(() => {
    const f = actionFilter === 'all' ? logs : logs.filter((l) => l.action === actionFilter);
    setFiltered(f);
    setPage(0);
  }, [logs, actionFilter]);

  const actionTypes = ['all', ...Array.from(new Set(logs.map((l) => l.action)))];
  const pageCount = Math.ceil(filtered.length / PAGE_SIZE);
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const startEntry = filtered.length === 0 ? 0 : page * PAGE_SIZE + 1;
  const endEntry = Math.min((page + 1) * PAGE_SIZE, filtered.length);

  return (
    <AdminLayout>
      <div className="admin-page-header">
        <h1 className="admin-page-title">Logs</h1>
        <select className="admin-input" style={{ width: 'auto', minWidth: 160 }}
          value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
          {actionTypes.map((a) => (
            <option key={a} value={a}>{a === 'all' ? 'All Actions' : a}</option>
          ))}
        </select>
      </div>

      {error && (
        <div className="auth-error" style={{ marginBottom: '1rem' }}>
          Failed to load logs.
          <button className="btn-secondary" style={{ marginLeft: 'auto', padding: '0.25rem 0.75rem', fontSize: '0.85rem' }}
            onClick={() => { setLoading(true); void fetchLogs(); }}>Retry</button>
        </div>
      )}

      <div className="glass-surface" style={{ overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: '2rem' }}>
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="stat-skeleton" style={{ height: 40, marginBottom: '0.5rem' }} />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state"><p style={{ opacity: 0.6 }}>No logs available yet.</p></div>
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Time</th><th>User</th><th>Action</th><th>IP Address</th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map((log, i) => (
                    <tr key={i}>
                      <td style={{ whiteSpace: 'nowrap', fontSize: '0.85rem' }}>{formatDate(log.createdAt)}</td>
                      <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {log.userEmail ?? <code style={{ fontSize: '0.8rem', opacity: 0.7 }}>{log.userId?.slice(0, 16)}...</code>}
                      </td>
                      <td><span className="badge badge-blue">{log.action}</span></td>
                      <td><code style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{log.ipAddress ?? '—'}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="pagination">
              <span style={{ opacity: 0.6, fontSize: '0.875rem' }}>
                Showing {startEntry}–{endEntry} of {filtered.length} entries
              </span>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn-secondary" style={{ padding: '0.4rem 0.875rem' }}
                  disabled={page === 0} onClick={() => setPage((p) => p - 1)}>← Previous</button>
                <button className="btn-secondary" style={{ padding: '0.4rem 0.875rem' }}
                  disabled={page >= pageCount - 1} onClick={() => setPage((p) => p + 1)}>Next →</button>
              </div>
            </div>
          </>
        )}
      </div>
    </AdminLayout>
  );
};
