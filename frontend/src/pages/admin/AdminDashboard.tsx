import React, { useEffect, useState } from 'react';
import { AdminLayout } from './AdminLayout';

interface Stats {
  totalClients: number;
  activeClients: number;
  totalUsers: number;
  recentLogins: number;
}

const StatCard: React.FC<{ label: string; value: number | null; loading: boolean }> = ({
  label,
  value,
  loading,
}) => (
  <div className="glass-surface stat-card">
    {loading ? (
      <div className="stat-skeleton" />
    ) : (
      <div className="stat-value">{value ?? '—'}</div>
    )}
    <div className="stat-label">{label}</div>
  </div>
);

/**
 * /admin — Overview dashboard with service-level stats.
 */
export const AdminDashboard: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchStats = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch('/api/admin/stats', { credentials: 'include' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: Stats = await res.json();
      setStats(data);
    } catch (err) {
      setError(`Failed to load stats: ${String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void fetchStats(); }, []);

  return (
    <AdminLayout>
      <div className="admin-page-header">
        <h1 className="admin-page-title">Overview</h1>
      </div>

      {error ? (
        <div className="auth-error" style={{ marginBottom: '1.5rem' }}>
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          {error}
          <button
            className="btn-secondary"
            style={{ marginLeft: 'auto', padding: '0.25rem 0.75rem', fontSize: '0.85rem' }}
            onClick={() => void fetchStats()}
          >
            Retry
          </button>
        </div>
      ) : null}

      <div className="stats-grid">
        <StatCard label="Total Applications" value={stats?.totalClients ?? null} loading={loading} />
        <StatCard label="Active Applications" value={stats?.activeClients ?? null} loading={loading} />
        <StatCard label="Total Users" value={stats?.totalUsers ?? null} loading={loading} />
        <StatCard label="Logins (last 24h)" value={stats?.recentLogins ?? null} loading={loading} />
      </div>
    </AdminLayout>
  );
};
