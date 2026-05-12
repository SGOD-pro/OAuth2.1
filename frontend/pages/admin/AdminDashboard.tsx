import React, { useEffect, useState, useCallback } from 'react';
import { AdminLayout } from './AdminLayout';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';

interface Stats {
  totalClients: number;
  activeClients: number;
  totalUsers: number;
  recentLogins: number;
}

const StatCard = React.memo(
  ({ label, value, loading }: { label: string; value: number | null; loading: boolean }) => (
    <GlassSurface
      width="100%"
      height="auto"
      borderRadius={20}
      backgroundOpacity={0.1}
      blur={10}
      saturation={1.6}
      className="w-full"
    >
      <div className="px-5 py-4 text-left">
        {loading ? (
          <div className="h-6 w-16 rounded-full bg-white/10" />
        ) : (
          <div className="text-2xl font-semibold text-foreground">{value ?? '—'}</div>
        )}
        <div className="mt-2 text-xs uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
      </div>
    </GlassSurface>
  )
);

/**
 * /admin — Overview dashboard with service-level stats.
 */
export const AdminDashboard: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchStats = useCallback(async () => {
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
  }, []);

  useEffect(() => { void fetchStats(); }, [fetchStats]);

  return (
    <AdminLayout>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Admin</p>
          <h1 className="mt-2 text-2xl font-semibold text-foreground">Overview</h1>
        </div>
      </div>

      {error ? (
        <div className="mt-6 flex items-center gap-4 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          <span>{error}</span>
          <Button size="sm" variant="outline" className="ml-auto" onClick={() => void fetchStats()}>
            Retry
          </Button>
        </div>
      ) : null}

      <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total Applications" value={stats?.totalClients ?? null} loading={loading} />
        <StatCard label="Active Applications" value={stats?.activeClients ?? null} loading={loading} />
        <StatCard label="Total Users" value={stats?.totalUsers ?? null} loading={loading} />
        <StatCard label="Logins (last 24h)" value={stats?.recentLogins ?? null} loading={loading} />
      </div>
    </AdminLayout>
  );
};
