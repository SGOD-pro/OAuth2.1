import React, { useEffect, useState, useCallback } from 'react';
import { AdminLayout } from './AdminLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';

interface Stats {
  totalClients: number;
  activeClients: number;
  totalUsers: number;
  recentLogins: number;
}

const StatCard = React.memo(
  ({ label, value, loading, icon }: { label: string; value: number | null; loading: boolean, icon: React.ReactNode }) => (
    <Card className="bg-card/50 backdrop-blur-md border-border/50 hover:bg-card/80 transition-colors shadow-sm">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">{label}</CardTitle>
        <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center text-primary">
          {icon}
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="h-8 w-16 rounded-full bg-muted animate-pulse mt-1" />
        ) : (
          <div className="text-3xl font-semibold text-foreground">{value ?? '—'}</div>
        )}
      </CardContent>
    </Card>
  )
);

export const AdminDashboard: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/admin/stats', { credentials: 'include' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: Stats = await res.json();
      setStats(data);
    } catch (err) {
      toast.error(`Failed to load stats: ${String(err)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void fetchStats(); }, [fetchStats]);

  return (
    <AdminLayout>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-foreground font-heading">Overview</h1>
          <p className="mt-2 text-sm text-muted-foreground">Monitor your identity platform activity and performance.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void fetchStats()} disabled={loading} className="rounded-full bg-card/50 backdrop-blur-sm">
          <svg className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" />
            <path d="M21 3v5h-5" />
          </svg>
          Refresh
        </Button>
      </div>

      <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
        <StatCard 
          label="Applications" 
          value={stats?.totalClients ?? null} 
          loading={loading} 
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" />
            </svg>
          }
        />
        <StatCard 
          label="Active Apps" 
          value={stats?.activeClients ?? null} 
          loading={loading}
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
            </svg>
          } 
        />
        <StatCard 
          label="Total Users" 
          value={stats?.totalUsers ?? null} 
          loading={loading} 
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
            </svg>
          }
        />
        <StatCard 
          label="Logins (24h)" 
          value={stats?.recentLogins ?? null} 
          loading={loading} 
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
          }
        />
      </div>
      
      <div className="mt-8 grid gap-6 md:grid-cols-2">
         {/* Add some placeholders for future charts or more detailed views */}
         <Card className="bg-card/50 backdrop-blur-md border-border/50 shadow-sm h-64 flex flex-col items-center justify-center text-muted-foreground border-dashed">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" className="mb-4 opacity-50"><path d="M21.21 15.89A10 10 0 1 1 8 2.83" /><path d="M22 12A10 10 0 0 0 12 2v10z" /></svg>
            <p className="text-sm">Activity Chart (Coming soon)</p>
         </Card>
         <Card className="bg-card/50 backdrop-blur-md border-border/50 shadow-sm h-64 flex flex-col items-center justify-center text-muted-foreground border-dashed">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" className="mb-4 opacity-50"><path d="M12 20v-6M6 20V10M18 20V4" /></svg>
            <p className="text-sm">User Growth (Coming soon)</p>
         </Card>
      </div>
    </AdminLayout>
  );
};
