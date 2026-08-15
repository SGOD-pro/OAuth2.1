import React, { useEffect } from 'react';
import { AdminLayout } from './AdminLayout';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAdminStore } from '@/lib/adminStore';

const StatCard = React.memo(
  ({ 
    label, 
    value, 
    loading, 
    icon, 
    delayClass,
    telemetryTag
  }: { 
    label: string; 
    value: number | null; 
    loading: boolean; 
    icon: React.ReactNode;
    delayClass?: string;
    telemetryTag: string;
  }) => (
    <Card className={`animate-in fade-in slide-in-from-bottom-4 duration-700 ${delayClass ?? ''}`}>
      <CardContent className="p-6 sm:p-[21px]">
        <div className="flex items-center justify-between mb-4">
          <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
            {label}
          </span>
          <div className="size-8 rounded-full bg-secondary flex items-center justify-center text-foreground">
            {icon}
          </div>
        </div>

        {loading ? (
          <div className="h-10 w-24 rounded-md bg-secondary animate-pulse mt-1" />
        ) : (
          <div className="font-heading text-[34px] leading-tight font-normal text-foreground">
            {value ?? '—'}
          </div>
        )}

        <div className="mt-3 pt-3 border-t border-border/40 flex items-center justify-between">
          <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            Telemetry Feed
          </span>
          <span className="font-mono text-[10px] uppercase text-accent font-medium">
            {telemetryTag}
          </span>
        </div>
      </CardContent>
    </Card>
  )
);

export const AdminDashboard: React.FC = () => {
  const { data: stats, loading } = useAdminStore((state) => state.stats);
  const fetchStats = useAdminStore((state) => state.fetchStats);

  useEffect(() => {
    void fetchStats();
  }, [fetchStats]);

  return (
    <AdminLayout>
      <div className="flex flex-wrap items-end justify-between gap-4 mb-8">
        <div>
          <span className="font-mono text-xs uppercase tracking-[0.2em] text-accent mb-1 block">
            System Telemetry // Live
          </span>
          <h1 className="font-heading text-4xl sm:text-[55px] leading-[1] tracking-[-0.03em] font-normal text-foreground">
            Telemetry Overview
          </h1>
          <p className="mt-2 font-sans text-sm text-muted-foreground">
            Real-time cryptographic authorization metrics and identity session status.
          </p>
        </div>

        <Button 
          variant="outline" 
          size="sm" 
          onClick={() => void fetchStats(true)} 
          disabled={loading}
        >
          <svg className={`mr-2 size-3.5 ${loading ? 'animate-spin' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" />
            <path d="M21 3v5h-5" />
          </svg>
          Sync Telemetry
        </Button>
      </div>

      <div className="grid gap-[21px] grid-cols-1 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Registered Apps"
          value={stats?.totalClients ?? null}
          loading={loading && !stats}
          delayClass="[animation-delay:100ms]"
          telemetryTag="ACTIVE // 100%"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" />
            </svg>
          }
        />
        <StatCard
          label="Active Integrations"
          value={stats?.activeClients ?? null}
          loading={loading && !stats}
          delayClass="[animation-delay:200ms]"
          telemetryTag="ONLINE"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
            </svg>
          }
        />
        <StatCard
          label="Authenticated Pilots"
          value={stats?.totalUsers ?? null}
          loading={loading && !stats}
          delayClass="[animation-delay:300ms]"
          telemetryTag="VERIFIED"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
            </svg>
          }
        />
        <StatCard
          label="Authorizations (24h)"
          value={stats?.recentLogins ?? null}
          loading={loading && !stats}
          delayClass="[animation-delay:400ms]"
          telemetryTag="FLOW // OK"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
          }
        />
      </div>

      <div className="mt-[34px] grid gap-[21px] grid-cols-1 md:grid-cols-2">
        <Card className="animate-in fade-in slide-in-from-bottom-4 duration-700 [animation-delay:500ms]">
          <CardContent className="p-8 sm:p-[34px] flex flex-col items-center justify-center text-center min-h-[220px]">
            <div className="size-12 rounded-full border border-border bg-secondary flex items-center justify-center text-muted-foreground mb-4">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M21.21 15.89A10 10 0 1 1 8 2.83" />
                <path d="M22 12A10 10 0 0 0 12 2v10z" />
              </svg>
            </div>
            <h3 className="font-heading text-lg font-normal text-foreground">Traffic Telemetry Stream</h3>
            <p className="font-mono text-xs uppercase tracking-wider text-muted-foreground mt-1">
              Real-time authorization velocity chart initializing...
            </p>
          </CardContent>
        </Card>

        <Card className="animate-in fade-in slide-in-from-bottom-4 duration-700 [animation-delay:600ms]">
          <CardContent className="p-8 sm:p-[34px] flex flex-col items-center justify-center text-center min-h-[220px]">
            <div className="size-12 rounded-full border border-border bg-secondary flex items-center justify-center text-muted-foreground mb-4">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 20v-6M6 20V10M18 20V4" />
              </svg>
            </div>
            <h3 className="font-heading text-lg font-normal text-foreground">Cryptographic Key Rotations</h3>
            <p className="font-mono text-xs uppercase tracking-wider text-muted-foreground mt-1">
              JWKS RS256 rotation schedule healthy.
            </p>
          </CardContent>
        </Card>
      </div>
    </AdminLayout>
  );
};
