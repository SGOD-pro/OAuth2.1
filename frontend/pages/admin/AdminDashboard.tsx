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
          <CardContent className="p-6 sm:p-7 flex flex-col justify-between min-h-[220px]">
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <div className="size-8 rounded-full border border-border bg-secondary flex items-center justify-center text-accent">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="font-heading text-base font-medium text-foreground">Traffic Telemetry Stream</h3>
                    <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">Authorization Flow Velocity</p>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  ONLINE
                </span>
              </div>

              <div className="grid grid-cols-3 gap-3 my-4 p-3.5 rounded-lg bg-secondary/30 border border-border/40">
                <div>
                  <span className="font-mono text-[10px] uppercase text-muted-foreground block">PKCE Method</span>
                  <span className="font-mono text-xs font-semibold text-foreground mt-0.5 block">S256 (SHA-256)</span>
                </div>
                <div>
                  <span className="font-mono text-[10px] uppercase text-muted-foreground block">Handshake</span>
                  <span className="font-mono text-xs font-semibold text-foreground mt-0.5 block">OAuth 2.1 Code</span>
                </div>
                <div>
                  <span className="font-mono text-[10px] uppercase text-muted-foreground block">Family Replay</span>
                  <span className="font-mono text-xs font-semibold text-emerald-400 mt-0.5 block">Protected</span>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-border/40 text-muted-foreground font-mono text-[11px]">
              <span>Active Handshake Protocol</span>
              <span className="text-foreground font-medium">RFC 6749 / RFC 7636</span>
            </div>
          </CardContent>
        </Card>

        <Card className="animate-in fade-in slide-in-from-bottom-4 duration-700 [animation-delay:600ms]">
          <CardContent className="p-6 sm:p-7 flex flex-col justify-between min-h-[220px]">
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <div className="size-8 rounded-full border border-border bg-secondary flex items-center justify-center text-accent">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="font-heading text-base font-medium text-foreground">Cryptographic Engine</h3>
                    <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">JWKS & Token Integrity</p>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  <span className="size-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  HEALTHY
                </span>
              </div>

              <div className="grid grid-cols-3 gap-3 my-4 p-3.5 rounded-lg bg-secondary/30 border border-border/40">
                <div>
                  <span className="font-mono text-[10px] uppercase text-muted-foreground block">Signature</span>
                  <span className="font-mono text-xs font-semibold text-foreground mt-0.5 block">RS256 / SHA-256</span>
                </div>
                <div>
                  <span className="font-mono text-[10px] uppercase text-muted-foreground block">Key Length</span>
                  <span className="font-mono text-xs font-semibold text-foreground mt-0.5 block">2048-bit RSA</span>
                </div>
                <div>
                  <span className="font-mono text-[10px] uppercase text-muted-foreground block">Discovery</span>
                  <span className="font-mono text-xs font-semibold text-emerald-400 mt-0.5 block">Active</span>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-border/40 text-muted-foreground font-mono text-[11px]">
              <span>OIDC Metadata Feed</span>
              <span className="text-foreground font-medium">/.well-known/openid-configuration</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </AdminLayout>
  );
};
