import React, { useEffect } from 'react';
import { AdminLayout } from './AdminLayout';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAdminStore } from '@/lib/adminStore';
import { usePageTitle } from '@/hooks/usePageTitle';

const StatCard = React.memo(
  ({ 
    label, 
    value, 
    loading, 
    icon, 
    helperText,
    accent = 'none',
  }: { 
    label: string; 
    value: number | null; 
    loading: boolean; 
    icon: React.ReactNode;
    helperText: string;
    accent?: 'none' | 'motorsport';
  }) => (
    <Card accent={accent}>
      <CardContent className="p-5 sm:p-6">
        <div className="flex items-center justify-between mb-3">
          <span className="font-sans text-xs font-medium text-muted-foreground">
            {label}
          </span>
          <div className="size-8 rounded-md bg-secondary border border-border flex items-center justify-center text-muted-foreground">
            {icon}
          </div>
        </div>

        {loading ? (
          <div className="h-9 w-20 rounded-md bg-secondary animate-pulse mt-1" />
        ) : (
          <div className="font-heading text-[34px] leading-tight font-semibold text-foreground tracking-tight">
            {value ?? '—'}
          </div>
        )}

        <div className="mt-3 pt-3 border-t border-border flex items-center justify-between">
          <span className="font-sans text-xs text-muted-foreground">
            Status
          </span>
          <span className="font-sans text-xs text-foreground font-medium">
            {helperText}
          </span>
        </div>
      </CardContent>
    </Card>
  )
);

export const AdminDashboard: React.FC = () => {
  usePageTitle('Overview');

  const { data: stats, loading } = useAdminStore((state) => state.stats);
  const fetchStats = useAdminStore((state) => state.fetchStats);

  useEffect(() => {
    void fetchStats();
  }, [fetchStats]);

  return (
    <AdminLayout>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 sm:mb-8">
        <div>
          <h1 className="font-heading text-2xl sm:text-[34px] font-semibold text-foreground tracking-tight leading-tight">
            Overview
          </h1>
          <p className="mt-1 font-sans text-sm text-muted-foreground">
            Monitor registered applications, user accounts, and authentication protocol settings.
          </p>
        </div>

        <Button 
          variant="outline" 
          size="sm" 
          onClick={() => void fetchStats(true)} 
          disabled={loading}
          className="h-9 px-3 self-start sm:self-auto shrink-0"
        >
          <svg className={`mr-1.5 size-3.5 ${loading ? 'animate-spin' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" />
            <path d="M21 3v5h-5" />
          </svg>
          Refresh
        </Button>
      </div>

      <div className="grid gap-5 grid-cols-1 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Applications"
          value={stats?.totalClients ?? null}
          loading={loading && !stats}
          helperText="Registered"
          accent="motorsport"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" />
            </svg>
          }
        />
        <StatCard
          label="Active Applications"
          value={stats?.activeClients ?? null}
          loading={loading && !stats}
          helperText="Operational"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
            </svg>
          }
        />
        <StatCard
          label="Total Users"
          value={stats?.totalUsers ?? null}
          loading={loading && !stats}
          helperText="Enrolled"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
            </svg>
          }
        />
        <StatCard
          label="Logins (24h)"
          value={stats?.recentLogins ?? null}
          loading={loading && !stats}
          helperText="Recent activity"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
          }
        />
      </div>

      <div className="mt-8 grid gap-6 grid-cols-1 md:grid-cols-2">
        <Card>
          <CardContent className="p-5 sm:p-6 flex flex-col justify-between min-h-[210px]">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2.5">
                  <div className="size-8 rounded-md border border-border bg-secondary flex items-center justify-center text-primary">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="font-heading text-base font-medium text-foreground">OAuth 2.1 Specification</h3>
                    <p className="font-sans text-xs text-muted-foreground">RFC 6749 / RFC 7636</p>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-sans font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  <span className="size-1.5 rounded-full bg-emerald-500" />
                  Active
                </span>
              </div>

              <div className="grid grid-cols-3 gap-3 my-4 p-3.5 rounded-md bg-secondary/30 border border-border">
                <div>
                  <span className="font-sans text-xs text-muted-foreground block">PKCE Method</span>
                  <span className="font-mono text-xs font-medium text-foreground mt-0.5 block">S256 (SHA-256)</span>
                </div>
                <div>
                  <span className="font-sans text-xs text-muted-foreground block">Grant Flow</span>
                  <span className="font-mono text-xs font-medium text-foreground mt-0.5 block">Authorization Code</span>
                </div>
                <div>
                  <span className="font-sans text-xs text-muted-foreground block">Token Reuse</span>
                  <span className="font-mono text-xs font-medium text-emerald-600 dark:text-emerald-400 mt-0.5 block">Protected</span>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-border text-muted-foreground font-sans text-xs">
              <span>Client Authentication</span>
              <span className="text-foreground font-medium">Public (PKCE) & Confidential</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-5 sm:p-6 flex flex-col justify-between min-h-[210px]">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2.5">
                  <div className="size-8 rounded-md border border-border bg-secondary flex items-center justify-center text-primary">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="font-heading text-base font-medium text-foreground">Keys & Token Discovery</h3>
                    <p className="font-sans text-xs text-muted-foreground">JWKS & OIDC Discovery</p>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-sans font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  <span className="size-1.5 rounded-full bg-emerald-500" />
                  Configured
                </span>
              </div>

              <div className="grid grid-cols-3 gap-3 my-4 p-3.5 rounded-md bg-secondary/30 border border-border">
                <div>
                  <span className="font-sans text-xs text-muted-foreground block">Signing Algorithm</span>
                  <span className="font-mono text-xs font-medium text-foreground mt-0.5 block">RS256</span>
                </div>
                <div>
                  <span className="font-sans text-xs text-muted-foreground block">Key Size</span>
                  <span className="font-mono text-xs font-medium text-foreground mt-0.5 block">2048-bit RSA</span>
                </div>
                <div>
                  <span className="font-sans text-xs text-muted-foreground block">JWKS Endpoint</span>
                  <span className="font-mono text-xs font-medium text-foreground mt-0.5 block">Active</span>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-border text-muted-foreground font-sans text-xs">
              <span>Metadata URL</span>
              <code className="text-foreground font-mono text-[11px]">/.well-known/openid-configuration</code>
            </div>
          </CardContent>
        </Card>
      </div>
    </AdminLayout>
  );
};
