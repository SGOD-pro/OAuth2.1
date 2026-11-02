import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useAdminStore } from '@/lib/adminStore';
import { usePageTitle } from '@/hooks/usePageTitle';
import { toast } from 'sonner';

function formatRelativeTime(dateString?: string | null): string {
  if (!dateString) return '—';
  const date = new Date(dateString);
  const now = new Date();
  const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);
  if (diffSec < 0 || diffSec < 60) return 'Just now';
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;
  const diffDay = Math.floor(diffHour / 24);
  return `${diffDay}d ago`;
}

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
    <Card accent={accent} className="transition-none hover:translate-y-0 relative overflow-hidden">
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

        <div className="mt-2 font-sans text-xs text-muted-foreground">
          {helperText}
        </div>
      </CardContent>
    </Card>
  )
);

export const AdminDashboard: React.FC = () => {
  usePageTitle('Overview');

  const { data: stats, loading: statsLoading } = useAdminStore((state) => state.stats);
  const { data: clients } = useAdminStore((state) => state.clients);
  const fetchStats = useAdminStore((state) => state.fetchStats);
  const fetchClients = useAdminStore((state) => state.fetchClients);

  const [copiedEndpoint, setCopiedEndpoint] = useState<string | null>(null);

  useEffect(() => {
    void fetchStats();
    void fetchClients();
  }, [fetchStats, fetchClients]);

  const copyToClipboard = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedEndpoint(label);
    toast.success(`${label} copied to clipboard`);
    setTimeout(() => setCopiedEndpoint(null), 1600);
  };

  const recentActivity = stats?.recentActivity || [];
  const clientList = (clients || []).slice(0, 3);

  return (
    <div className="flex flex-col gap-6 sm:gap-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="font-heading text-2xl sm:text-[34px] font-semibold text-foreground tracking-tight leading-tight">
            Overview
          </h1>
          <p className="mt-1 font-sans text-sm text-muted-foreground max-w-2xl">
            Monitor registered applications, user accounts, and authentication protocol settings.
          </p>
        </div>

        <div className="flex items-center gap-2.5 self-start sm:self-auto shrink-0">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => {
              void fetchStats(true);
              void fetchClients(true);
            }} 
            disabled={statsLoading}
            className="h-9 px-3.5 self-start sm:self-auto shrink-0 gap-1.5"
          >
            <svg className={`size-3.5 ${statsLoading ? 'animate-spin' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" />
              <path d="M21 3v5h-5" />
            </svg>
            Refresh
          </Button>
        </div>
      </div>

      {/* 4 KPI Metrics Row */}
      <div className="grid gap-4 sm:gap-5 grid-cols-1 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Applications"
          value={stats?.totalClients ?? null}
          loading={statsLoading && !stats}
          helperText={`${stats?.activeClients ?? 0} active`}
          accent="motorsport"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" />
            </svg>
          }
        />
        <StatCard
          label="Total Users"
          value={stats?.totalUsers ?? null}
          loading={statsLoading && !stats}
          helperText="Enrolled platform users"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
            </svg>
          }
        />
        <StatCard
          label="New sessions (24h)"
          value={stats?.recentLogins ?? null}
          loading={statsLoading && !stats}
          helperText="Created in last 24h"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
          }
        />
        <StatCard
          label="Active Sessions"
          value={stats?.activeSessions ?? null}
          loading={statsLoading && !stats}
          helperText="Current active sessions"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          }
        />
      </div>

      {/* Cockpit Asymmetric Layout: Left Main Column & Right Architecture Column */}
      <div className="grid gap-6 grid-cols-1 lg:grid-cols-12">
        {/* Left Column (8 cols): Recent Authentication Activity & Registered Apps Quick-Matrix */}
        <div className="lg:col-span-8 flex flex-col gap-6">
          {/* Recent Sign-Ins Ledger */}
          <Card className="flex flex-col">
            <CardContent className="p-5 sm:p-6 flex flex-col flex-1">
              <div className="flex items-center justify-between pb-4 border-b border-border">
                <div>
                  <h2 className="font-heading text-base sm:text-lg font-medium text-foreground">
                    Recent sign ins
                  </h2>
                  <p className="font-sans text-xs text-muted-foreground mt-0.5">
                    Most recent user authentication sessions
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs text-muted-foreground">
                    {recentActivity.length} logged
                  </span>
                  <NavLink
                    to="/admin/logs"
                    className="font-sans text-xs text-primary hover:underline font-medium"
                  >
                    View audit log →
                  </NavLink>
                </div>
              </div>

              {recentActivity.length === 0 ? (
                <div className="py-12 text-center font-sans text-sm text-muted-foreground flex flex-col items-center justify-center">
                  <div className="size-10 rounded-full bg-secondary border border-border flex items-center justify-center text-muted-foreground mb-3">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                  </div>
                  <span>No recent sign-ins.</span>
                </div>
              ) : (
                <div className="divide-y divide-border/70">
                  {recentActivity.map((activity, idx) => {
                    const date = activity.timestamp ? new Date(activity.timestamp) : null;
                    const absoluteTime = date ? `${date.toISOString()} (${date.toUTCString()})` : '';
                    return (
                      <div key={activity.id || idx} className="py-3.5 flex items-center justify-between gap-3 text-xs font-sans">
                        <div className="flex items-center gap-3 min-w-0">
                          <div className="size-2 rounded-full bg-emerald-500 shrink-0" />
                          <div className="min-w-0">
                            <span className="font-mono font-medium text-foreground block truncate">
                              {activity.ipAddress || 'Unknown IP'}
                            </span>
                            <span className="text-muted-foreground text-[11px] block truncate">
                              {activity.userAgent || 'Web Client'}
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center gap-3 shrink-0">
                          <span className="hidden sm:inline-flex px-2 py-0.5 rounded-pill text-[10px] font-sans font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                            session_created
                          </span>
                          <time 
                            dateTime={activity.timestamp || undefined} 
                            title={absoluteTime}
                            className="text-muted-foreground font-sans text-xs shrink-0"
                          >
                            {formatRelativeTime(activity.timestamp)}
                          </time>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Registered Applications Quick-Matrix */}
          <Card>
            <CardContent className="p-5 sm:p-6">
              <div className="flex items-center justify-between pb-4 border-b border-border">
                <div>
                  <h2 className="font-heading text-base sm:text-lg font-medium text-foreground">
                    Registered Applications
                  </h2>
                  <p className="font-sans text-xs text-muted-foreground mt-0.5">
                    Active client identity and permission profiles
                  </p>
                </div>
                <NavLink
                  to="/admin/clients"
                  className="font-sans text-xs text-primary hover:underline font-medium"
                >
                  Manage all ({clients?.length ?? 0}) →
                </NavLink>
              </div>

              {clientList.length === 0 ? (
                <div className="py-8 text-center font-sans text-sm text-muted-foreground">
                  No applications registered yet.
                </div>
              ) : (
                <div className="divide-y divide-border/70">
                  {clientList.map((client) => {
                    const isDev = Boolean(client.is_dev || client.isDev);
                    const isPublic = client.is_public !== false && client.isPublic !== false;
                    return (
                      <div key={client.client_id} className="py-3 flex items-center justify-between gap-3 text-xs font-sans">
                        <div className="flex items-center gap-3 min-w-0">
                          <div className="size-8 rounded-md bg-secondary border border-border flex items-center justify-center font-mono text-xs font-semibold text-foreground uppercase shrink-0">
                            {client.client_name.substring(0, 2)}
                          </div>
                          <div className="min-w-0">
                            <span className="font-sans font-medium text-foreground text-sm block truncate">
                              {client.client_name}
                            </span>
                            <code className="font-mono text-[11px] text-muted-foreground block truncate">
                              {client.client_id}
                            </code>
                          </div>
                        </div>

                        <div className="flex items-center gap-1.5 shrink-0">
                          <Badge variant={isDev ? 'warning' : 'secondary'} className="text-[10px]">
                            {isDev ? 'Development' : 'Production'}
                          </Badge>
                          <Badge variant="outline" className="text-[10px] hidden sm:inline-flex">
                            {isPublic ? 'Public' : 'Private'}
                          </Badge>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Column (4 cols): Protocol & Cryptographic Cockpit */}
        <div className="lg:col-span-4 flex flex-col gap-6">
          {/* OAuth 2.1 Specification Cockpit Card */}
          <Card>
            <CardContent className="p-5 sm:p-6 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-border">
                <div className="flex items-center gap-2.5">
                  <div className="size-8 rounded-md border border-border bg-secondary flex items-center justify-center text-primary">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="font-heading text-sm sm:text-base font-medium text-foreground">OAuth 2.1 Specification</h3>
                    <p className="font-sans text-xs text-muted-foreground">RFC 6749 / RFC 7636</p>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-pill text-[11px] font-sans font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  <span className="size-1.5 rounded-full bg-emerald-500" />
                  Active
                </span>
              </div>

              <div className="space-y-2.5 font-sans text-xs">
                <div className="flex items-center justify-between py-1 border-b border-border/50">
                  <span className="text-muted-foreground">PKCE Method</span>
                  <span className="font-mono font-medium text-foreground">S256</span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-border/50">
                  <span className="text-muted-foreground">Grant Flow</span>
                  <span className="font-mono font-medium text-foreground">Authorization Code</span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-border/50">
                  <span className="text-muted-foreground">Token Reuse</span>
                  <span className="font-mono font-medium text-emerald-600 dark:text-emerald-400">Protected</span>
                </div>
                <div className="flex items-center justify-between py-1">
                  <span className="text-muted-foreground">Client Authentication</span>
                  <span className="font-medium text-foreground text-right">Public (PKCE) & Confidential</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Keys & Discovery Cockpit Card */}
          <Card>
            <CardContent className="p-5 sm:p-6 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-border">
                <div className="flex items-center gap-2.5">
                  <div className="size-8 rounded-md border border-border bg-secondary flex items-center justify-center text-primary">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="font-heading text-sm sm:text-base font-medium text-foreground">Keys & Token Discovery</h3>
                    <p className="font-sans text-xs text-muted-foreground">JWKS & OIDC Discovery</p>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-pill text-[11px] font-sans font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  <span className="size-1.5 rounded-full bg-emerald-500" />
                  Configured
                </span>
              </div>

              <div className="space-y-2.5 font-sans text-xs">
                <div className="flex items-center justify-between py-1 border-b border-border/50">
                  <span className="text-muted-foreground">Signing Algorithm</span>
                  <span className="font-mono font-medium text-foreground">RS256</span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-border/50">
                  <span className="text-muted-foreground">Key Size</span>
                  <span className="font-mono font-medium text-foreground">2048-bit RSA</span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-border/50">
                  <span className="text-muted-foreground">JWKS Endpoint</span>
                  <span className="font-mono font-medium text-foreground">Active</span>
                </div>
                <div className="pt-1">
                  <div className="flex items-center justify-between text-muted-foreground mb-1">
                    <span>Metadata URL</span>
                    <button
                      type="button"
                      onClick={() => void copyToClipboard('/.well-known/openid-configuration', 'Metadata URL')}
                      className="text-primary hover:underline text-[11px] cursor-pointer"
                    >
                      {copiedEndpoint === 'Metadata URL' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <code className="text-foreground font-mono text-[11px] bg-secondary/60 px-2 py-1 rounded block truncate border border-border">
                    /.well-known/openid-configuration
                  </code>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Quick Platform Shortcuts */}
          <Card>
            <CardContent className="p-4 sm:p-5">
              <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground block mb-3">
                Quick Console Actions
              </span>
              <div className="grid grid-cols-1 gap-2">
                <NavLink
                  to="/admin/clients"
                  className="flex items-center justify-between p-2.5 rounded-lg border border-border bg-card hover:bg-secondary/50 text-xs font-sans text-foreground transition-colors group"
                >
                  <span className="font-medium">Register Application</span>
                  <span className="text-muted-foreground group-hover:text-foreground">→</span>
                </NavLink>
                <NavLink
                  to="/admin/logs"
                  className="flex items-center justify-between p-2.5 rounded-lg border border-border bg-card hover:bg-secondary/50 text-xs font-sans text-foreground transition-colors group"
                >
                  <span className="font-medium">Audit Event Logs</span>
                  <span className="text-muted-foreground group-hover:text-foreground">→</span>
                </NavLink>
                <NavLink
                  to="/admin/security"
                  className="flex items-center justify-between p-2.5 rounded-lg border border-border bg-card hover:bg-secondary/50 text-xs font-sans text-foreground transition-colors group"
                >
                  <span className="font-medium">Security & 2FA Configuration</span>
                  <span className="text-muted-foreground group-hover:text-foreground">→</span>
                </NavLink>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};
