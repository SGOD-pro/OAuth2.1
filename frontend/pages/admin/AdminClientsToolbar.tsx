import React, { useCallback, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Search, X, RotateCcw } from 'lucide-react';
import type { OAuthClient } from '@/lib/adminStore-types';
import { resolveDisplayPolicy } from './ClientPolicyBadges';

interface AdminClientsToolbarProps {
  clients: OAuthClient[];
  filteredCount: number;
  searchTerm: string;
  setSearchTerm: (v: string) => void;
  envFilter: 'all' | 'prod' | 'dev';
  setEnvFilter: (v: 'all' | 'prod' | 'dev') => void;
  accessFilter: 'all' | 'open' | 'private';
  setAccessFilter: (v: 'all' | 'open' | 'private') => void;
  typeFilter: 'all' | 'confidential' | 'public';
  setTypeFilter: (v: 'all' | 'confidential' | 'public') => void;
  ambiguousOnly: boolean;
  setAmbiguousOnly: (v: boolean) => void;
  hasAdminsOnly: boolean;
  setHasAdminsOnly: (v: boolean) => void;
  hasActiveFilters: boolean;
  resetFilters: () => void;
}

export const AdminClientsToolbar: React.FC<AdminClientsToolbarProps> = ({
  clients,
  filteredCount,
  searchTerm,
  setSearchTerm,
  envFilter,
  setEnvFilter,
  accessFilter,
  setAccessFilter,
  typeFilter,
  setTypeFilter,
  ambiguousOnly,
  setAmbiguousOnly,
  hasAdminsOnly,
  setHasAdminsOnly,
  hasActiveFilters,
  resetFilters,
}) => {
  const filterSegments = useMemo(() => {
    const policies = clients.map((c) => resolveDisplayPolicy(c));
    return [
      { key: 'all', label: `All (${clients.length})`, onClick: () => { setEnvFilter('all'); setAccessFilter('all'); setAmbiguousOnly(false); } },
      { key: 'prod', label: `Production (${policies.filter((p) => !p.isDev).length})`, onClick: () => { setEnvFilter('prod'); setAccessFilter('all'); setAmbiguousOnly(false); } },
      { key: 'dev', label: `Development (${policies.filter((p) => p.isDev).length})`, onClick: () => { setEnvFilter('dev'); setAccessFilter('all'); setAmbiguousOnly(false); } },
      { key: 'open', label: `Open (${policies.filter((p) => p.accessPolicy === 'open').length})`, onClick: () => { setAccessFilter('open'); setEnvFilter('all'); setAmbiguousOnly(false); } },
      { key: 'private', label: `Private (${policies.filter((p) => p.accessPolicy === 'private').length})`, onClick: () => { setAccessFilter('private'); setEnvFilter('all'); setAmbiguousOnly(false); } },
      { key: 'ambiguous', label: `Ambiguous (${policies.filter((p) => p.isAmbiguous).length})`, onClick: () => { setAmbiguousOnly(true); setEnvFilter('all'); setAccessFilter('all'); } },
    ];
  }, [clients, setEnvFilter, setAccessFilter, setAmbiguousOnly]);

  const activeSegmentKey = useMemo(() => {
    if (ambiguousOnly) return 'ambiguous';
    if (envFilter === 'all' && accessFilter === 'all') return 'all';
    if (envFilter === 'prod' && accessFilter === 'all') return 'prod';
    if (envFilter === 'dev' && accessFilter === 'all') return 'dev';
    if (accessFilter === 'open' && envFilter === 'all') return 'open';
    if (accessFilter === 'private' && envFilter === 'all') return 'private';
    return null;
  }, [envFilter, accessFilter, ambiguousOnly]);

  const containerRef = useRef<HTMLDivElement>(null);
  const btnRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const [indicator, setIndicator] = useState({ left: 0, top: 0, width: 0, height: 0, ready: false });

  const updateIndicator = useCallback(() => {
    if (!activeSegmentKey) { setIndicator((p) => (p.ready ? { ...p, ready: false } : p)); return; }
    const c = containerRef.current;
    const t = btnRefs.current[activeSegmentKey];
    if (c && t) {
      const cr = c.getBoundingClientRect();
      const tr = t.getBoundingClientRect();
      setIndicator({ left: tr.left - cr.left, top: tr.top - cr.top, width: tr.width, height: tr.height, ready: true });
    }
  }, [activeSegmentKey]);

  useLayoutEffect(() => {
    updateIndicator();
    window.addEventListener('resize', updateIndicator);
    return () => window.removeEventListener('resize', updateIndicator);
  }, [updateIndicator, clients.length]);

  return (
    <>
      <div ref={containerRef} className="relative flex flex-wrap items-center gap-1.5 p-1 rounded-full bg-secondary/60 border border-border/80 w-fit">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute left-0 top-0 rounded-full bg-card shadow-2xs transition-[transform,width,height,opacity] duration-220 ease-emphasis will-change-transform motion-reduce:transition-none"
          style={{
            transform: `translateX(${indicator.left}px) translateY(${indicator.top}px) translateZ(0)`,
            width: `${indicator.width}px`,
            height: `${indicator.height}px`,
            opacity: indicator.ready && activeSegmentKey ? 1 : 0,
          }}
        />
        {filterSegments.map((s) => (
          <button
            key={s.key}
            ref={(el) => { btnRefs.current[s.key] = el; }}
            type="button"
            onClick={s.onClick}
            className={`relative z-10 px-3 py-1 rounded-full text-xs font-sans transition-colors cursor-pointer ${
              activeSegmentKey === s.key ? 'text-foreground font-medium' : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            {s.label}
          </button>
        ))}
      </div>

      <search className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 p-3 rounded-[12px] bg-card border border-border shadow-2xs">
        <div className="flex flex-1 flex-wrap items-center gap-2.5">
          <div className="relative flex-1 min-w-[180px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-4 text-muted-foreground pointer-events-none" />
            <Input
              type="text"
              placeholder="Search by name or client ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8.5 pr-8 h-9 text-xs"
              aria-label="Search applications"
            />
            {searchTerm && (
              <button type="button" onClick={() => setSearchTerm('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-0.5 rounded" aria-label="Clear search text">
                <X className="size-3.5" />
              </button>
            )}
          </div>

          <Select value={typeFilter} onValueChange={(v) => setTypeFilter(v as 'all' | 'confidential' | 'public')}>
            <SelectTrigger className="w-full sm:w-40 text-xs"><SelectValue placeholder="Client type" /></SelectTrigger>
            <SelectContent><SelectGroup>
              <SelectLabel>Client Type</SelectLabel>
              <SelectItem value="all">All types</SelectItem>
              <SelectItem value="confidential">Confidential</SelectItem>
              <SelectItem value="public">Public</SelectItem>
            </SelectGroup></SelectContent>
          </Select>

          <Select value={accessFilter} onValueChange={(v) => setAccessFilter(v as 'all' | 'open' | 'private')}>
            <SelectTrigger className="w-full sm:w-40 text-xs"><SelectValue placeholder="Access policy" /></SelectTrigger>
            <SelectContent><SelectGroup>
              <SelectLabel>Access Policy</SelectLabel>
              <SelectItem value="all">All policies</SelectItem>
              <SelectItem value="private">Private</SelectItem>
              <SelectItem value="open">Open</SelectItem>
            </SelectGroup></SelectContent>
          </Select>

          <Select value={envFilter} onValueChange={(v) => setEnvFilter(v as 'all' | 'prod' | 'dev')}>
            <SelectTrigger className="w-full sm:w-40 text-xs"><SelectValue placeholder="Environment" /></SelectTrigger>
            <SelectContent><SelectGroup>
              <SelectLabel>Environment</SelectLabel>
              <SelectItem value="all">All environments</SelectItem>
              <SelectItem value="prod">Production</SelectItem>
              <SelectItem value="dev">Development</SelectItem>
            </SelectGroup></SelectContent>
          </Select>

          <label className="flex items-center gap-2 px-3 py-1.5 rounded-md border border-border bg-secondary/20 hover:bg-secondary/40 cursor-pointer text-xs font-medium text-foreground select-none h-9">
            <Checkbox aria-label="Assigned custom admins" checked={hasAdminsOnly} onCheckedChange={(c) => setHasAdminsOnly(Boolean(c))} />
            <span>Custom admins</span>
          </label>
        </div>

        <div className="flex items-center justify-between lg:justify-end gap-3 shrink-0 pt-2 lg:pt-0 border-t lg:border-t-0 border-border/50">
          <span className="text-xs text-muted-foreground font-mono">
            Showing {filteredCount} of {clients.length} app{clients.length === 1 ? '' : 's'}
          </span>
          {hasActiveFilters && (
            <Button variant="ghost" size="sm" onClick={resetFilters} className="h-8 px-2.5 text-xs text-muted-foreground hover:text-foreground gap-1.5">
              <RotateCcw className="size-3" /> Reset
            </Button>
          )}
        </div>
      </search>
    </>
  );
};
