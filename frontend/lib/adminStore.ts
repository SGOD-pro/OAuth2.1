import { create } from 'zustand';
import { toast } from 'sonner';
import { apiFetch } from './api';

export interface RecentActivityItem {
  id?: string;
  type?: string;
  userId?: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  timestamp?: string | null;
}

export interface Stats {
  totalClients: number;
  activeClients: number;
  totalUsers: number;
  recentLogins: number;
  recentSessions24h?: number;
  activeSessions?: number;
  recentActivity?: RecentActivityItem[];
}

export interface OAuthClient {
  client_id: string;
  client_name: string;
  // client_secret is intentionally NOT included — secrets are only returned once at creation
  // time (POST /clients response) and should never be fetched via list/detail endpoints.
  redirect_uris: string[];
  redirectUris?: string[];
  allowed_origins?: string[];
  allowedOrigins?: string[];
  disabled: boolean;
  is_dev?: boolean;
  isDev?: boolean;
  is_public?: boolean;
  isPublic?: boolean;
  metadata?: {
    allowedOrigins?: string[];
    allowed_origins?: string[];
    isDev?: boolean;
    is_dev?: boolean;
  };
  skip_consent: boolean;
  enable_end_session: boolean;
  has_custom_admins?: boolean;
  hasCustomAdmins?: boolean;
  adminEmail?: string | null;
  adminUserId?: string | null;
  createdAt?: string | Date;
  created_at?: string | Date;
  updatedAt?: string | Date;
  updated_at?: string | Date;
}

export interface LogEntry {
  userId: string;
  userEmail: string | null;
  action: string;
  ipAddress: string | null;
  createdAt: string | null;
  appName?: string | null;
  applicationName?: string | null;
  outcome?: string | null;
  clientId?: string | null;
}

export interface LogsQuery {
  page?: number;
  limit?: number;
  search?: string;
  action?: string;
  outcome?: string;
  clientId?: string;
}

export interface LogsState {
  data: LogEntry[] | null;
  totalCount: number;
  page: number;
  limit: number;
  totalPages: number;
  lastFetched: number;
  loading: boolean;
  error: string | null;
  activeQueryKey: string;
}

interface CacheState<T> {
  data: T | null;
  lastFetched: number;
  loading: boolean;
}

interface AdminStore {
  stats: CacheState<Stats>;
  clients: CacheState<OAuthClient[]>;
  logs: LogsState;
  
  fetchStats: (force?: boolean) => Promise<void>;
  fetchClients: (force?: boolean) => Promise<void>;
  fetchLogs: (query?: LogsQuery, force?: boolean) => Promise<void>;
  
  // Optimistic mutations
  addClientLocal: (client: OAuthClient) => void;
  updateClientLocal: (client: OAuthClient) => void;
  deleteClientLocal: (clientId: string) => void;
}

const CACHE_TTL = 30_000; // 30 seconds

interface CachedQueryResult {
  data: LogEntry[];
  totalCount: number;
  page: number;
  limit: number;
  totalPages: number;
  lastFetched: number;
}

const logsCache = new Map<string, CachedQueryResult>();
const inFlightLogs = new Map<string, Promise<{
  data: LogEntry[];
  totalCount: number;
  page: number;
  limit: number;
  totalPages: number;
}>>();
const queryOwnership = new Map<string, number>();

let inFlightStats: Promise<void> | null = null;
let inFlightClients: Promise<void> | null = null;
let latestLogRequestId = 0;
let latestLogQuerySequence = 0;

export function _resetAdminLogsCacheForTesting() {
  logsCache.clear();
  inFlightLogs.clear();
  queryOwnership.clear();
  latestLogRequestId = 0;
  latestLogQuerySequence = 0;
}

export const useAdminStore = create<AdminStore>((set, get) => ({
  stats: { data: null, lastFetched: 0, loading: false },
  clients: { data: null, lastFetched: 0, loading: false },
  logs: {
    data: null,
    totalCount: 0,
    page: 1,
    limit: 50,
    totalPages: 1,
    lastFetched: 0,
    loading: false,
    error: null,
    activeQueryKey: '',
  },

  fetchStats: async (force = false) => {
    const { stats } = get();
    if (!force && stats.data && Date.now() - stats.lastFetched < CACHE_TTL) return;
    if (inFlightStats) return inFlightStats;

    inFlightStats = (async () => {
      set({ stats: { ...get().stats, loading: true } });
      try {
        const res = await apiFetch('/api/admin/stats');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: Stats = await res.json();
        set({ stats: { data, lastFetched: Date.now(), loading: false } });
      } catch (err) {
        toast.error(`Failed to load stats: ${String(err)}`);
        set({ stats: { ...get().stats, loading: false } });
      } finally {
        inFlightStats = null;
      }
    })();

    return inFlightStats;
  },

  fetchClients: async (force = false) => {
    const { clients } = get();
    if (!force && clients.data && Date.now() - clients.lastFetched < CACHE_TTL) return;
    if (inFlightClients) return inFlightClients;

    inFlightClients = (async () => {
      set({ clients: { ...get().clients, loading: true } });
      try {
        const res = await apiFetch('/api/admin/clients');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: OAuthClient[] = await res.json();
        const sorted = (data || []).sort((a, b) => {
          const timeA = a.createdAt ? new Date(a.createdAt).getTime() : (a.created_at ? new Date(a.created_at).getTime() : 0);
          const timeB = b.createdAt ? new Date(b.createdAt).getTime() : (b.created_at ? new Date(b.created_at).getTime() : 0);
          return timeB - timeA;
        });
        set({ clients: { data: sorted, lastFetched: Date.now(), loading: false } });
      } catch (err) {
        toast.error(String(err));
        set({ clients: { ...get().clients, loading: false } });
      } finally {
        inFlightClients = null;
      }
    })();

    return inFlightClients;
  },

  fetchLogs: async (query?: LogsQuery, force = false) => {
    const page = query?.page && query.page > 0 ? query.page : 1;
    const limit = query?.limit && query.limit > 0 ? query.limit : 50;
    const search = query?.search?.trim() || '';
    const action = query?.action && query.action !== 'all' ? query.action : '';
    const outcome = query?.outcome && query.outcome !== 'all' ? query.outcome : '';
    const clientId = query?.clientId?.trim() || '';

    const queryKey = JSON.stringify({ page, limit, search, action, outcome, clientId });
    const now = Date.now();

    // 1. Cached Query Return:
    // If unexpired cached data exists for this query, return it immediately.
    // Crucially, increment request identity before returning so any obsolete in-flight
    // request cannot update results, totals, loading, or errors.
    const cached = logsCache.get(queryKey);
    const activeMatch = get().logs.activeQueryKey === queryKey && get().logs.data !== null;
    const isCachedValid = Boolean(cached && now - cached.lastFetched < CACHE_TTL);
    const isActiveValid = Boolean(activeMatch && now - get().logs.lastFetched < CACHE_TTL);

    if (!force && (isCachedValid || isActiveValid)) {
      const validCache: CachedQueryResult = isCachedValid && cached
        ? cached
        : {
            data: get().logs.data!,
            totalCount: get().logs.totalCount,
            page: get().logs.page,
            limit: get().logs.limit,
            totalPages: get().logs.totalPages,
            lastFetched: get().logs.lastFetched,
          };

      // Invalidate any older in-flight requests by updating request identity
      ++latestLogRequestId;

      set({
        logs: {
          data: validCache.data,
          totalCount: validCache.totalCount,
          page: validCache.page,
          limit: validCache.limit,
          totalPages: validCache.totalPages,
          lastFetched: validCache.lastFetched,
          loading: false,
          error: null,
          activeQueryKey: queryKey,
        },
      });
      return;
    }

    // 2. Fresh Request:
    // Update request identity and mark store as loading for this query
    const currentRequestId = ++latestLogRequestId;
    set({ logs: { ...get().logs, loading: true, error: null } });

    // 3. In-flight Deduplication & Ownership Tracking:
    // Reuse in-flight network request for identical query parameters unless forced
    let fetchPromise = inFlightLogs.get(queryKey);

    try {
      if (!fetchPromise || force) {
        const queryToken = ++latestLogQuerySequence;
        if (queryOwnership.size >= 100 && !queryOwnership.has(queryKey)) {
          const oldestKey = queryOwnership.keys().next().value;
          if (oldestKey) queryOwnership.delete(oldestKey);
        }
        queryOwnership.set(queryKey, queryToken);

        fetchPromise = (async () => {
          const params = new URLSearchParams();
          params.set('page', String(page));
          params.set('limit', String(limit));
          if (search) params.set('search', search);
          if (action) params.set('action', action);
          if (outcome) params.set('outcome', outcome);
          if (clientId) params.set('clientId', clientId);

          const res = await apiFetch(`/api/admin/logs?${params.toString()}`);
          if (!res.ok) {
            throw new Error(`HTTP ${res.status}: Failed to load logs`);
          }

          const totalCount = parseInt(res.headers.get('X-Total-Count') || '0', 10);
          const resPage = parseInt(res.headers.get('X-Page') || String(page), 10);
          const resLimit = parseInt(res.headers.get('X-Limit') || String(limit), 10);
          const totalPages = parseInt(res.headers.get('X-Total-Pages') || '1', 10);
          const data: LogEntry[] = await res.json();

          const result = {
            data,
            totalCount,
            page: resPage,
            limit: resLimit,
            totalPages,
          };

          // Only the current sequence owner may publish that query's cached result
          if (queryOwnership.get(queryKey) === queryToken) {
            if (logsCache.size >= 100) {
              const oldestKey = logsCache.keys().next().value;
              if (oldestKey) {
                logsCache.delete(oldestKey);
                queryOwnership.delete(oldestKey);
              }
            }
            logsCache.set(queryKey, {
              ...result,
              lastFetched: Date.now(),
            });
          }

          return result;
        })();

        inFlightLogs.set(queryKey, fetchPromise);
      }

      const result = await fetchPromise;

      // Guard against race conditions: do not overwrite newer search/filter results
      if (currentRequestId === latestLogRequestId) {
        set({
          logs: {
            data: result.data,
            totalCount: result.totalCount,
            page: result.page,
            limit: result.limit,
            totalPages: result.totalPages,
            lastFetched: Date.now(),
            loading: false,
            error: null,
            activeQueryKey: queryKey,
          },
        });
      }
    } catch (err: unknown) {
      if (currentRequestId === latestLogRequestId) {
        const errorMsg =
          err instanceof Error
            ? err.message
            : typeof err === 'string'
            ? err
            : 'Failed to load logs';
        toast.error(errorMsg);
        set({
          logs: {
            ...get().logs,
            loading: false,
            error: errorMsg,
          },
        });
      }
    } finally {
      // Delete in-flight entry only when it still belongs to the completing request
      if (fetchPromise && inFlightLogs.get(queryKey) === fetchPromise) {
        inFlightLogs.delete(queryKey);
      }
    }
  },

  addClientLocal: (client) => {
    const enriched: OAuthClient = {
      ...client,
      createdAt: client.createdAt || client.created_at || new Date().toISOString(),
      created_at: client.createdAt || client.created_at || new Date().toISOString(),
    };
    set((state) => {
      const remaining = (state.clients.data || []).filter((c) => c.client_id !== enriched.client_id);
      const updated = [enriched, ...remaining].sort((a, b) => {
        const timeA = a.createdAt ? new Date(a.createdAt).getTime() : (a.created_at ? new Date(a.created_at).getTime() : 0);
        const timeB = b.createdAt ? new Date(b.createdAt).getTime() : (b.created_at ? new Date(b.created_at).getTime() : 0);
        return timeB - timeA;
      });
      return {
        clients: {
          ...state.clients,
          data: updated,
        },
      };
    });
    // Trigger background stats refresh
    void get().fetchStats(true);
  },

  updateClientLocal: (client) => {
    set((state) => ({
      clients: {
        ...state.clients,
        data: (state.clients.data || []).map((c) => c.client_id === client.client_id ? client : c)
      }
    }));
    // Trigger background stats refresh
    void get().fetchStats(true);
  },

  deleteClientLocal: (clientId) => {
    set((state) => ({
      clients: {
        ...state.clients,
        data: (state.clients.data || []).filter((c) => c.client_id !== clientId)
      }
    }));
    // Trigger background stats refresh
    void get().fetchStats(true);
  }
}));
