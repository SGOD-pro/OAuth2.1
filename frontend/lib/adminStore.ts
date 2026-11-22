import { create } from 'zustand';
import { toast } from 'sonner';
import { apiFetch } from './api';
import type {
  Stats,
  OAuthClient,
  LogEntry,
  LogsQuery,
  AdminStore,
  CachedQueryResult,
} from './adminStore-types';
import {
  CACHE_TTL,
  logsCache,
  inFlightLogs,
  queryOwnership,
  incrementRequestId,
  incrementQuerySequence,
  getLatestRequestId,
  _resetAdminLogsCacheForTesting,
} from './adminStore-cache';

export * from './adminStore-types';
export { _resetAdminLogsCacheForTesting };

let inFlightStats: Promise<void> | null = null;
let inFlightClients: Promise<void> | null = null;

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

      incrementRequestId();

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

    const currentRequestId = incrementRequestId();
    set({ logs: { ...get().logs, loading: true, error: null } });

    let fetchPromise = inFlightLogs.get(queryKey);

    try {
      if (!fetchPromise || force) {
        const queryToken = incrementQuerySequence();
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

      if (currentRequestId === getLatestRequestId()) {
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
      if (currentRequestId === getLatestRequestId()) {
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
    void get().fetchStats(true);
  },

  updateClientLocal: (client) => {
    set((state) => ({
      clients: {
        ...state.clients,
        data: (state.clients.data || []).map((c) => c.client_id === client.client_id ? client : c)
      }
    }));
    void get().fetchStats(true);
  },

  deleteClientLocal: (clientId) => {
    set((state) => ({
      clients: {
        ...state.clients,
        data: (state.clients.data || []).filter((c) => c.client_id !== clientId)
      }
    }));
    void get().fetchStats(true);
  }
}));
