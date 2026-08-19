import { create } from 'zustand';
import { toast } from 'sonner';
import { apiFetch } from './api';

export interface Stats {
  totalClients: number;
  activeClients: number;
  totalUsers: number;
  recentLogins: number;
}

export interface OAuthClient {
  client_id: string;
  client_name: string;
  // client_secret is intentionally NOT included — secrets are only returned once at creation
  // time (POST /clients response) and should never be fetched via list/detail endpoints.
  redirect_uris: string[];
  disabled: boolean;
  is_dev?: boolean;
  metadata?: {
    allowedOrigins?: string[];
    isDev?: boolean;
  };
  adminUserId?: string;
  adminEmail?: string;
  skip_consent: boolean;
  enable_end_session: boolean;
}

export interface LogEntry {
  userId: string;
  userEmail: string | null;
  action: string;
  ipAddress: string | null;
  createdAt: string;
}

export interface User {
  _id: string;
  email: string;
  name: string;
  role: string;
  createdAt: string;
}

interface CacheState<T> {
  data: T | null;
  lastFetched: number;
  loading: boolean;
}

interface AdminStore {
  stats: CacheState<Stats>;
  clients: CacheState<OAuthClient[]>;
  logs: CacheState<LogEntry[]>;
  users: CacheState<User[]>;
  
  fetchStats: (force?: boolean) => Promise<void>;
  fetchClients: (force?: boolean) => Promise<void>;
  fetchLogs: (force?: boolean) => Promise<void>;
  fetchUsers: (force?: boolean) => Promise<void>;
  
  // Optimistic mutations
  addClientLocal: (client: OAuthClient) => void;
  updateClientLocal: (client: OAuthClient) => void;
  deleteClientLocal: (clientId: string) => void;
  updateUserRoleLocal: (userId: string, role: string) => void;
}

const CACHE_TTL = 30_000; // 30 seconds

export const useAdminStore = create<AdminStore>((set, get) => ({
  stats: { data: null, lastFetched: 0, loading: false },
  clients: { data: null, lastFetched: 0, loading: false },
  logs: { data: null, lastFetched: 0, loading: false },
  users: { data: null, lastFetched: 0, loading: false },

  fetchStats: async (force = false) => {
    const { stats } = get();
    if (!force && stats.data && Date.now() - stats.lastFetched < CACHE_TTL) return;

    set({ stats: { ...get().stats, loading: true } });
    try {
      const res = await apiFetch('/api/admin/stats');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: Stats = await res.json();
      set({ stats: { data, lastFetched: Date.now(), loading: false } });
    } catch (err) {
      toast.error(`Failed to load stats: ${String(err)}`);
      set({ stats: { ...get().stats, loading: false } });
    }
  },

  fetchClients: async (force = false) => {
    const { clients } = get();
    if (!force && clients.data && Date.now() - clients.lastFetched < CACHE_TTL) return;

    set({ clients: { ...get().clients, loading: true } });
    try {
      const res = await apiFetch('/api/admin/clients');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: OAuthClient[] = await res.json();
      set({ clients: { data, lastFetched: Date.now(), loading: false } });
    } catch (err) {
      toast.error(String(err));
      set({ clients: { ...get().clients, loading: false } });
    }
  },

  fetchLogs: async (force = false) => {
    const { logs } = get();
    if (!force && logs.data && Date.now() - logs.lastFetched < CACHE_TTL) return;

    set({ logs: { ...get().logs, loading: true } });
    try {
      const res = await apiFetch('/api/admin/logs');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: LogEntry[] = await res.json();
      set({ logs: { data, lastFetched: Date.now(), loading: false } });
    } catch (err) {
      toast.error(`Failed to load logs: ${String(err)}`);
      set({ logs: { ...get().logs, loading: false } });
    }
  },

  fetchUsers: async (force = false) => {
    const { users } = get();
    if (!force && users.data && Date.now() - users.lastFetched < CACHE_TTL) return;

    set({ users: { ...get().users, loading: true } });
    try {
      const res = await apiFetch('/api/admin/users');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: User[] = await res.json();
      set({ users: { data, lastFetched: Date.now(), loading: false } });
    } catch (err) {
      toast.error(`Failed to load users: ${String(err)}`);
      set({ users: { ...get().users, loading: false } });
    }
  },

  addClientLocal: (client) => {
    set((state) => ({
      clients: {
        ...state.clients,
        data: [...(state.clients.data || []), client]
      }
    }));
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
  },

  updateUserRoleLocal: (userId, role) => {
    set((state) => ({
      users: {
        ...state.users,
        data: (state.users.data || []).map((u) => u._id === userId ? { ...u, role } : u)
      }
    }));
  }
}));
