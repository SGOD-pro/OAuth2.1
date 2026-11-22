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

export interface CacheState<T> {
  data: T | null;
  lastFetched: number;
  loading: boolean;
}

export interface CachedQueryResult {
  data: LogEntry[];
  totalCount: number;
  page: number;
  limit: number;
  totalPages: number;
  lastFetched: number;
}

export interface AdminStore {
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
