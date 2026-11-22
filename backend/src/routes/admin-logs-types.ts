export interface NormalizedLogEntry {
  userId: string;
  userEmail: string | null;
  action: string;
  outcome: string | null;
  ipAddress: string | null;
  createdAt: string | null;
  appName?: string | null;
  applicationName?: string | null;
  clientId?: string | null;
  reason?: string | null;
  details?: Record<string, unknown> | null;
}

export interface AggregatedLogsParams {
  page: number;
  limit: number;
  outcome?: string | null;
  action?: string | null;
  clientId?: string | null;
  from?: Date | null;
  to?: Date | null;
  search?: string | null;
}

export interface AggregatedLogsResult {
  entries: NormalizedLogEntry[];
  totalCount: number;
  page: number;
  limit: number;
  totalPages: number;
}
