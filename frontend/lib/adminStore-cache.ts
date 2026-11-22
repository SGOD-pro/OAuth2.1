import type { CachedQueryResult, LogEntry } from './adminStore-types';

export const CACHE_TTL = 30_000; // 30 seconds

export const logsCache = new Map<string, CachedQueryResult>();
export const inFlightLogs = new Map<string, Promise<{
  data: LogEntry[];
  totalCount: number;
  page: number;
  limit: number;
  totalPages: number;
}>>();
export const queryOwnership = new Map<string, number>();

export let latestLogRequestId = 0;
export let latestLogQuerySequence = 0;

export function incrementRequestId(): number {
  return ++latestLogRequestId;
}

export function incrementQuerySequence(): number {
  return ++latestLogQuerySequence;
}

export function getLatestRequestId(): number {
  return latestLogRequestId;
}

export function _resetAdminLogsCacheForTesting() {
  logsCache.clear();
  inFlightLogs.clear();
  queryOwnership.clear();
  latestLogRequestId = 0;
  latestLogQuerySequence = 0;
}
