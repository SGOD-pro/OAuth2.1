import { normalizeOrigin } from "../utils/security";

export interface OriginCheckContext {
  origin: string;
  /**
   * Shared monotonic sequence version at the start of this check, sourced
   * from MongoDB's single authoritative counter. Never from independent Redis
   * counters or process wall clocks.
   */
  startVersion: number;
  /** @deprecated use startVersion; kept for wire compatibility */
  startTime: number;
}

export const lastInvalidatedVersion = new Map<string, number>();
const MAX_INVALIDATION_MAP_SIZE = 1000;

export function pruneInvalidatedVersion(): void {
  if (lastInvalidatedVersion.size > MAX_INVALIDATION_MAP_SIZE) {
    const excess = lastInvalidatedVersion.size - MAX_INVALIDATION_MAP_SIZE;
    let count = 0;
    for (const key of lastInvalidatedVersion.keys()) {
      lastInvalidatedVersion.delete(key);
      count++;
      if (count >= excess) break;
    }
  }
}

export function getInvalidationMapSizeForTesting(): number {
  return lastInvalidatedVersion.size;
}

export function clearInvalidationMapForTesting(): void {
  lastInvalidatedVersion.clear();
  setGlobalLastInvalidatedVersion(0);
}

export let globalLastInvalidatedVersion = 0;

export function setGlobalLastInvalidatedVersion(ver: number): void {
  globalLastInvalidatedVersion = ver;
}

export let redisOutageDetected = false;

export function setRedisOutageDetected(val: boolean): void {
  redisOutageDetected = val;
}

export function getRedisOutageDetected(): boolean {
  return redisOutageDetected;
}

export function setRedisOutageDetectedForTesting(val: boolean): void {
  redisOutageDetected = val;
}

export function getLastInvalidatedAt(origin: string): number {
  const norm = normalizeOrigin(origin) || origin;
  return Math.max(lastInvalidatedVersion.get(norm) || 0, globalLastInvalidatedVersion);
}

export let preRedisWriteHook: ((origin: string, allowed: boolean, version?: number) => Promise<void>) | null = null;
export let postMongoCheckHook: ((origin: string, allowed: boolean, version?: number) => Promise<void>) | null = null;

export function setPreRedisWriteHookForTesting(
  hook: ((origin: string, allowed: boolean, version?: number) => Promise<void>) | null,
): void {
  preRedisWriteHook = hook;
}

export function setPostMongoCheckHookForTesting(
  hook: ((origin: string, allowed: boolean, version?: number) => Promise<void>) | null,
): void {
  postMongoCheckHook = hook;
}
