import {
  getOriginCache,
  putOriginCache,
  invalidateOriginCache,
} from "../db/state";
import {
  getCachedOriginRedis,
  setCachedOriginRedis,
  invalidateCachedOriginRedis,
} from "./redis";

export async function getCachedOrigin(
  origin: string,
): Promise<boolean | null> {
  // 1. Check Redis first (fast REST / memory)
  const redisVal = await getCachedOriginRedis(origin);
  if (redisVal !== null) {
    return redisVal;
  }

  // 2. Fall back to MongoDB cache collection
  return getOriginCache(origin);
}

export async function setCachedOrigin(
  origin: string,
  allowed: boolean,
): Promise<void> {
  await Promise.all([
    setCachedOriginRedis(origin, allowed),
    putOriginCache(origin, allowed),
  ]);
}

export async function clearOriginCache(): Promise<void> {
  await Promise.all([
    invalidateCachedOriginRedis(),
    invalidateOriginCache(),
  ]);
}

export async function invalidateOrigin(
  origin: string,
): Promise<void> {
  await Promise.all([
    invalidateCachedOriginRedis([origin]),
    invalidateOriginCache([origin]),
  ]);
}
