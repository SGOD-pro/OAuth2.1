import {
  getOriginCache,
  putOriginCache,
  invalidateOriginCache,
} from "../db/dynamo";

export async function getCachedOrigin(
  origin: string,
): Promise<boolean | null> {
  return getOriginCache(origin);
}

export async function setCachedOrigin(
  origin: string,
  allowed: boolean,
): Promise<void> {
  await putOriginCache(origin, allowed);
}

export async function clearOriginCache(): Promise<void> {
  await invalidateOriginCache();
}

export async function invalidateOrigin(
  origin: string,
): Promise<void> {
  await invalidateOriginCache([origin]);
}