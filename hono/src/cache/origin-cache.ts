import { LRUCache } from "lru-cache";

export const originCache =
  new LRUCache<string, boolean>({
    max: 1000,
    ttl: 1000 * 60 * 5,
  });

export function clearOriginCache() {
  originCache.clear();
}

export function invalidateOrigin(
  origin: string
) {
  originCache.delete(origin);
}