import { Injectable } from '@nestjs/common';
import { originCache } from '../middleware/dynamic-cors.middleware.js';

/**
 * CorsCacheService — provides controlled cache invalidation
 * for the DynamicCorsMiddleware origin allowlist.
 *
 * Injected into AdminController so that client mutations
 * (create, update, delete) immediately reflect new allowed origins
 * without waiting for the 5-minute LRU TTL to expire.
 */
@Injectable()
export class CorsCacheService {
  /**
   * Invalidate one specific origin (fine-grained) or the entire cache.
   *
   * @param origin — if provided, removes only that origin.
   *                 If omitted, clears all cached entries.
   */
  invalidate(origin?: string): void {
    if (origin) {
      originCache.delete(origin);
    } else {
      originCache.clear();
    }
  }
}
