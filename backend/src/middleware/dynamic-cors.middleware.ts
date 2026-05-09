import { Injectable, NestMiddleware } from '@nestjs/common';
import { LRUCache } from 'lru-cache';
import type { Request, Response, NextFunction } from 'express';
import { MongoService } from '../database/mongo.service.js';

/**
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * Dynamic CORS Middleware
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Replaces hardcoded CORS. Checks incoming Origin against
 * allowedOrigins stored in MongoDB's oauthClient collection,
 * backed by an LRU cache with 5-minute TTL.
 *
 * Cache is invalidated when admin registers/updates a client
 * via the exported `clearOriginCache()` function.
 *
 * Why not rely only on OAuth Provider?
 *   The OAuth Provider validates origins for OAuth flows only.
 *   Preflight requests from consuming apps hitting the auth API
 *   directly (e.g., /api/auth/session) would be blocked without
 *   this middleware.
 */

// ── Origin cache (exported for CorsCacheService invalidation) ────
export const originCache = new LRUCache<string, boolean>({
  max: 500,
  ttl: 1000 * 60 * 5, // 5 minute TTL
});

/**
 * Call this when admin registers or updates a client.
 * Ensures new apps work immediately without waiting for TTL.
 */
export function clearOriginCache(): void {
  originCache.clear();
}

/**
 * Remove a specific origin from cache (fine-grained invalidation).
 */
export function invalidateOrigin(origin: string): void {
  originCache.delete(origin);
}

// ── Middleware ────────────────────────────────────────────────────
@Injectable()
export class DynamicCorsMiddleware implements NestMiddleware {
  constructor(private readonly mongo: MongoService) {}

  async use(req: Request, res: Response, next: NextFunction): Promise<void> {
    const origin = req.headers['origin'] as string | undefined;

    const ownFrontend = process.env.FRONTEND_URL || 'http://localhost:5173';
    if (!origin || origin === ownFrontend) {
      res.setHeader('Access-Control-Allow-Origin', origin || ownFrontend);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader(
        'Access-Control-Allow-Methods',
        'GET,POST,PUT,DELETE,OPTIONS',
      );
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type,Authorization',
      );
      if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
      }
      return next();
    }

    // Check cache first
    let allowed = originCache.get(origin);

    if (allowed === undefined) {
      // Cache miss — query MongoDB oauthClient collection
      // The OAuth Provider plugin stores clients in the 'oauthClient' collection.
      // We check if any active client has this origin in its redirect_uris
      // or if the origin matches the client's registered URI scheme+host.
      try {
        const client = await this.mongo
          .collection('oauthClient')
          .findOne({
            // OAuth Provider stores redirect URIs; we derive allowed origins
            // by checking if any redirect_uri starts with this origin.
            // This is a pragmatic approach since the plugin doesn't store
            // a separate allowedOrigins field.
            redirectUris: {
              $elemMatch: {
                $regex: `^${escapeRegex(origin)}`,
              },
            },
          });
        allowed = !!client;
      } catch {
        // DB error — fail open for own frontend, closed for others
        allowed = false;
      }
      originCache.set(origin, allowed);
    }

    if (!allowed) {
      res.status(403).json({ error: 'Origin not allowed' });
      return;
    }

    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET,POST,PUT,DELETE,OPTIONS',
    );
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type,Authorization',
    );

    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }

    return next();
  }
}

/**
 * Escape special regex characters in a string for safe use in $regex.
 * Prevents regex injection via malicious Origin headers.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
