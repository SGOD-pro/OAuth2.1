import type { Context, Next } from "hono";

import { config } from "../config";
import {
  getCachedOrigin,
  setCachedOrigin,
} from "../cache/origin-cache";
import { getDb } from "../db/mongo";
import { isLoopbackHost, normalizeOrigin, originMatchesRedirectUri, getTrustedClientIp } from "../utils/security";

const CORS_ALLOW_HEADERS =
  "Content-Type,Authorization,X-CSRF-Token,x-csrf-token";

export async function isOriginAllowed(origin: string): Promise<boolean> {
  const normalizedOrigin = normalizeOrigin(origin);
  if (!normalizedOrigin) {
    return false;
  }

  const database = await getDb();
  const clients = await database
    .collection("oauthClient")
    .find(
      {},
      { projection: { redirectUris: 1, allowedOrigins: 1 } },
    )
    .toArray();

  for (const client of clients) {
    const redirectUris = (client["redirectUris"] as string[] | undefined) ?? [];
    for (const uri of redirectUris) {
      if (originMatchesRedirectUri(normalizedOrigin, uri)) return true;
    }

    const allowedOrigins =
      (client["allowedOrigins"] as string[] | undefined) ?? [];
    for (const allowed of allowedOrigins) {
      if (allowed === normalizedOrigin) return true;
      // Also accept full URLs stored as "allowed origins"
      if (originMatchesRedirectUri(normalizedOrigin, allowed)) return true;
    }
  }

  return false;
}

function applyCorsHeaders(c: Context, origin: string) {
  c.header("Access-Control-Allow-Origin", origin);
  c.header("Access-Control-Allow-Credentials", "true");
  c.header(
    "Access-Control-Allow-Methods",
    "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  );
  c.header("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS);
}

function applyCorsHeadersToResponse(c: Context, origin: string) {
  c.res.headers.set("Access-Control-Allow-Origin", origin);
  c.res.headers.set("Access-Control-Allow-Credentials", "true");
  c.res.headers.set(
    "Access-Control-Allow-Methods",
    "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  );
  c.res.headers.set("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS);
}

// P1-8: In-memory rate limit for novel CORS origin DB lookups.
// Prevents an attacker from spraying unique Origin headers to force unbounded MongoDB queries.
// Limit: 30 novel uncached origin lookups per IP per 60 seconds.
const CORS_LOOKUP_LIMIT = 30;
const CORS_LOOKUP_WINDOW_MS = 60_000;
const corsLookupBuckets = new Map<string, { count: number; resetAt: number }>();

function checkCorsLookupRateLimit(ip: string): boolean {
  const now = Date.now();
  const bucket = corsLookupBuckets.get(ip);
  if (!bucket || now > bucket.resetAt) {
    corsLookupBuckets.set(ip, { count: 1, resetAt: now + CORS_LOOKUP_WINDOW_MS });
    return true; // allowed
  }
  bucket.count++;
  return bucket.count <= CORS_LOOKUP_LIMIT;
}

export async function dynamicCors(c: Context, next: Next) {
  const origin = c.req.header("origin");
  const ownFrontend = config.frontendUrl;
  const normalizedOrigin = origin ? normalizeOrigin(origin) : null;

  // Allow internal frontend (and same-origin / non-browser requests without Origin)
  // In development, also permit local loopback origins (localhost / 127.0.0.1)
  const isDevLoopback = config.env !== "production" && normalizedOrigin && isLoopbackHost(new URL(normalizedOrigin).hostname);
  if (!normalizedOrigin || normalizedOrigin === ownFrontend || isDevLoopback) {
    applyCorsHeaders(c, normalizedOrigin || ownFrontend);

    if (c.req.method === "OPTIONS") {
      return c.body(null, 204);
    }

    await next();
    applyCorsHeadersToResponse(c, normalizedOrigin || ownFrontend);
    return;
  }

  let allowed = await getCachedOrigin(normalizedOrigin);

  if (allowed === null) {
    // P1-8: Only perform the DB lookup if the IP hasn't exceeded the novel-origin rate limit
    const clientIp = getTrustedClientIp(c.req.raw.headers);
    if (!checkCorsLookupRateLimit(clientIp)) {
      // Treat as not allowed without hitting DB
      return c.json({ error: "Too many requests" }, 429);
    }

    try {
      allowed = await isOriginAllowed(normalizedOrigin);
      await setCachedOrigin(normalizedOrigin, allowed);
    } catch {
      allowed = false;
    }
  }

  applyCorsHeaders(c, normalizedOrigin);

  if (!allowed) {
    return c.json({ error: "Origin not allowed" }, 403);
  }

  if (c.req.method === "OPTIONS") {
    return c.body(null, 204);
  }

  await next();
  applyCorsHeadersToResponse(c, normalizedOrigin);
}
