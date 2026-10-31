import type { Context, Next } from "hono";

import { config } from "../config";
import {
  getCachedOrigin,
  setCachedOrigin,
  startOriginCheck,
} from "../cache/origin-cache";
import { getDb } from "../db/mongo";
import { isLoopbackHost, normalizeOrigin, originMatchesRedirectUri, getTrustedClientIp } from "../utils/security";

const CORS_ALLOW_HEADERS =
  "Content-Type,Authorization,X-CSRF-Token,x-csrf-token";

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isOriginLoopback(originUrl: string): boolean {
  try {
    return isLoopbackHost(new URL(originUrl).hostname);
  } catch {
    return false;
  }
}

export async function isOriginAllowed(origin: string): Promise<boolean> {
  const normalizedOrigin = normalizeOrigin(origin);
  if (!normalizedOrigin) {
    return false;
  }

  const database = await getDb();
  // Anchored prefix regex with literal trailing slash and NO case-insensitive flag
  // ensures MongoDB can establish tight B-Tree index bounds: [ "https://example.com/", "https://example.com0" )
  // Note: OAuth 2.1 redirect URIs standardly require absolute URIs with a path component (such as /callback).
  // The query matches exact origins or anchored origin prefixes with a trailing slash to prevent subdomain and host confusion attacks.
  const originSlashPattern = new RegExp(`^${escapeRegex(normalizedOrigin)}/`);

  // Query using targeted $or filter matching allowedOrigins, allowed_origins, and redirect URIs
  // so MongoDB leverages compound indexes with tight B-tree index bounds
  const clients = await database
    .collection("oauthClient")
    .find(
      {
        disabled: { $ne: true },
        is_active: { $ne: false },
        isActive: { $ne: false },
        $or: [
          { allowedOrigins: normalizedOrigin },
          { allowed_origins: normalizedOrigin },
          { allowedOrigins: originSlashPattern },
          { allowed_origins: originSlashPattern },
          { redirectUris: normalizedOrigin },
          { redirect_uris: normalizedOrigin },
          { redirectUris: originSlashPattern },
          { redirect_uris: originSlashPattern },
        ],
      },
      { projection: { redirectUris: 1, redirect_uris: 1, allowedOrigins: 1, allowed_origins: 1, isDev: 1, is_dev: 1 } },
    )
    .toArray();

  const isProduction = config.env === "production";
  const allowDevInProd = config.allowDevClientsInProduction;
  const isLoopback = isOriginLoopback(normalizedOrigin);

  for (const client of clients) {
    // If running in production and origin is loopback, client MUST have isDev: true and allowDevInProd must be true
    const isDev = Boolean(client["isDev"] || client["is_dev"]);
    if (isProduction && isLoopback && (!isDev || !allowDevInProd)) {
      continue;
    }

    const redirectUris =
      (client["redirectUris"] as string[] | undefined) ??
      (client["redirect_uris"] as string[] | undefined) ??
      [];
    for (const uri of redirectUris) {
      if (originMatchesRedirectUri(normalizedOrigin, uri)) return true;
    }

    const allowedOrigins =
      (client["allowedOrigins"] as string[] | undefined) ??
      (client["allowed_origins"] as string[] | undefined) ??
      [];
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
  let isDevLoopback = false;
  if (normalizedOrigin && config.env !== "production") {
    isDevLoopback = isOriginLoopback(normalizedOrigin);
  }
  if (!normalizedOrigin || normalizedOrigin === ownFrontend || isDevLoopback) {
    applyCorsHeaders(c, normalizedOrigin || ownFrontend);

    if (c.req.method === "OPTIONS") {
      return c.body(null, 204);
    }

    await next();
    applyCorsHeadersToResponse(c, normalizedOrigin || ownFrontend);
    return;
  }

  const checkContext = await startOriginCheck(normalizedOrigin);
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
      await setCachedOrigin(normalizedOrigin, allowed, checkContext);
    } catch {
      allowed = false;
    }
  }

  if (!allowed) {
    return c.json({ error: "Origin not allowed" }, 403);
  }

  applyCorsHeaders(c, normalizedOrigin);

  if (c.req.method === "OPTIONS") {
    return c.body(null, 204);
  }

  await next();
  applyCorsHeadersToResponse(c, normalizedOrigin);
}
