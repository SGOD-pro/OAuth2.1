import type { Context, Next } from "hono";

import { config } from "../config";
import {
  getCachedOrigin,
  setCachedOrigin,
} from "../cache/origin-cache";
import { getDb } from "../db/mongo";
import { normalizeOrigin, originMatchesRedirectUri } from "../utils/security";

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

export async function dynamicCors(c: Context, next: Next) {
  const origin = c.req.header("origin");
  const ownFrontend = config.frontendUrl;
  const normalizedOrigin = origin ? normalizeOrigin(origin) : null;

  // Allow internal frontend (and same-origin / non-browser requests without Origin)
  if (!normalizedOrigin || normalizedOrigin === ownFrontend) {
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
    try {
      allowed = await isOriginAllowed(normalizedOrigin);
      await setCachedOrigin(normalizedOrigin, allowed);
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
