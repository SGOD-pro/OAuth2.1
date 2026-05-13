import { Hono } from "hono";
import type { Context } from "hono";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { clearOriginCache } from "../cache/origin-cache";

const admin = new Hono();

type JsonObject = Record<string, unknown>;

function validateRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri);
    if (!['http:', 'https:'].includes(url.protocol)) return false;
    if (url.protocol === 'javascript:') return false;
    const privateRanges = [
      /^localhost/,
      /^127\./,
      /^10\./,
      /^192\.168\./,
      /^172\.(1[6-9]|2\d|3[01])\./,
    ];
    const isProduction = process.env.NODE_ENV === "production";
    if (isProduction && privateRanges.some((r) => r.test(url.hostname))) return false;
    if (uri.includes("*")) return false;
    return true;
  } catch {
    return false;
  }
}

function validateRedirectUris(uris: string[]): string | null {
  for (const uri of uris) {
    if (!validateRedirectUri(uri)) {
      return uri;
    }
  }

  return null;
}

function getHeaders(c: Context): Record<string, string> {
  return Object.fromEntries(c.req.raw.headers.entries());
}

admin.get("/clients", async (c) => {
  const result = await authProvider.api.getOAuthClients({
    headers: getHeaders(c),
  });

  return c.json(result);
});

admin.get("/clients/:id", async (c) => {
  const id = c.req.param("id");

  const result = await authProvider.api.getOAuthClient({
    headers: getHeaders(c),
    query: { client_id: id },
  });

  return c.json(result);
});

admin.post("/clients", async (c) => {
  let body: JsonObject | null = null;

  try {
    body = (await c.req.json()) as JsonObject;
  } catch {
    body = null;
  }

  if (!body || typeof body.client_name !== "string") {
    return c.json({ error: "Invalid request body" }, 400);
  }

  const redirectUris = Array.isArray(body.redirect_uris)
    ? (body.redirect_uris as string[])
    : [];
  const allowedOrigins = Array.isArray(body.allowed_origins)
    ? (body.allowed_origins as string[])
    : [];

  const invalidRedirectUri = validateRedirectUris(redirectUris);
  if (invalidRedirectUri) {
    return c.json({ error: `Invalid redirect_uri: ${invalidRedirectUri}` }, 400);
  }

  const invalidAllowedOrigin = validateRedirectUris(allowedOrigins);
  if (invalidAllowedOrigin) {
    return c.json({ error: `Invalid redirect_uri: ${invalidAllowedOrigin}` }, 400);
  }

  const result = await authProvider.api.adminCreateOAuthClient({
    headers: getHeaders(c),
    body: {
      client_name: body.client_name as string,
      redirect_uris: redirectUris,
      skip_consent: (body.skip_consent as boolean) ?? false,
      enable_end_session: (body.enable_end_session as boolean) ?? true,
    },
  });

  clearOriginCache();

  return c.json(result, 201);
});

admin.patch("/clients/:id", async (c) => {
  const id = c.req.param("id");
  let body: JsonObject | null = null;

  try {
    body = (await c.req.json()) as JsonObject;
  } catch {
    body = null;
  }

  if (!body) {
    return c.json({ error: "Invalid request body" }, 400);
  }

  const redirectUris = Array.isArray(body.redirect_uris)
    ? (body.redirect_uris as string[])
    : null;
  const allowedOrigins = Array.isArray(body.allowed_origins)
    ? (body.allowed_origins as string[])
    : null;

  if (redirectUris) {
    const invalidRedirectUri = validateRedirectUris(redirectUris);
    if (invalidRedirectUri) {
      return c.json({ error: `Invalid redirect_uri: ${invalidRedirectUri}` }, 400);
    }
  }

  if (allowedOrigins) {
    const invalidAllowedOrigin = validateRedirectUris(allowedOrigins);
    if (invalidAllowedOrigin) {
      return c.json({ error: `Invalid redirect_uri: ${invalidAllowedOrigin}` }, 400);
    }
  }

  const result = await authProvider.api.adminUpdateOAuthClient({
    headers: getHeaders(c),
    body: {
      client_id: id,
      update: {
        ...body,
      },
    },
  });

  clearOriginCache();

  return c.json(result);
});

admin.delete("/clients/:id", async (c) => {
  const id = c.req.param("id");

  const result = await authProvider.api.deleteOAuthClient({
    headers: getHeaders(c),
    body: { client_id: id },
  });

  clearOriginCache();

  return c.json(result);
});

admin.get("/stats", async (c) => {
  try {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const database = await getDb();

    const [totalUsers, totalClients, activeClients, recentLogins] =
      await Promise.all([
        database.collection("user").countDocuments(),
        database.collection("oauthClient").countDocuments(),
        database
          .collection("oauthClient")
          .countDocuments({ disabled: { $ne: true } }),
        database.collection("session").countDocuments({
          createdAt: { $gte: since24h },
        }),
      ]);

    return c.json({
      totalClients,
      activeClients,
      totalUsers,
      recentLogins,
    });
  } catch (error) {
    return c.json(
      { error: `Failed to query stats: ${String(error)}` },
      500,
    );
  }
});

admin.get("/logs", async (c) => {
  try {
    const database = await getDb();
    const sessions = await database
      .collection("session")
      .find({})
      .sort({ createdAt: -1 })
      .limit(100)
      .toArray();

    const userIds = [...new Set(sessions.map((s) => s["userId"]))].filter(Boolean);
    const users = await database
      .collection("user")
      .find({ _id: { $in: userIds } })
      .toArray();

    const userEmailMap = new Map(
      users.map((u) => [String(u["_id"]), u["email"]]),
    );

    const logs = sessions.map((s) => ({
      userId: s["userId"],
      userEmail: userEmailMap.get(String(s["userId"])) ?? null,
      action: "sign_in",
      ipAddress: s["ipAddress"] ?? null,
      createdAt: s["createdAt"],
    }));

    return c.json(logs);
  } catch (error) {
    return c.json(
      { error: `Failed to query logs: ${String(error)}` },
      500,
    );
  }
});

export default admin;