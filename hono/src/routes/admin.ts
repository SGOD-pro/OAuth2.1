import { Hono } from "hono";
import type { Context } from "hono";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { clearOriginCache } from "../cache/origin-cache";
import { validateRedirectUris } from "../utils/security";

const admin = new Hono();

type JsonObject = Record<string, unknown>;

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

  if (redirectUris.length === 0) {
    return c.json({ error: "At least one redirect_uri is required" }, 400);
  }

  if (allowedOrigins.length === 0) {
    return c.json({ error: "At least one allowed_origin is required" }, 400);
  }

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
      allowed_origins: allowedOrigins,
      skip_consent: (body.skip_consent as boolean) ?? false,
      enable_end_session: (body.enable_end_session as boolean) ?? true,
    },
  });

  const database = await getDb();
  await database.collection("oauthClient").updateOne(
    { clientId: result.client_id },
    { $set: { allowedOrigins } },
  );

  await clearOriginCache();

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
        ...(typeof body.client_name === "string" ? { client_name: body.client_name } : {}),
        ...(redirectUris ? { redirect_uris: redirectUris } : {}),
        ...(allowedOrigins ? { allowed_origins: allowedOrigins } : {}),
        ...(typeof body.skip_consent === "boolean" ? { skip_consent: body.skip_consent } : {}),
        ...(typeof body.enable_end_session === "boolean" ? { enable_end_session: body.enable_end_session } : {}),
        ...(typeof body.disabled === "boolean" ? { disabled: body.disabled } : {}),
        ...(typeof body.is_active === "boolean" ? { disabled: !body.is_active } : {}),
      },
    },
  });

  if (allowedOrigins !== null) {
    const database = await getDb();
    await database.collection("oauthClient").updateOne(
      { clientId: id },
      { $set: { allowedOrigins } },
    );
  }

  await clearOriginCache();

  return c.json(result);
});

admin.delete("/clients/:id", async (c) => {
  const id = c.req.param("id");

  const result = await authProvider.api.deleteOAuthClient({
    headers: getHeaders(c),
    body: { client_id: id },
  });

  await clearOriginCache();

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
    console.error({ event: "admin_stats_failed", error });
    return c.json({ error: "Failed to query stats" }, 500);
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
    console.error({ event: "admin_logs_failed", error });
    return c.json({ error: "Failed to query logs" }, 500);
  }
});

export default admin;
