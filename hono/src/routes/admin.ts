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
  try {
    const database = await getDb();
    const clients = await database.collection("oauthClient").find({}).toArray();

    const mapped = clients.map(client => ({
      id: String(client._id),
      client_id: client.clientId,
      client_name: client.name,
      client_secret: client.clientSecret,
      redirect_uris: client.redirectUris || [],
      disabled: client.disabled || false,
      skip_consent: client.skipConsent || false,
      enable_end_session: client.enableEndSession ?? true,
      metadata: {
        allowedOrigins: client.allowedOrigins || [],
      },
      adminUserId: client.adminUserId,
      adminEmail: client.adminEmail,
      createdAt: client.createdAt,
      updatedAt: client.updatedAt
    }));

    return c.json(mapped);
  } catch (error) {
    console.error({ event: "admin_get_clients_failed", error });
    return c.json({ error: "Failed to query clients" }, 500);
  }
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

  if (redirectUris?.length === 0) {
    return c.json({ error: "At least one redirect_uri is required" }, 400);
  }

  if (allowedOrigins?.length === 0) {
    return c.json({ error: "At least one allowed_origin is required" }, 400);
  }

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
  try {
    const id = c.req.param("id");
    console.log("Delete client requested for id:", id);
    const database = await getDb();
    
    const result = await database.collection("oauthClient").deleteOne({ clientId: id });
    console.log("Delete client result:", result);
    
    if (result.deletedCount === 0) {
      // Try to find if the client exists to debug
      const client = await database.collection("oauthClient").findOne({ clientId: id });
      console.log("Found client with this id?", !!client);
      return c.json({ error: "Client not found" }, 404);
    }

    await clearOriginCache();

    return c.json({ success: true });
  } catch (error) {
    console.error({ event: "admin_delete_client_failed", error });
    return c.json({ error: "Failed to delete client" }, 500);
  }
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

admin.post("/users", async (c) => {
  let body: JsonObject | null = null;
  try {
    body = (await c.req.json()) as JsonObject;
  } catch {
    body = null;
  }

  if (!body || typeof body.email !== "string" || typeof body.password !== "string" || typeof body.clientId !== "string") {
    return c.json({ error: "Invalid request body. Expected email, password, and clientId" }, 400);
  }

  try {
    // 1. Create the user using Better Auth API to ensure proper password hashing
    const signUpResult = await authProvider.api.signUpEmail({
      body: {
        email: body.email,
        password: body.password,
        name: typeof body.name === "string" ? body.name : "App Admin",
      },
      headers: c.req.raw.headers,
    });

    if (!signUpResult || !signUpResult.user) {
      console.error('Failed to create user via Auth Provider. Result:', signUpResult);
      return c.json({ error: "Failed to create user via Auth Provider" }, 500);
    }

    const userId = signUpResult.user.id;

    // 2. Update the user document to set role: "admin"
    const database = await getDb();
    await database.collection("user").updateOne(
      { _id: userId },
      { $set: { role: "admin" } }
    );

    // 3. Update the oauthClient document to set adminUserId and adminEmail
    await database.collection("oauthClient").updateOne(
      { clientId: body.clientId },
      { 
        $set: { 
          adminUserId: userId,
          adminEmail: body.email,
        } 
      }
    );

    return c.json({
      success: true,
      user: {
        id: userId,
        email: body.email,
        role: "admin",
      }
    });
  } catch (error) {
    console.error({ event: "admin_create_app_admin_failed", error });
    return c.json({ error: "Failed to provision app admin", details: error instanceof Error ? error.message : String(error) }, 500);
  }
});

export default admin;
