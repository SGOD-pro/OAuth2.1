import { Hono } from "hono";
import crypto from "crypto";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { getHeaders, isStrongPassword, validateRedirectUris, getTrustedClientIp } from "../utils/security";
import { invalidateOriginCache, recordAdminAudit } from "../db/state";
import { requireAdmin, requireSuperAdmin, requireScopedAdmin } from "../middleware/admin-auth";
import { adminProvisionRateLimit } from "../middleware/rate-limit";
import { ObjectId } from "mongodb";
import { hashPassword } from "better-auth/crypto";

// Helper accessor for Better Auth dynamic plugin APIs
const authApi = authProvider.api as any;

export const admin = new Hono<{
  Variables: {
    user: any;
    session: any;
    scopedClientId: string | null;
  };
}>();

// -- Super-Admin Only Routes ---------------------------------------------

// 1. List All OAuth Clients (Super-Admin or Scoped-Admin)
admin.get("/clients", requireAdmin, async (c) => {
  try {
    const database = await getDb();
    const sessionUser = c.get("user") as any;
    const scopedClientId = sessionUser?.scopedClientId;

    const query = scopedClientId
      ? { $or: [{ clientId: scopedClientId }, { client_id: scopedClientId }, { id: scopedClientId }] }
      : {};

    const clients = await database.collection("oauthClient").find(query).toArray();
    const safeClients = clients.map((doc: any) => {
      const { clientSecret, client_secret, _id, ...rest } = doc;
      return {
        ...rest,
        client_id: rest.clientId || rest.client_id || rest.id || String(_id),
        client_name: rest.name || rest.client_name || "Application",
        redirect_uris: rest.redirectUris || rest.redirect_uris || [],
        allowed_origins: rest.allowedOrigins || rest.allowed_origins || [],
        disabled: Boolean(rest.disabled),
        is_dev: Boolean(rest.isDev || rest.is_dev),
        skip_consent: Boolean(rest.skipConsent || rest.skip_consent),
        adminEmail: rest.adminEmail || rest.admin_email || null,
        adminUserId: rest.adminUserId || rest.admin_user_id || null,
      };
    });
    return c.json(safeClients);
  } catch (err: any) {
    console.error("[ADMIN_CLIENTS] Error listing clients:", err);
    return c.json({ error: "Failed to fetch clients" }, 500);
  }
});

// 2. Create OAuth Client (Super-Admin only)
admin.post("/clients", requireSuperAdmin, async (c) => {
  const body = await c.req.json();
  const sessionUser = c.get("user") as any;

  const isDev = Boolean(body.isDev || body.is_dev);
  const clientName = (body.name || body.client_name || "").trim();
  if (!clientName) {
    return c.json({ error: "Application name is required" }, 400);
  }

  const redirectUris = (body.redirect_uris || body.redirectUris || []) as string[];
  const allowedOrigins = (body.allowed_origins || body.allowedOrigins || []) as string[];

  if (redirectUris.length === 0) {
    return c.json({ error: "At least one redirect URI is required" }, 400);
  }

  if (allowedOrigins.length === 0) {
    return c.json({ error: "At least one allowed origin is required" }, 400);
  }

  const invalidUri = validateRedirectUris(redirectUris, { isDev });
  if (invalidUri) {
    return c.json({
      error: `Invalid redirect URI: "${invalidUri}". In production, non-HTTPS URLs are only permitted on loopback addresses (localhost, 127.0.0.1) when Development Mode is enabled.`,
    }, 400);
  }

  const invalidOrigin = validateRedirectUris(allowedOrigins, { isDev });
  if (invalidOrigin) {
    return c.json({
      error: `Invalid allowed origin: "${invalidOrigin}". In production, non-HTTPS origins are only permitted on loopback addresses (localhost, 127.0.0.1) when Development Mode is enabled.`,
    }, 400);
  }

  // Determine application_type:
  // If redirect_uris contain loopback (localhost, 127.0.0.1, [::1]) or if isDev is enabled,
  // Better Auth mandates application_type: "native" because RFC 8252 requires loopback redirect URIs to be native.
  // "web" strictly forbids loopback redirect URIs.
  const hasLoopback = redirectUris.some((uri) => {
    try {
      const u = new URL(uri);
      return (
        u.hostname === "localhost" ||
        u.hostname === "127.0.0.1" ||
        u.hostname === "[::1]" ||
        u.protocol === "http:"
      );
    } catch {
      return false;
    }
  });

  const applicationType = body.application_type || ((isDev || hasLoopback) ? "native" : "web");

  const createBody: any = {
    client_name: clientName,
    redirect_uris: redirectUris,
    application_type: applicationType,
    skip_consent: Boolean(body.skip_consent ?? body.skipConsent),
    enable_end_session: body.enable_end_session !== false && body.enableEndSession !== false,
    metadata: {
      allowedOrigins,
      isDev,
    },
  };

  let result: any = null;
  try {
    result = await authApi.adminCreateOAuthClient({
      headers: getHeaders(c),
      body: createBody,
    });
  } catch (err: any) {
    console.error("[ADMIN_CREATE_CLIENT] Better-Auth error:", err.body || err.message);
    const msg = err.body?.error_description || err.body?.error || err.message || "Failed to create OAuth client";
    const statusCode = typeof err.statusCode === "number" ? err.statusCode : (err.status === "BAD_REQUEST" ? 400 : 500);
    return c.json({ error: msg }, statusCode as any);
  }

  if (!result) {
    return c.json({ error: "Failed to create client" }, 500);
  }

  const clientId = result.client_id || result.clientId || result.id;

  // Persist extra fields in MongoDB oauthClient collection
  const database = await getDb();
  await database.collection("oauthClient").updateOne(
    { $or: [{ clientId }, { id: clientId }, { client_id: clientId }] },
    {
      $set: {
        allowedOrigins,
        isDev,
        skipConsent: Boolean(body.skip_consent ?? body.skipConsent),
        enableEndSession: body.enable_end_session !== false && body.enableEndSession !== false,
        updatedAt: new Date(),
      },
    },
  );

  if (allowedOrigins.length > 0) {
    await invalidateOriginCache(allowedOrigins);
  }

  await recordAdminAudit({
    actorUserId: sessionUser?.id,
    actorEmail: sessionUser?.email,
    actorScope: sessionUser?.scopedClientId || "super_admin",
    action: "client_created",
    targetClientId: String(clientId),
    details: { name: clientName, client_id: clientId },
    ipAddress: getTrustedClientIp(c),
    timestamp: new Date(),
  });

  const responsePayload = {
    ...result,
    client_id: clientId,
    client_secret: result.client_secret || result.clientSecret,
    client_name: clientName,
    redirect_uris: redirectUris,
    allowed_origins: allowedOrigins,
    is_dev: isDev,
    skip_consent: Boolean(body.skip_consent ?? body.skipConsent),
    enable_end_session: body.enable_end_session !== false && body.enableEndSession !== false,
  };

  return c.json(responsePayload, 201);
});

// 3. Platform Stats (Super-Admin only)
admin.get("/stats", requireAdmin, async (c) => {
  try {
    const database = await getDb();
    const sessionUser = c.get("user") as any;
    const scopedClientId = sessionUser?.scopedClientId;

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const clientQuery = scopedClientId
      ? { $or: [{ clientId: scopedClientId }, { client_id: scopedClientId }, { id: scopedClientId }] }
      : {};

    const [totalUsers, totalClients, activeClients, recent24hLogins, activeSessions, recentLogs] = await Promise.all([
      scopedClientId ? 1 : database.collection("user").countDocuments(),
      database.collection("oauthClient").countDocuments(clientQuery),
      database.collection("oauthClient").countDocuments({ ...clientQuery, disabled: { $ne: true } }),
      database.collection("session").countDocuments({ createdAt: { $gte: oneDayAgo } }),
      database.collection("session").countDocuments({ expiresAt: { $gt: new Date() } }),
      database.collection("session").find().sort({ createdAt: -1 }).limit(10).toArray(),
    ]);

    return c.json({
      totalUsers,
      totalClients,
      activeClients: activeClients || totalClients,
      recentLogins: recent24hLogins || activeSessions || 1,
      activeSessions,
      recentActivity: recentLogs.map((log: any) => ({
        id: log.id || log._id?.toString(),
        type: "session_created",
        userId: log.userId,
        ipAddress: log.ipAddress || "Unknown",
        userAgent: log.userAgent ? log.userAgent.split(" ")[0] : "Unknown",
        timestamp: log.createdAt || log.updatedAt,
      })),
    });
  } catch (err) {
    console.error("[ADMIN_STATS] Error fetching stats:", err);
    return c.json({ error: "Failed to fetch stats" }, 500);
  }
});

// 4. Audit & Activity Logs (Super-Admin only)
admin.get("/logs", requireSuperAdmin, async (c) => {
  try {
    const database = await getDb();
    const [sessions, audits, userDocs] = await Promise.all([
      database.collection("session").find().sort({ createdAt: -1 }).limit(50).toArray(),
      database.collection("admin_audit").find().sort({ timestamp: -1 }).limit(50).toArray(),
      database.collection("user").find({}).toArray(),
    ]);

    const userMap = new Map<string, string>();
    userDocs.forEach((u: any) => {
      if (u.email) {
        userMap.set(String(u._id), u.email);
        if (u.id) userMap.set(String(u.id), u.email);
      }
    });

    const sessionLogs = sessions.map((s: any) => ({
      userId: String(s.userId || s._id),
      userEmail: userMap.get(String(s.userId)) || s.userId || "Active Session",
      action: "user_sign_in",
      ipAddress: s.ipAddress || "127.0.0.1",
      createdAt: s.createdAt ? new Date(s.createdAt).toISOString() : new Date().toISOString(),
    }));

    const auditLogs = audits.map((a: any) => ({
      userId: String(a.actorUserId || "system"),
      userEmail: a.actorEmail || userMap.get(String(a.actorUserId)) || (a.actorUserId ? String(a.actorUserId) : "Security Engine"),
      action: a.action || "admin_audit",
      ipAddress: a.ipAddress || "127.0.0.1",
      createdAt: a.timestamp ? new Date(a.timestamp).toISOString() : new Date().toISOString(),
    }));

    const combined = [...sessionLogs, ...auditLogs].sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );

    return c.json(combined);
  } catch (err) {
    console.error("[ADMIN_LOGS] Error fetching logs:", err);
    return c.json([], 200);
  }
});

// 5. Delete OAuth Client (Super-Admin only)
admin.delete("/clients/:id", requireSuperAdmin, async (c) => {
  const id = c.req.param("id");
  const sessionUser = c.get("user") as any;
  const database = await getDb();

  const existingClient = await database.collection("oauthClient").findOne({
    $or: [{ clientId: id }, { client_id: id }, { id }],
  });

  if (!existingClient) {
    return c.json({ error: "Client not found" }, 404);
  }

  // Invalidate origin cache
  const allowedOrigins = existingClient.allowedOrigins || existingClient.allowed_origins || [];
  if (Array.isArray(allowedOrigins) && allowedOrigins.length > 0) {
    await invalidateOriginCache(allowedOrigins as string[]);
  }

  // Attempt Better Auth delete if user ownership matches, but catch if it throws 401 UNAUTHORIZED
  // (Better Auth's deleteOAuthClient is an end-user endpoint checking client.userId === session.user.id.
  // A Super-Admin has global authority to delete any application).
  try {
    await authApi.deleteOAuthClient({
      headers: getHeaders(c),
      body: { client_id: id },
    });
  } catch (err: any) {
    console.warn(
      `[ADMIN_DELETE_CLIENT] Better Auth deleteOAuthClient skipped (${err?.body?.error || err?.message || err?.status}), proceeding with Super-Admin database deletion.`
    );
  }

  // Delete all traces of client and associated tokens/sessions
  await Promise.all([
    database.collection("oauthClient").deleteMany({
      $or: [{ clientId: id }, { client_id: id }, { id }],
    }),
    database.collection("user_app_registrations").deleteMany({ clientId: id }),
    database.collection("oauthAccessToken").deleteMany({ clientId: id }),
    database.collection("oauthRefreshToken").deleteMany({ clientId: id }),
    database.collection("oauthAuthorizationCode").deleteMany({ clientId: id }),
    database.collection("oauth_token_families").deleteMany({ clientId: id }),
  ]);

  await recordAdminAudit({
    actorUserId: sessionUser?.id,
    actorEmail: sessionUser?.email,
    actorScope: sessionUser?.scopedClientId || "super_admin",
    action: "client_deleted",
    targetClientId: id,
    ipAddress: getTrustedClientIp(c),
    timestamp: new Date(),
  });

  return c.json({ success: true, message: "Client deleted successfully" });
});

// 6. Provision Scoped or Global Admin (Super-Admin only with Rate Limiting B6)
admin.post("/users", adminProvisionRateLimit, requireSuperAdmin, async (c) => {
  const body = await c.req.json();
  const sessionUser = c.get("user") as any;

  if (!body.email || typeof body.email !== "string") {
    return c.json({ error: "Valid email is required" }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const name = body.name || email.split("@")[0];
  const scopedClientId = body.clientId || body.scopedClientId || null;

  // Generate secure random temp password if not provided
  let password = body.password;
  let isTempPassword = false;
  if (!password) {
    password = crypto.randomBytes(12).toString("base64url") + "!Aa1";
    isTempPassword = true;
  } else {
    if (!isStrongPassword(password)) {
      return c.json(
        {
          error: "weak_password",
          message: "Password must be at least 12 characters and include uppercase, lowercase, number, and special character.",
        },
        400
      );
    }
  }

  try {
    const database = await getDb();
    const existing = await database.collection("user").findOne({ email });
    if (existing) {
      return c.json({ error: "User with this email already exists" }, 409);
    }

    // 1. Create base user in Better Auth
    const newUser = await authApi.signUpEmail({
      body: { email, password, name },
    });

    const userId = newUser?.user?.id || (newUser as any)?.id;

    // 2. Set role: "admin", scopedClientId, emailVerified: true, and mustChangePassword
    await database.collection("user").updateOne(
      { $or: [{ id: userId }, { _id: userId }, { email }] } as any,
      {
        $set: {
          role: "admin",
          emailVerified: true,
          scopedClientId: scopedClientId,
          mustChangePassword: isTempPassword,
          updatedAt: new Date(),
        },
      }
    );

    // 3. If assigned to a client, link to oauthClient document
    if (scopedClientId) {
      await database.collection("oauthClient").updateOne(
        { $or: [{ clientId: scopedClientId }, { client_id: scopedClientId }, { id: scopedClientId }] },
        {
          $set: {
            adminUserId: String(userId),
            adminEmail: email,
            updatedAt: new Date(),
          },
        }
      );
    }

    // 4. Record audit trail
    await recordAdminAudit({
      actorUserId: sessionUser?.id,
      actorEmail: sessionUser?.email,
      actorScope: sessionUser?.scopedClientId || "super_admin",
      action: "admin_provisioned",
      targetUserId: String(userId),
      targetClientId: scopedClientId || undefined,
      details: { email, scopedClientId, isTempPassword },
      ipAddress: getTrustedClientIp(c),
      timestamp: new Date(),
    });

    return c.json({
      success: true,
      user: {
        id: userId,
        email,
        name,
        role: "admin",
        scopedClientId,
        tempPassword: isTempPassword ? password : null,
        mustChangePassword: isTempPassword,
      },
    });
  } catch (err: any) {
    console.error("[ADMIN_PROVISION] Error creating admin user:", err);
    return c.json({ error: err?.message || "Failed to provision admin user" }, 500);
  }
});

// 6b. List All Users (Super-Admin only)
admin.get("/users", requireSuperAdmin, async (c) => {
  try {
    const database = await getDb();
    const users = await database.collection("user").find({}).sort({ createdAt: -1 }).toArray();
    const safeUsers = users.map((u: any) => ({
      _id: u._id?.toString() || u.id,
      email: u.email,
      name: u.name || u.email?.split("@")[0] || "User",
      role: u.role || "user",
      scopedClientId: u.scopedClientId || null,
      createdAt: u.createdAt || new Date(),
    }));
    return c.json(safeUsers);
  } catch (err: any) {
    console.error("[ADMIN_USERS] Error listing users:", err);
    return c.json({ error: "Failed to fetch users" }, 500);
  }
});

// -- Scoped-Admin & Super-Admin Routes -----------------------------------

// 7. Get OAuth Client by ID (Super-Admin or Assigned Scoped-Admin)
admin.get("/clients/:id", requireScopedAdmin, async (c) => {
  const id = c.req.param("id");

  try {
    const database = await getDb();
    const clientDoc = await database.collection("oauthClient").findOne({
      $or: [{ id }, { clientId: id }, { client_id: id }],
    });

    if (!clientDoc) return c.json({ error: "Client not found" }, 404);

    const { clientSecret, client_secret, _id, ...rest } = clientDoc;
    return c.json({
      ...rest,
      client_id: rest.clientId || rest.client_id || rest.id || String(_id),
      client_name: rest.name || rest.client_name || "Application",
      redirect_uris: rest.redirectUris || rest.redirect_uris || [],
      allowed_origins: rest.allowedOrigins || rest.allowed_origins || [],
      disabled: Boolean(rest.disabled),
      is_dev: Boolean(rest.isDev || rest.is_dev),
      skip_consent: Boolean(rest.skipConsent || rest.skip_consent),
    });
  } catch (err: any) {
    return c.json({ error: "Client not found" }, 404);
  }
});

// 8. Patch OAuth Client by ID (Super-Admin or Assigned Scoped-Admin)
admin.patch("/clients/:id", requireScopedAdmin, async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json();
  const sessionUser = c.get("user") as any;

  // Prevent scoped admins from modifying client_id or ownership
  delete body.client_id;
  delete body.id;
  delete body.userId;

  let oldClient: any = null;
  try {
    oldClient = await authApi.getOAuthClient({
      headers: getHeaders(c),
      query: { client_id: id },
    });
  } catch {}

  const isDev = Boolean(body.isDev ?? body.is_dev ?? oldClient?.isDev ?? oldClient?.is_dev);

  const redirectUris = (body.redirect_uris || body.redirectUris) as string[] | undefined;
  const allowedOrigins = (body.allowed_origins || body.allowedOrigins) as string[] | undefined;

  if (Array.isArray(redirectUris)) {
    if (redirectUris.length === 0) {
      return c.json({ error: "At least one redirect URI is required" }, 400);
    }
    const invalidUri = validateRedirectUris(redirectUris, { isDev });
    if (invalidUri) {
      return c.json({
        error: `Invalid redirect URI: "${invalidUri}". In production, non-HTTPS URLs are only permitted on loopback addresses (localhost, 127.0.0.1) when Development Mode is enabled.`,
      }, 400);
    }
  }

  if (Array.isArray(allowedOrigins)) {
    if (allowedOrigins.length === 0) {
      return c.json({ error: "At least one allowed origin is required" }, 400);
    }
    const invalidOrigin = validateRedirectUris(allowedOrigins, { isDev });
    if (invalidOrigin) {
      return c.json({
        error: `Invalid allowed origin: "${invalidOrigin}". In production, non-HTTPS origins are only permitted on loopback addresses (localhost, 127.0.0.1) when Development Mode is enabled.`,
      }, 400);
    }
  }

  const hasLoopback = redirectUris?.some((uri) => {
    try {
      const u = new URL(uri);
      return (
        u.hostname === "localhost" ||
        u.hostname === "127.0.0.1" ||
        u.hostname === "[::1]" ||
        u.protocol === "http:"
      );
    } catch {
      return false;
    }
  });

  const applicationType = body.application_type || ((isDev || hasLoopback) ? "native" : (redirectUris ? "web" : undefined));

  const updatePayload: any = {};
  if (typeof body.client_name === "string") updatePayload.client_name = body.client_name;
  if (typeof body.name === "string") updatePayload.client_name = body.name;
  if (redirectUris) updatePayload.redirect_uris = redirectUris;
  if (applicationType) updatePayload.application_type = applicationType;
  if (typeof body.skip_consent === "boolean") updatePayload.skip_consent = body.skip_consent;
  if (typeof body.skipConsent === "boolean") updatePayload.skip_consent = body.skipConsent;
  if (typeof body.enable_end_session === "boolean") updatePayload.enable_end_session = body.enable_end_session;
  if (typeof body.enableEndSession === "boolean") updatePayload.enable_end_session = body.enableEndSession;
  if (typeof body.disabled === "boolean") updatePayload.disabled = body.disabled;
  if (typeof body.is_active === "boolean") updatePayload.disabled = !body.is_active;

  let result: any = null;
  try {
    result = await authApi.adminUpdateOAuthClient({
      headers: getHeaders(c),
      body: { client_id: id, update: updatePayload },
    });
  } catch (err: any) {
    console.warn("[ADMIN_PATCH_CLIENT] Better-Auth update error, proceeding with direct DB update:", err?.body || err?.message);
  }

  // Fallback / sync direct update to DB for custom fields (allowedOrigins, isDev, etc.)
  const database = await getDb();
  const dbUpdates: any = { updatedAt: new Date() };
  if (allowedOrigins) dbUpdates.allowedOrigins = allowedOrigins;
  if (typeof (body.isDev ?? body.is_dev) === "boolean") dbUpdates.isDev = isDev;
  if (typeof updatePayload.skip_consent === "boolean") dbUpdates.skipConsent = updatePayload.skip_consent;
  if (typeof updatePayload.enable_end_session === "boolean") dbUpdates.enableEndSession = updatePayload.enable_end_session;
  if (typeof updatePayload.disabled === "boolean") dbUpdates.disabled = updatePayload.disabled;
  if (redirectUris) dbUpdates.redirectUris = redirectUris;
  if (applicationType) dbUpdates.applicationType = applicationType;
  if (updatePayload.client_name) dbUpdates.name = updatePayload.client_name;

  await database.collection("oauthClient").updateOne(
    { $or: [{ clientId: id }, { client_id: id }, { id }] },
    { $set: dbUpdates }
  );
  const updatedDoc = await database.collection("oauthClient").findOne({
    $or: [{ clientId: id }, { client_id: id }, { id }],
  });

  if (!result && !updatedDoc) return c.json({ error: "Client not found" }, 404);

  // Invalidate CORS origin cache for updated origins
  const originsToInvalidate = new Set<string>();
  if (oldClient && Array.isArray(oldClient.allowed_origins)) {
    oldClient.allowed_origins.forEach((o: string) => originsToInvalidate.add(o));
  }
  if (Array.isArray(allowedOrigins)) {
    allowedOrigins.forEach((o: string) => originsToInvalidate.add(o));
  }
  if (originsToInvalidate.size > 0) {
    await invalidateOriginCache(Array.from(originsToInvalidate));
  }

  // Token revocation on client disable
  if (body.disabled === true || body.is_active === false) {
    await Promise.all([
      database.collection("oauthAccessToken").deleteMany({ clientId: id }),
      database.collection("oauthRefreshToken").deleteMany({ clientId: id }),
      database.collection("oauthAuthorizationCode").deleteMany({ clientId: id }),
      database.collection("oauth_token_families").deleteMany({ clientId: id }),
    ]);
  }

  await recordAdminAudit({
    actorUserId: sessionUser?.id,
    actorEmail: sessionUser?.email,
    actorScope: sessionUser?.scopedClientId || "super_admin",
    action: "client_patched",
    targetClientId: id,
    details: { modifiedFields: Object.keys(body) },
    ipAddress: getTrustedClientIp(c),
    timestamp: new Date(),
  });

  const finalResult = {
    ...(result || {}),
    ...(updatedDoc || {}),
    client_id: updatedDoc?.clientId || id,
    client_name: updatedDoc?.name || result?.client_name || "Application",
    redirect_uris: updatedDoc?.redirectUris || redirectUris || [],
    allowed_origins: updatedDoc?.allowedOrigins || allowedOrigins || [],
    disabled: Boolean(updatedDoc?.disabled),
    is_dev: Boolean(updatedDoc?.isDev),
    skip_consent: Boolean(updatedDoc?.skipConsent),
    enable_end_session: Boolean(updatedDoc?.enableEndSession ?? true),
  };

  const { client_secret: _omit, clientSecret: _omit2, _id: _omit3, ...safeResult } = finalResult as any;
  return c.json(safeResult);
});

// 9. Dedicated Scoped Application Configuration Routes
admin.get("/app/:clientId/config", requireScopedAdmin, async (c) => {
  const clientId = c.req.param("clientId");
  try {
    const result = (await authApi.getOAuthClient({
      headers: getHeaders(c),
      query: { client_id: clientId },
    })) as Record<string, unknown> | null;

    if (!result) return c.json({ error: "Application not found" }, 404);
    const { client_secret: _omit, ...safeResult } = result as { client_secret?: unknown } & Record<string, unknown>;
    return c.json(safeResult);
  } catch {
    return c.json({ error: "Application not found or unauthorized" }, 404);
  }
});

admin.patch("/app/:clientId/config", requireScopedAdmin, async (c) => {
  const clientId = c.req.param("clientId");
  const body = await c.req.json();
  const sessionUser = c.get("user") as any;

  delete body.client_id;
  delete body.id;

  let result: any = null;
  try {
    result = await authApi.updateOAuthClient({
      headers: getHeaders(c),
      body: { client_id: clientId, update: body },
    });
  } catch {
    const database = await getDb();
    await database.collection("oauthClient").updateOne(
      { client_id: clientId },
      { $set: { ...body, updatedAt: new Date() } }
    );
    result = await database.collection("oauthClient").findOne({ client_id: clientId });
  }

  if (!result) return c.json({ error: "Application not found" }, 404);

  await recordAdminAudit({
    actorUserId: sessionUser?.id,
    actorEmail: sessionUser?.email,
    actorScope: sessionUser?.scopedClientId || "super_admin",
    action: "scoped_app_config_patched",
    targetClientId: clientId,
    details: { modifiedFields: Object.keys(body) },
    ipAddress: getTrustedClientIp(c),
    timestamp: new Date(),
  });

  const { client_secret: _omit, ...safeResult } = result as { client_secret?: unknown } & Record<string, unknown>;
  return c.json(safeResult);
});

// -- Application Administrators Management (Super Admin) ------------------

// 10. List Application Admins for a Client
admin.get("/clients/:clientId/app-admins", requireSuperAdmin, async (c) => {
  const clientId = c.req.param("clientId");
  try {
    const database = await getDb();
    const admins = await database
      .collection("app_admins")
      .find({ clientId })
      .sort({ createdAt: -1 })
      .toArray();

    const safeAdmins = admins.map((a: any) => ({
      id: a._id.toString(),
      email: a.email,
      name: a.name || a.email.split("@")[0],
      redirectUrl: a.redirectUrl || "",
      isActive: a.isActive !== false,
      loginCount: a.loginCount || 0,
      lastLoginAt: a.lastLoginAt ? a.lastLoginAt.toISOString() : null,
      createdAt: a.createdAt ? a.createdAt.toISOString() : new Date().toISOString(),
    }));

    return c.json({ admins: safeAdmins });
  } catch (err: any) {
    console.error("[ADMIN_LIST_APP_ADMINS] Error:", err);
    return c.json({ error: "Failed to load application administrators" }, 500);
  }
});

// Helper: Validate that an app admin redirectUrl matches one of the client's registered origins or redirect URIs
function isRedirectUrlAllowedForClient(redirectUrl: string, client: any): { allowed: boolean; error?: string } {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(redirectUrl);
  } catch {
    return { allowed: false, error: "Redirect URL must be a valid URL format (e.g. https://app.example.com/admin)" };
  }

  const isDev = Boolean(client.isDev || client.is_dev);
  const isLoopback = parsedUrl.hostname === "localhost" || parsedUrl.hostname === "127.0.0.1" || parsedUrl.hostname === "[::1]";

  if (isDev && isLoopback) {
    return { allowed: true };
  }

  const clientOrigins = new Set<string>();
  const allowedOrigins = ((client.allowedOrigins || client.allowed_origins || []) as string[]);
  const redirectUris = ((client.redirectUris || client.redirect_uris || []) as string[]);

  for (const o of allowedOrigins) {
    try {
      clientOrigins.add(new URL(o).origin);
    } catch {
      clientOrigins.add(o.replace(/\/$/, ""));
    }
  }

  for (const u of redirectUris) {
    try {
      clientOrigins.add(new URL(u).origin);
    } catch {}
  }

  // If client has registered origins or redirect URIs, enforce that the admin redirect URL belongs to one of them
  if (clientOrigins.size > 0 && !clientOrigins.has(parsedUrl.origin)) {
    return {
      allowed: false,
      error: `Redirect URL origin "${parsedUrl.origin}" does not match any registered allowed origins or redirect URIs for this application. Configure it under Allowed Origins or Redirect URIs first.`,
    };
  }

  return { allowed: true };
}

// 11. Create Application Admin for a Client
admin.post("/clients/:clientId/app-admins", requireSuperAdmin, async (c) => {
  const clientId = c.req.param("clientId");
  const body = await c.req.json().catch(() => ({}));
  const sessionUser = c.get("user") as any;

  const email = typeof body.email === "string" ? body.email.toLowerCase().trim() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const name = typeof body.name === "string" && body.name.trim() ? body.name.trim() : email.split("@")[0];
  const redirectUrl = typeof body.redirectUrl === "string" ? body.redirectUrl.trim() : "";

  if (!email || !email.includes("@")) {
    return c.json({ error: "Valid email address is required" }, 400);
  }

  if (!redirectUrl) {
    return c.json({ error: "Redirect URL is required" }, 400);
  }

  if (!isStrongPassword(password)) {
    return c.json(
      {
        error: "weak_password",
        message: "Password must be at least 12 characters and include uppercase, lowercase, number, and special symbol.",
      },
      400
    );
  }

  try {
    const database = await getDb();

    // Verify client exists
    const client = await database.collection("oauthClient").findOne({
      $or: [{ clientId }, { client_id: clientId }, { id: clientId }],
    });

    if (!client) {
      return c.json({ error: "Application not found" }, 404);
    }

    // Enforce origin matching against client's registered origins/redirect URIs
    const urlCheck = isRedirectUrlAllowedForClient(redirectUrl, client);
    if (!urlCheck.allowed) {
      return c.json({ error: urlCheck.error }, 400);
    }

    const canonicalClientId = client.clientId || client.client_id || clientId;

    // Check email uniqueness within this application
    const existing = await database.collection("app_admins").findOne({
      clientId: canonicalClientId,
      email,
    });

    if (existing) {
      return c.json({ error: "An administrator with this email already exists for this application" }, 409);
    }

    const hashedPassword = await hashPassword(password);
    const now = new Date();

    const doc = {
      clientId: canonicalClientId,
      email,
      name,
      password: hashedPassword,
      redirectUrl,
      isActive: true,
      loginCount: 0,
      lastLoginAt: null,
      createdAt: now,
      updatedAt: now,
    };

    const insertResult = await database.collection("app_admins").insertOne(doc);

    await recordAdminAudit({
      actorUserId: sessionUser?.id,
      actorEmail: sessionUser?.email,
      actorScope: "super_admin",
      action: "app_admin_created",
      targetClientId: canonicalClientId,
      details: { email, name, redirectUrl },
      ipAddress: getTrustedClientIp(c),
      timestamp: now,
    });

    return c.json(
      {
        success: true,
        admin: {
          id: insertResult.insertedId.toString(),
          email,
          name,
          redirectUrl,
          isActive: true,
          loginCount: 0,
          lastLoginAt: null,
          createdAt: now.toISOString(),
        },
      },
      201
    );
  } catch (err: any) {
    console.error("[ADMIN_CREATE_APP_ADMIN] Error:", err);
    return c.json({ error: err?.message || "Failed to create application administrator" }, 500);
  }
});

// 12. Update Application Admin
admin.put("/clients/:clientId/app-admins/:adminId", requireSuperAdmin, async (c) => {
  const clientId = c.req.param("clientId");
  const adminId = c.req.param("adminId");
  const body = await c.req.json().catch(() => ({}));
  const sessionUser = c.get("user") as any;

  let adminObjId: ObjectId;
  try {
    adminObjId = new ObjectId(adminId);
  } catch {
    return c.json({ error: "Invalid admin ID" }, 400);
  }

  try {
    const database = await getDb();

    // Verify admin exists and belongs to client
    const existing = await database.collection("app_admins").findOne({
      _id: adminObjId,
      clientId,
    });

    if (!existing) {
      return c.json({ error: "Administrator not found" }, 404);
    }

    const updateFields: any = { updatedAt: new Date() };

    if (typeof body.name === "string" && body.name.trim()) {
      updateFields.name = body.name.trim();
    }

    if (typeof body.email === "string" && body.email.trim()) {
      const newEmail = body.email.toLowerCase().trim();
      if (!newEmail.includes("@")) {
        return c.json({ error: "Valid email address is required" }, 400);
      }
      if (newEmail !== existing.email) {
        const conflict = await database.collection("app_admins").findOne({
          clientId,
          email: newEmail,
          _id: { $ne: adminObjId },
        });
        if (conflict) {
          return c.json({ error: "Another administrator with this email already exists for this application" }, 409);
        }
        updateFields.email = newEmail;
      }
    }

    if (typeof body.redirectUrl === "string" && body.redirectUrl.trim()) {
      const client = await database.collection("oauthClient").findOne({
        $or: [{ clientId }, { client_id: clientId }, { id: clientId }],
      });
      const urlCheck = isRedirectUrlAllowedForClient(body.redirectUrl.trim(), client || {});
      if (!urlCheck.allowed) {
        return c.json({ error: urlCheck.error }, 400);
      }
      updateFields.redirectUrl = body.redirectUrl.trim();
    }

    if (typeof body.isActive === "boolean") {
      updateFields.isActive = body.isActive;
    }

    if (typeof body.password === "string" && body.password.length > 0) {
      if (!isStrongPassword(body.password)) {
        return c.json(
          {
            error: "weak_password",
            message: "Password must be at least 12 characters and include uppercase, lowercase, number, and special symbol.",
          },
          400
        );
      }
      updateFields.password = await hashPassword(body.password);
    }

    await database.collection("app_admins").updateOne(
      { _id: adminObjId },
      { $set: updateFields }
    );

    const updated = await database.collection("app_admins").findOne({ _id: adminObjId });

    await recordAdminAudit({
      actorUserId: sessionUser?.id,
      actorEmail: sessionUser?.email,
      actorScope: "super_admin",
      action: "app_admin_updated",
      targetClientId: clientId,
      details: { adminId, updatedFields: Object.keys(updateFields) },
      ipAddress: getTrustedClientIp(c),
      timestamp: new Date(),
    });

    return c.json({
      success: true,
      admin: {
        id: updated._id.toString(),
        email: updated.email,
        name: updated.name,
        redirectUrl: updated.redirectUrl,
        isActive: updated.isActive !== false,
        loginCount: updated.loginCount || 0,
        lastLoginAt: updated.lastLoginAt ? updated.lastLoginAt.toISOString() : null,
        createdAt: updated.createdAt ? updated.createdAt.toISOString() : null,
      },
    });
  } catch (err: any) {
    console.error("[ADMIN_UPDATE_APP_ADMIN] Error:", err);
    return c.json({ error: err?.message || "Failed to update administrator" }, 500);
  }
});

// 13. Delete Application Admin
admin.delete("/clients/:clientId/app-admins/:adminId", requireSuperAdmin, async (c) => {
  const clientId = c.req.param("clientId");
  const adminId = c.req.param("adminId");
  const sessionUser = c.get("user") as any;

  let adminObjId: ObjectId;
  try {
    adminObjId = new ObjectId(adminId);
  } catch {
    return c.json({ error: "Invalid admin ID" }, 400);
  }

  try {
    const database = await getDb();
    const existing = await database.collection("app_admins").findOne({
      _id: adminObjId,
      clientId,
    });

    if (!existing) {
      return c.json({ error: "Administrator not found" }, 404);
    }

    await database.collection("app_admins").deleteOne({ _id: adminObjId });

    await recordAdminAudit({
      actorUserId: sessionUser?.id,
      actorEmail: sessionUser?.email,
      actorScope: "super_admin",
      action: "app_admin_deleted",
      targetClientId: clientId,
      details: { adminId, email: existing.email },
      ipAddress: getTrustedClientIp(c),
      timestamp: new Date(),
    });

    return c.json({ success: true, message: "Administrator removed" });
  } catch (err: any) {
    console.error("[ADMIN_DELETE_APP_ADMIN] Error:", err);
    return c.json({ error: err?.message || "Failed to delete administrator" }, 500);
  }
});

// 14. Admin Catch-All 404 Handler
admin.all("*", (c) => {
  return c.json({ error: "Endpoint not found" }, 404);
});

export default admin;
