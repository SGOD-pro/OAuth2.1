import { Hono } from "hono";
import crypto from "crypto";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { getHeaders, isStrongPassword } from "../utils/security";
import { invalidateOriginCache, recordAdminAudit } from "../db/state";
import { requireSuperAdmin, requireScopedAdmin } from "../middleware/admin-auth";
import { adminProvisionRateLimit } from "../middleware/rate-limit";

export const admin = new Hono();

// -- Super-Admin Only Routes ---------------------------------------------

// 1. List All OAuth Clients (Super-Admin only)
admin.get("/clients", requireSuperAdmin, async (c) => {
  const result = await authProvider.api.listOAuthClients({
    headers: getHeaders(c),
  }) as Array<Record<string, unknown>> | null;

  if (!result) return c.json([]);

  const safeClients = result.map(({ client_secret: _omit, ...rest }) => rest);
  return c.json(safeClients);
});

// 2. Create OAuth Client (Super-Admin only)
admin.post("/clients", requireSuperAdmin, async (c) => {
  const body = await c.req.json();
  const sessionUser = c.get("user") as any;

  const result = await authProvider.api.createOAuthClient({
    headers: getHeaders(c),
    body,
  }) as Record<string, unknown> | null;

  if (result && Array.isArray(result.allowed_origins)) {
    await invalidateOriginCache(result.allowed_origins as string[]);
  }

  if (result) {
    await recordAdminAudit({
      actorUserId: sessionUser?.id,
      actorEmail: sessionUser?.email,
      actorScope: sessionUser?.scopedClientId || "super_admin",
      action: "client_created",
      targetClientId: String(result.client_id || result.id),
      details: { name: body.name || body.client_name, client_id: result.client_id },
      ipAddress: c.req.header("x-forwarded-for") || "127.0.0.1",
      timestamp: new Date(),
    });
  }

  return c.json(result);
});

// 3. Platform Stats (Super-Admin only)
admin.get("/stats", requireSuperAdmin, async (c) => {
  const database = await getDb();
  const [totalUsers, totalClients, activeSessions, recentLogs] = await Promise.all([
    database.collection("user").countDocuments(),
    database.collection("oauthClient").countDocuments(),
    database.collection("session").countDocuments({ expiresAt: { $gt: new Date() } }),
    database.collection("session").find().sort({ createdAt: -1 }).limit(5).toArray(),
  ]);

  return c.json({
    totalUsers,
    totalClients,
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
});

// 4. Audit & Activity Logs (Super-Admin only)
admin.get("/logs", requireSuperAdmin, async (c) => {
  const database = await getDb();
  const [sessions, audits] = await Promise.all([
    database.collection("session").find().sort({ createdAt: -1 }).limit(25).toArray(),
    database.collection("admin_audit").find().sort({ timestamp: -1 }).limit(25).toArray(),
  ]);

  return c.json({
    sessions: sessions.map((s: any) => ({
      id: s.id || s._id?.toString(),
      userId: s.userId,
      ipAddress: s.ipAddress || "127.0.0.1",
      userAgent: s.userAgent || "Unknown",
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
    })),
    audits: audits.map((a: any) => ({
      id: a._id?.toString(),
      actorUserId: a.actorUserId,
      actorEmail: a.actorEmail,
      actorScope: a.actorScope,
      action: a.action,
      targetClientId: a.targetClientId,
      targetUserId: a.targetUserId,
      details: a.details,
      ipAddress: a.ipAddress,
      timestamp: a.timestamp,
    })),
  });
});

// 5. Delete OAuth Client (Super-Admin only)
admin.delete("/clients/:id", requireSuperAdmin, async (c) => {
  const id = c.req.param("id");
  const sessionUser = c.get("user") as any;

  try {
    const existing = await authProvider.api.getOAuthClient({
      headers: getHeaders(c),
      query: { client_id: id },
    }) as Record<string, unknown> | null;

    if (existing && Array.isArray(existing.allowed_origins)) {
      await invalidateOriginCache(existing.allowed_origins as string[]);
    }
  } catch {
    // Ignore fetch error before deletion
  }

  const result = await authProvider.api.deleteOAuthClient({
    headers: getHeaders(c),
    body: { client_id: id },
  });

  const database = await getDb();
  await Promise.all([
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
    ipAddress: c.req.header("x-forwarded-for") || "127.0.0.1",
    timestamp: new Date(),
  });

  return c.json(result);
});

// 6. Provision Scoped or Global Admin (Super-Admin only with Rate Limiting B6)
admin.post("/users", requireSuperAdmin, adminProvisionRateLimit, async (c) => {
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
    const newUser = await authProvider.api.signUpEmail({
      body: { email, password, name },
    });

    const userId = newUser?.user?.id || (newUser as any)?.id;

    // 2. Set role: "admin", scopedClientId, and mustChangePassword
    await database.collection("user").updateOne(
      { $or: [{ id: userId }, { _id: userId }, { email }] } as any,
      {
        $set: {
          role: "admin",
          scopedClientId: scopedClientId,
          mustChangePassword: isTempPassword,
          updatedAt: new Date(),
        },
      }
    );

    // 3. Record audit trail
    await recordAdminAudit({
      actorUserId: sessionUser?.id,
      actorEmail: sessionUser?.email,
      actorScope: sessionUser?.scopedClientId || "super_admin",
      action: "admin_provisioned",
      targetUserId: String(userId),
      targetClientId: scopedClientId || undefined,
      details: { email, scopedClientId, isTempPassword },
      ipAddress: c.req.header("x-forwarded-for") || "127.0.0.1",
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

// -- Scoped-Admin & Super-Admin Routes -----------------------------------

// 7. Get OAuth Client by ID (Super-Admin or Assigned Scoped-Admin)
admin.get("/clients/:id", requireScopedAdmin, async (c) => {
  const id = c.req.param("id");

  try {
    const result = await authProvider.api.getOAuthClient({
      headers: getHeaders(c),
      query: { client_id: id },
    }) as Record<string, unknown> | null;

    if (!result) return c.json({ error: "Client not found" }, 404);

    const { client_secret: _omit, ...safeResult } = result as { client_secret?: unknown } & Record<string, unknown>;
    return c.json(safeResult);
  } catch (err: any) {
    // Graceful 404 mapping for Better-Auth APIError (Unauthorized / Not Found)
    if (err?.name === "APIError" || err?.status === "UNAUTHORIZED" || err?.status === "NOT_FOUND") {
      return c.json({ error: "Client not found or unauthorized" }, 404);
    }
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
    oldClient = await authProvider.api.getOAuthClient({
      headers: getHeaders(c),
      query: { client_id: id },
    });
  } catch {}

  let result: any = null;
  try {
    result = await authProvider.api.updateOAuthClient({
      headers: getHeaders(c),
      body: { client_id: id, update: body },
    });
  } catch {
    // Fallback direct update to DB if updateOAuthClient fails on custom fields
    const database = await getDb();
    await database.collection("oauthClient").updateOne(
      { client_id: id },
      { $set: { ...body, updatedAt: new Date() } }
    );
    result = await database.collection("oauthClient").findOne({ client_id: id });
  }

  if (!result) return c.json({ error: "Client not found" }, 404);

  // Invalidate CORS origin cache for updated origins
  const originsToInvalidate = new Set<string>();
  if (oldClient && Array.isArray(oldClient.allowed_origins)) {
    oldClient.allowed_origins.forEach((o: string) => originsToInvalidate.add(o));
  }
  if (result && Array.isArray(result.allowed_origins)) {
    (result.allowed_origins as string[]).forEach((o: string) => originsToInvalidate.add(o));
  }
  if (originsToInvalidate.size > 0) {
    await invalidateOriginCache(Array.from(originsToInvalidate));
  }

  // Token revocation on client disable
  if (body.disabled === true || body.is_active === false) {
    const database = await getDb();
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
    ipAddress: c.req.header("x-forwarded-for") || "127.0.0.1",
    timestamp: new Date(),
  });

  const { client_secret: _omit, ...safeResult } = result as { client_secret?: unknown } & Record<string, unknown>;
  return c.json(safeResult);
});

// 9. Dedicated Scoped Application Configuration Routes
admin.get("/app/:clientId/config", requireScopedAdmin, async (c) => {
  const clientId = c.req.param("clientId");
  try {
    const result = await authProvider.api.getOAuthClient({
      headers: getHeaders(c),
      query: { client_id: clientId },
    }) as Record<string, unknown> | null;

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
    result = await authProvider.api.updateOAuthClient({
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
    ipAddress: c.req.header("x-forwarded-for") || "127.0.0.1",
    timestamp: new Date(),
  });

  const { client_secret: _omit, ...safeResult } = result as { client_secret?: unknown } & Record<string, unknown>;
  return c.json(safeResult);
});

// 10. Admin Catch-All 404 Handler
admin.all("*", (c) => {
  return c.json({ error: "Endpoint not found" }, 404);
});

export default admin;
