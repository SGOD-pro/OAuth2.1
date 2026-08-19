import { createMiddleware } from "hono/factory";
import { authProvider } from "../utils/auth";
import { getHeaders } from "../utils/security";
import { getDb } from "../db/mongo";

export const requireAdmin = createMiddleware(async (c, next) => {
  const session = await authProvider.api.getSession({
    headers: getHeaders(c),
  });

  if (!session || !session.user) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const database = await getDb();
  const userDoc = await database.collection("user").findOne({
    $or: [{ id: session.user.id }, { _id: (session.user as any)._id }, { email: session.user.email }],
  });

  const role = userDoc?.role || session.user.role;
  if (role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }

  c.set("user", { ...session.user, ...userDoc });
  c.set("session", session.session);
  return next();
});

/**
 * Super-Admin Middleware: Global operations only (client creation, user provisioning, global stats/logs)
 */
export const requireSuperAdmin = createMiddleware(async (c, next) => {
  const session = await authProvider.api.getSession({
    headers: getHeaders(c),
  });

  if (!session || !session.user) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const database = await getDb();
  const userDoc = await database.collection("user").findOne({
    $or: [{ id: session.user.id }, { _id: (session.user as any)._id }, { email: session.user.email }],
  });

  const role = userDoc?.role || session.user.role;
  if (role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }

  const scopedClientId = userDoc?.scopedClientId ?? (session.user as any).scopedClientId;
  if (scopedClientId !== null && scopedClientId !== undefined && scopedClientId !== "") {
    return c.json(
      {
        error: "forbidden",
        message: "Super-Admin privileges required for this global administrative operation",
      },
      403
    );
  }

  c.set("user", { ...session.user, ...userDoc });
  c.set("session", session.session);
  return next();
});

/**
 * Scoped-Admin Middleware: App-level operations only (managing own client config)
 */
export const requireScopedAdmin = createMiddleware(async (c, next) => {
  const session = await authProvider.api.getSession({
    headers: getHeaders(c),
  });

  if (!session || !session.user) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const database = await getDb();
  const userDoc = await database.collection("user").findOne({
    $or: [{ id: session.user.id }, { _id: (session.user as any)._id }, { email: session.user.email }],
  });

  const role = userDoc?.role || session.user.role;
  if (role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }

  // Enforce mandatory password change for freshly provisioned temporary accounts
  if (userDoc?.mustChangePassword === true || (session.user as any).mustChangePassword === true) {
    return c.json(
      {
        error: "password_change_required",
        message: "Temporary password must be changed before accessing admin operations",
      },
      403
    );
  }

  const scopedClientId = userDoc?.scopedClientId ?? (session.user as any).scopedClientId;
  const targetClientId = c.req.param("id") || c.req.param("clientId");

  // If user is scoped to a specific application, enforce strict boundary
  if (scopedClientId && targetClientId && targetClientId !== scopedClientId) {
    return c.json(
      {
        error: "forbidden",
        message: "Cross-tenant access forbidden: you can only manage your own assigned application",
      },
      403
    );
  }

  c.set("user", { ...session.user, ...userDoc });
  c.set("session", session.session);
  c.set("scopedClientId", scopedClientId || null);
  return next();
});
