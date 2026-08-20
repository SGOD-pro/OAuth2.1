import { createMiddleware } from "hono/factory";
import { authProvider } from "../utils/auth";
import { getHeaders } from "../utils/security";
import { getDb } from "../db/mongo";

/**
 * Helper to fetch session and user document once per request and cache on context `c`
 */
async function getAuthenticatedUser(c: any): Promise<{ user: any; session: any } | null> {
  const existingUser = c.get("user");
  const existingSession = c.get("session");
  if (existingUser && existingSession) {
    return { user: existingUser, session: existingSession };
  }

  const session = await authProvider.api.getSession({
    headers: getHeaders(c),
  });

  if (!session || !session.user) {
    return null;
  }

  const database = await getDb();
  const userDoc = await database.collection("user").findOne({
    $or: [{ id: session.user.id }, { _id: (session.user as any)._id }, { email: session.user.email }],
  });

  const fullUser = { ...session.user, ...userDoc };
  c.set("user", fullUser);
  c.set("session", session.session);

  return { user: fullUser, session: session.session };
}

export const requireAdmin = createMiddleware(async (c, next) => {
  const auth = await getAuthenticatedUser(c);

  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const role = auth.user?.role;
  if (role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }

  return next();
});

/**
 * Super-Admin Middleware: Global operations only (client creation, user provisioning, global stats/logs)
 */
export const requireSuperAdmin = createMiddleware(async (c, next) => {
  const auth = await getAuthenticatedUser(c);

  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const role = auth.user?.role;
  if (role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }

  const scopedClientId = auth.user?.scopedClientId;
  if (scopedClientId !== null && scopedClientId !== undefined && scopedClientId !== "") {
    return c.json(
      {
        error: "forbidden",
        message: "Super-Admin privileges required for this global administrative operation",
      },
      403
    );
  }

  return next();
});

/**
 * Scoped-Admin Middleware: App-level operations only (managing own client config)
 */
export const requireScopedAdmin = createMiddleware(async (c, next) => {
  const auth = await getAuthenticatedUser(c);

  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const role = auth.user?.role;
  if (role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }

  // Enforce mandatory password change for freshly provisioned temporary accounts
  if (auth.user?.mustChangePassword === true) {
    return c.json(
      {
        error: "password_change_required",
        message: "Temporary password must be changed before accessing admin operations",
      },
      403
    );
  }

  const scopedClientId = auth.user?.scopedClientId;
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

  c.set("scopedClientId", scopedClientId || null);
  return next();
});
