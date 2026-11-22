import { Hono } from "hono";
import { hasDangerousMongoKeys } from "../utils/security";
import {
  requireAdmin,
  requireSuperAdmin,
  requireScopedAdmin,
  requireConsumerAppAdmin,
  requireGatewayTrust,
  requireRecentMfa,
} from "../middleware/admin-auth";
import { adminProvisionRateLimit } from "../middleware/rate-limit";

import { handleGetStats } from "./admin-stats";
import { handleGetLogs, handleGetV2Logs } from "./admin-logs";
import { handlePostUsers, handleGetUsers } from "./admin-users";
import { handleGetClients, handlePostClients, handleDeleteClient } from "./admin-clients";
import { handleGetClientById, handlePatchClientById } from "./admin-client-detail";
import { handleGetAppConfig, handlePatchAppConfig } from "./admin-app-config";
import { handleGetAppAdmins, handlePostAppAdmins } from "./admin-app-admins";
import { updateAppAdminHandler, handleDeleteAppAdmin } from "./admin-app-admins-update";
import { handleGetAppUsers, handlePostAppUsers, handleDeleteAppUser } from "./admin-app-users";

export * from "./admin-stats";
export * from "./admin-logs";
export * from "./admin-logs-types";
export * from "./admin-logs-service";
export * from "./admin-users";
export * from "./admin-clients";
export * from "./admin-client-detail";
export * from "./admin-app-config";
export * from "./admin-app-admins";
export * from "./admin-app-admins-update";
export * from "./admin-app-users";

export const admin = new Hono<{
  Variables: {
    user: any;
    session: any;
    scopedClientId: string | null;
  };
}>();

// Gateway trust perimeter: enforce trusted gateway boundary on all admin endpoints
admin.use("*", requireGatewayTrust);

// Enforce NoSQL injection, operator injection, and prototype pollution defenses on all admin JSON bodies
admin.use("*", async (c, next) => {
  const method = c.req.method;
  if (method === "POST" || method === "PUT" || method === "PATCH") {
    const contentType = c.req.header("content-type") || "";
    if (contentType.includes("application/json")) {
      try {
        const rawClone = c.req.raw.clone();
        const parsed = await rawClone.json().catch(() => null);
        if (parsed && hasDangerousMongoKeys(parsed)) {
          return c.json(
            {
              error: "invalid_input",
              code: "ERR_INVALID_INPUT",
              message: "Invalid input: operator injection and prototype modification rejected",
            },
            400
          );
        }
      } catch {}
    }
  }
  return next();
});

// 0. Admin Current Identity & MFA Status (Accessible to unenrolled admins for setup)
admin.get("/me", requireAdmin, async (c) => {
  const user = c.get("user") as any;
  const session = c.get("session") as any;
  const reqId = c.get("requestId") || c.req.header("x-request-id");

  return c.json({
    id: user.id || user._id,
    email: user.email,
    name: user.name,
    role: user.role,
    scopedClientId: user.scopedClientId || null,
    twoFactorEnabled: Boolean(user.twoFactorEnabled === true),
    twoFactorVerified: Boolean(session?.twoFactorVerified === true),
    mfaVerifiedAt: session?.mfaVerifiedAt || null,
    mustChangePassword: Boolean(user.mustChangePassword === true),
    requestId: reqId,
  });
});

// 1. OAuth Clients List (Super-Admin only)
admin.get("/clients", requireSuperAdmin, handleGetClients);

// 2. Create OAuth Client (Super-Admin only)
admin.post("/clients", requireSuperAdmin, handlePostClients);

// 3. Platform Stats (Super-Admin only)
admin.get("/stats", requireSuperAdmin, handleGetStats);

// 4. Audit & Activity Logs (Super-Admin only)
admin.get("/logs", requireSuperAdmin, handleGetLogs);

// 4b. Versioned Structured Audit Logs API (Super-Admin only)
admin.get("/v2/logs", requireSuperAdmin, handleGetV2Logs);

// 5. Delete OAuth Client (Super-Admin only)
admin.delete("/clients/:id", requireSuperAdmin, requireRecentMfa, handleDeleteClient);

// 6. Provision Scoped or Global Admin (Super-Admin only with Rate Limiting B6 & Recent MFA)
admin.post("/users", adminProvisionRateLimit, requireSuperAdmin, requireRecentMfa, handlePostUsers);

// 6b. List All Users (Super-Admin only)
admin.get("/users", requireSuperAdmin, handleGetUsers);

// 7. Get OAuth Client by ID (Super-Admin or Assigned Scoped-Admin)
admin.get("/clients/:id", requireScopedAdmin, handleGetClientById);

// 8. Patch OAuth Client by ID (Super-Admin or Assigned Scoped-Admin)
admin.patch("/clients/:id", requireScopedAdmin, handlePatchClientById);

// 9. Dedicated Scoped Application Configuration Routes
admin.get("/app/:clientId/config", requireConsumerAppAdmin, handleGetAppConfig);
admin.patch("/app/:clientId/config", requireConsumerAppAdmin, handlePatchAppConfig);

// 10. List Application Admins for a Client (Super-Admin or Scoped-Admin for own app)
admin.get("/clients/:clientId/app-admins", requireScopedAdmin, handleGetAppAdmins);

// 11. Create Application Admin for a Client (Super-Admin or Scoped-Admin for own app)
admin.post("/clients/:clientId/app-admins", requireScopedAdmin, requireRecentMfa, handlePostAppAdmins);

// 12. Update Application Admin (supports PUT and PATCH)
admin.put("/clients/:clientId/app-admins/:adminId", requireScopedAdmin, requireRecentMfa, updateAppAdminHandler);
admin.patch("/clients/:clientId/app-admins/:adminId", requireScopedAdmin, requireRecentMfa, updateAppAdminHandler);

// 13. Delete Application Admin (Super-Admin or Scoped-Admin for own app)
admin.delete("/clients/:clientId/app-admins/:adminId", requireScopedAdmin, requireRecentMfa, handleDeleteAppAdmin);

// 14. List Users Assigned to a Client
admin.get("/clients/:clientId/users", requireScopedAdmin, handleGetAppUsers);

// 15. Assign a User to a Client (for Private Applications)
admin.post("/clients/:clientId/users", requireScopedAdmin, handlePostAppUsers);

// 16. Remove a User from a Client
admin.delete("/clients/:clientId/users/:userId", requireScopedAdmin, requireRecentMfa, handleDeleteAppUser);

// 17. Admin Catch-All 404 Handler
admin.all("*", (c) => {
  return c.json({ error: "Endpoint not found" }, 404);
});

export default admin;
