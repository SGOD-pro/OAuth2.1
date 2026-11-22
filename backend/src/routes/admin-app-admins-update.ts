import { ObjectId } from "mongodb";
import { getDb } from "../db/mongo";
import {
  isStrongPassword,
  getTrustedClientIp,
  resolveOAuthClient,
} from "../utils/security";
import { recordAdminAudit } from "../db/state";
import { hashPassword } from "better-auth/crypto";
import { syncAppAdminIdentity, removeAppAdminIdentity } from "../utils/admin-sync";
import { isRedirectUrlAllowedForClient } from "./admin-app-admins";

export const updateAppAdminHandler = async (c: any): Promise<Response> => {
  const clientId = c.req.param("clientId");
  const adminId = c.req.param("adminId");
  const body = await c.req.json().catch(() => ({}));
  const sessionUser = c.get("user") as any;

  // Reject conflicting client IDs between route and body
  if (body.clientId && typeof body.clientId === "string" && body.clientId !== clientId) {
    return c.json({ error: "Conflicting clientId in request body", code: "ERR_CONFLICTING_CLIENT_ID" }, 400);
  }

  let adminObjId: ObjectId;
  try {
    adminObjId = new ObjectId(adminId);
  } catch {
    return c.json({ error: "Invalid admin ID" }, 400);
  }

  try {
    const database = await getDb();

    let client: any;
    try {
      client = await resolveOAuthClient(database, clientId);
    } catch (err: any) {
      console.error("[ADMIN_UPDATE_APP_ADMIN] DB error resolving client:", err);
      return c.json({ error: "Failed to resolve client due to database error" }, 500);
    }

    if (!client) {
      return c.json({ error: "Application not found" }, 404);
    }

    const canonicalClientId = client.clientId;

    // Verify admin exists and belongs to client
    const existing = await database.collection("app_admins").findOne({
      _id: adminObjId,
      clientId: canonicalClientId,
    });

    if (!existing) {
      return c.json({ error: "Administrator not found" }, 404);
    }

    const updateFields: any = { updatedAt: new Date() };

    if (typeof body.name === "string" && body.name.trim()) {
      updateFields.name = body.name.trim();
    }

    if (typeof body.email === "string" && body.email.trim() && !body.email.includes("***")) {
      const newEmail = body.email.toLowerCase().trim();
      if (!newEmail.includes("@")) {
        return c.json({ error: "Valid email address is required" }, 400);
      }
      if (newEmail !== existing.email) {
        // USER-REQUIRED POLICY: Reject assigning an existing super-admin identity as an app admin.
        const superAdminCheck = await database.collection("user").findOne({ email: newEmail });
        if (superAdminCheck && (superAdminCheck.role === "super-admin" || (superAdminCheck.role === "admin" && superAdminCheck.scopedClientId === null))) {
          const reqId = c.get("requestId") || c.req.header("x-request-id");
          return c.json(
            {
              error: "Identity conflict: Global Super Admin cannot be assigned as an Application Administrator",
              code: "ERR_IDENTITY_CONFLICT",
              requestId: reqId,
            },
            409
          );
        }

        const conflict = await database.collection("app_admins").findOne({
          clientId: canonicalClientId,
          email: newEmail,
          _id: { $ne: adminObjId },
        });
        if (conflict) {
          return c.json({ error: "Another administrator with this email already exists for this application" }, 409);
        }
        updateFields.email = newEmail;
      }
    }

    if (body.removeRedirectUrl === true || body.redirectUrl === "" || body.redirectUrl === null) {
      updateFields.redirectUrl = "";
    } else if (typeof body.redirectUrl === "string" && body.redirectUrl.trim()) {
      const urlCheck = isRedirectUrlAllowedForClient(body.redirectUrl.trim(), client);
      if (!urlCheck.allowed) {
        return c.json({ error: urlCheck.error }, 400);
      }
      updateFields.redirectUrl = body.redirectUrl.trim();
    }

    if (typeof body.isActive === "boolean") {
      updateFields.isActive = body.isActive;
      if (body.isActive === false) {
        updateFields.tokensRevokedBefore = new Date();
        updateFields.tokenVersion = ((existing.tokenVersion as number) || 1) + 1;
      }
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
      updateFields.passwordChangedAt = new Date();
      updateFields.tokensRevokedBefore = new Date();
      updateFields.tokenVersion = ((existing.tokenVersion as number) || 1) + 1;
    }

    await database.collection("app_admins").updateOne(
      { _id: adminObjId },
      { $set: updateFields }
    );

    const updated = await database.collection("app_admins").findOne({ _id: adminObjId });
    if (!updated) {
      return c.json({ error: "Administrator not found after update" }, 404);
    }

    // Synchronize updates to centralized Better Auth user, account, and user_app_registrations
    try {
      await syncAppAdminIdentity(database, {
        userId: updated.userId ? String(updated.userId) : undefined,
        email: updated.email,
        clientId: canonicalClientId,
        name: updated.name,
        hashedPassword: updated.password,
        isActive: updated.isActive !== false,
        previousEmail: existing.email,
        createdAt: updated.createdAt,
      });
    } catch (syncErr: any) {
      console.warn("[ADMIN_UPDATE_APP_ADMIN] Warning syncing to centralized user collection:", syncErr?.message || syncErr);
    }

    await recordAdminAudit({
      actorUserId: sessionUser?.id,
      actorEmail: sessionUser?.email,
      actorScope: "super_admin",
      action: "app_admin_updated",
      targetClientId: canonicalClientId,
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
        redirectUrl: updated.redirectUrl || "",
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
};

export async function handleDeleteAppAdmin(c: any): Promise<Response> {
  const rawClientId = c.req.param("clientId");
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
    let client: any;
    try {
      client = await resolveOAuthClient(database, rawClientId);
    } catch (err: any) {
      console.error("[ADMIN_DELETE_APP_ADMIN] DB error resolving client:", err);
      return c.json({ error: "Failed to resolve client due to database error" }, 500);
    }

    if (!client) {
      return c.json({ error: "Application not found" }, 404);
    }

    const canonicalClientId = client.clientId;

    const existing = await database.collection("app_admins").findOne({
      _id: adminObjId,
      clientId: canonicalClientId,
    });

    if (!existing) {
      return c.json({ error: "Administrator not found" }, 404);
    }

    await database.collection("app_admins").deleteOne({ _id: adminObjId });

    // If user was scoped to this client, remove scopedClientId, reset role, and remove registration
    try {
      await removeAppAdminIdentity(database, {
        email: existing.email,
        clientId: canonicalClientId,
      });
    } catch (delErr: any) {
      console.warn("[ADMIN_DELETE_APP_ADMIN] Warning removing centralized identity:", delErr?.message || delErr);
    }

    await recordAdminAudit({
      actorUserId: sessionUser?.id,
      actorEmail: sessionUser?.email,
      actorScope: "super_admin",
      action: "app_admin_deleted",
      targetClientId: canonicalClientId,
      details: { adminId, email: existing.email },
      ipAddress: getTrustedClientIp(c),
      timestamp: new Date(),
    });

    return c.json({ success: true, message: "Administrator removed" });
  } catch (err: any) {
    console.error("[ADMIN_DELETE_APP_ADMIN] Error:", err);
    return c.json({ error: err?.message || "Failed to delete administrator" }, 500);
  }
}
