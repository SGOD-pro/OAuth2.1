import crypto from "crypto";
import { authProvider } from "../utils/auth";
import { ObjectId } from "mongodb";
import { getDb } from "../db/mongo";
import {
  isStrongPassword,
  getTrustedClientIp,
  toApprovedDisplayLabel,
  isEmailShaped,
} from "../utils/security";
import { recordAdminAudit } from "../db/state";
import { AccountKeyAccessError, type AccountKeyProvider } from "../identity/account-key-provider";
import { ProtectedFieldError } from "../identity/protected-envelope";
import {
  resolveProtectedAdminDisplayFields,
  type ProtectedProfileCollection,
} from "../identity/protected-profile-store";

export interface AdminUsersRouteDeps {
  getDb?: () => Promise<any>;
  protectedProfileStore?: ProtectedProfileCollection;
  accountKeyProvider?: AccountKeyProvider;
  migrationMode?: "compat" | "strict";
}

const authApi = authProvider.api as any;

export async function handlePostUsers(c: any): Promise<Response> {
  const body = await c.req.json();
  const sessionUser = c.get("user") as any;

  if (!body.email || typeof body.email !== "string") {
    return c.json({ error: "Valid email is required" }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const name = body.name || email.split("@")[0];
  const rawClientId = body.clientId ?? body.scopedClientId;
  let scopedClientId: string | null = null;
  if (typeof rawClientId === "string") {
    const trimmed = rawClientId.trim();
    if (trimmed.length === 0) {
      return c.json({ error: "Invalid clientId: cannot be empty string" }, 400);
    }
    scopedClientId = trimmed;
  } else if (rawClientId !== null && rawClientId !== undefined) {
    return c.json({ error: "Invalid clientId format" }, 400);
  }

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

    // 2. Explicit domain role enforcement:
    // "app-admin": requires non-empty scopedClientId.
    // "super-admin": unscoped platform admin only.
    // "user": standard non-privileged user.
    let explicitRole: "super-admin" | "app-admin" | "user" = "user";
    if (body.role === "app-admin" || (body.role === "admin" && scopedClientId)) {
      if (!scopedClientId) {
        return c.json(
          {
            error: "Application administrators must be scoped to an application client ID.",
            code: "ERR_SCOPED_CLIENT_REQUIRED",
          },
          400
        );
      }
      explicitRole = "app-admin";
    } else if (body.role === "super-admin") {
      if (scopedClientId) {
        return c.json(
          {
            error: "Super administrators cannot be scoped to a client ID.",
            code: "ERR_SUPER_ADMIN_CANNOT_BE_SCOPED",
          },
          400
        );
      }
      explicitRole = "super-admin";
    } else if (body.role === "admin" && !scopedClientId) {
      return c.json(
        {
          error: "Application administrators must be scoped to an application client ID.",
          code: "ERR_SCOPED_CLIENT_REQUIRED",
        },
        400
      );
    } else {
      if (scopedClientId) {
        return c.json(
          {
            error: "Standard users cannot be scoped as application administrators.",
            code: "ERR_USER_CANNOT_BE_SCOPED",
          },
          400
        );
      }
      explicitRole = "user";
    }
    await database.collection("user").updateOne(
      { $or: [{ id: userId }, { _id: userId }, { email }] } as any,
      {
        $set: {
          role: explicitRole,
          emailVerified: true,
          scopedClientId: explicitRole === "app-admin" ? scopedClientId : null,
          mustChangePassword: isTempPassword,
          updatedAt: new Date(),
        },
      }
    );

    // 3. If assigned to a client as an application administrator, link to oauthClient and user_app_registrations
    if (explicitRole === "app-admin" && scopedClientId) {
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

      await database.collection("user_app_registrations").updateOne(
        { clientId: scopedClientId, userId: String(userId) },
        {
          $set: {
            userId: String(userId),
            clientId: scopedClientId,
            appRole: "admin",
            registeredAt: new Date(),
          },
        },
        { upsert: true }
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
        role: explicitRole,
        scopedClientId,
        tempPassword: isTempPassword ? password : null,
        mustChangePassword: isTempPassword,
      },
    });
  } catch (err: any) {
    console.error("[ADMIN_PROVISION] Error creating admin user:", err);
    return c.json({ error: err?.message || "Failed to provision admin user" }, 500);
  }
}

export function createGetUsersHandler(deps: AdminUsersRouteDeps = {}) {
  return (c: any) => runGetUsers(c, deps);
}

export async function handleGetUsers(c: any): Promise<Response> {
  return runGetUsers(c, {});
}

async function runGetUsers(c: any, deps: AdminUsersRouteDeps): Promise<Response> {
  try {
    const rawLimit = parseInt(c.req.query("limit") || "100", 10);
    const rawPage = parseInt(c.req.query("page") || "1", 10);
    const limit = isNaN(rawLimit) || rawLimit < 1 ? 100 : Math.min(rawLimit, 500);
    const page = isNaN(rawPage) || rawPage < 1 ? 1 : rawPage;
    const skip = (page - 1) * limit;

    const rawQ = (c.req.query("q") || "").trim();
    const filter: Record<string, any> = {};
    if (rawQ) {
      const orClauses: any[] = [
        { usernameNormalized: rawQ.toLowerCase() },
        { username: rawQ },
        { id: rawQ },
      ];
      if (ObjectId.isValid(rawQ) && rawQ.length === 24) {
        orClauses.push({ _id: new ObjectId(rawQ) });
      }
      filter.$or = orClauses;
    }

    const database = await (deps.getDb ?? getDb)();
    const users = await database
      .collection("user")
      .find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();
    const safeUsers = await Promise.all(users.map(async (u: any) => {
      const resolved = await resolveProtectedAdminDisplayFields({
        userDoc: u,
        store: deps.protectedProfileStore,
        provider: deps.accountKeyProvider,
        migrationMode: deps.migrationMode,
      });
      return {
        _id: u._id?.toString() || u.id,
        username: u.username ?? null,
        displayLabel: toApprovedDisplayLabel(resolved.email, resolved.name),
        name: isEmailShaped(resolved.name) ? toApprovedDisplayLabel(resolved.name) : (resolved.name || "User"),
        role: u.role || "user",
        scopedClientId: u.scopedClientId || null,
        createdAt: u.createdAt || new Date(),
      };
    }));
    return c.json(safeUsers);
  } catch (err: any) {
    if (err instanceof AccountKeyAccessError) {
      return c.json({ error: err.code, error_description: err.message }, err.code === "provider_outage" ? 503 : 403);
    }
    if (err instanceof ProtectedFieldError) {
      return c.json({ error: err.code, error_description: err.message }, err.code === "profile_not_found" ? 404 : 500);
    }
    console.error("[ADMIN_USERS] Error listing users:", err);
    return c.json({ error: "Failed to fetch users" }, 500);
  }
}
