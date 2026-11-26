import { getDb } from "../db/mongo";
import {
  isStrongPassword,
  getTrustedClientIp,
  resolveOAuthClient,
  toApprovedDisplayLabel,
  isEmailShaped,
} from "../utils/security";
import { recordAdminAudit } from "../db/state";
import { hashPassword } from "better-auth/crypto";
import { syncAppAdminIdentity } from "../utils/admin-sync";

// Helper: Validate that an app admin redirectUrl matches one of the client's registered origins or redirect URIs
export function isRedirectUrlAllowedForClient(redirectUrl: string, client: any): { allowed: boolean; error?: string } {
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

export async function handleGetAppAdmins(c: any): Promise<Response> {
  const rawClientId = c.req.param("clientId");
  try {
    const database = await getDb();
    let client: any;
    try {
      client = await resolveOAuthClient(database, rawClientId);
    } catch (err: any) {
      console.error("[ADMIN_LIST_APP_ADMINS] DB error resolving client:", err);
      return c.json({ error: "Failed to resolve client due to database error" }, 500);
    }
    if (!client) {
      return c.json({ error: "Application not found" }, 404);
    }
    const canonicalClientId = client.clientId;

    const admins = await database
      .collection("app_admins")
      .find({ clientId: canonicalClientId })
      .sort({ createdAt: -1 })
      .toArray();

    const safeAdmins = admins.map((a: any) => ({
      id: a._id.toString(),
      email: toApprovedDisplayLabel(a.email),
      displayLabel: toApprovedDisplayLabel(a.email, a.name),
      name: isEmailShaped(a.name) ? toApprovedDisplayLabel(a.name) : (a.name || toApprovedDisplayLabel(a.email)),
      redirectUrl: a.redirectUrl || "",
      isActive: a.isActive !== false,
      totpEnabled: a.totpEnabled === true,
      loginCount: a.loginCount || 0,
      lastLoginAt: a.lastLoginAt ? a.lastLoginAt.toISOString() : null,
      createdAt: a.createdAt ? a.createdAt.toISOString() : new Date().toISOString(),
    }));

    return c.json({ admins: safeAdmins });
  } catch (err: any) {
    console.error("[ADMIN_LIST_APP_ADMINS] Error:", err);
    return c.json({ error: "Failed to load application administrators" }, 500);
  }
}

export async function handlePostAppAdmins(c: any): Promise<Response> {
  const clientId = c.req.param("clientId");
  const body = await c.req.json().catch(() => ({}));
  const sessionUser = c.get("user") as any;

  // Reject conflicting client IDs between route and body
  if (body.clientId && typeof body.clientId === "string" && body.clientId !== clientId) {
    return c.json({ error: "Conflicting clientId in request body", code: "ERR_CONFLICTING_CLIENT_ID" }, 400);
  }

  const email = typeof body.email === "string" ? body.email.toLowerCase().trim() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const name = typeof body.name === "string" && body.name.trim() ? body.name.trim() : email.split("@")[0];
  const redirectUrl = typeof body.redirectUrl === "string" ? body.redirectUrl.trim() : "";

  if (!email || !email.includes("@")) {
    return c.json({ error: "Valid email address is required" }, 400);
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
    let client: any;
    try {
      client = await resolveOAuthClient(database, clientId);
    } catch (err: any) {
      console.error("[ADMIN_CREATE_APP_ADMIN] DB error resolving client:", err);
      return c.json({ error: "Failed to resolve client due to database error" }, 500);
    }

    if (!client) {
      return c.json({ error: "Application not found" }, 404);
    }

    // Enforce origin matching against client's registered origins/redirect URIs if provided
    if (redirectUrl) {
      const urlCheck = isRedirectUrlAllowedForClient(redirectUrl, client);
      if (!urlCheck.allowed) {
        return c.json({ error: urlCheck.error }, 400);
      }
    }

    const canonicalClientId = client.clientId;

    // USER-REQUIRED POLICY: Reject assigning an existing super-admin identity as an app admin.
    const userInDb = await database.collection("user").findOne({ email });
    if (userInDb && (userInDb.role === "super-admin" || (userInDb.role === "admin" && userInDb.scopedClientId === null))) {
      const reqId = (c as any).get("requestId") || c.req.header("x-request-id");
      return c.json(
        {
          error: "Identity conflict: Global Super Admin cannot be assigned as an Application Administrator",
          code: "ERR_IDENTITY_CONFLICT",
          requestId: reqId,
        },
        409
      );
    }

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

    // Ensure centralized IdP identity exists in user, account, and user_app_registrations
    try {
      const syncResult = await syncAppAdminIdentity(database, {
        email,
        clientId: canonicalClientId,
        name,
        hashedPassword,
        isActive: true,
        createdAt: now,
      });
      if (syncResult?.userId) {
        await database.collection("app_admins").updateOne(
          { _id: insertResult.insertedId },
          { $set: { userId: syncResult.userId } }
        );
      }
    } catch (provisionErr: any) {
      console.warn("[ADMIN_CREATE_APP_ADMIN] Warning syncing to centralized user collection:", provisionErr?.message || provisionErr);
    }

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
          displayLabel: toApprovedDisplayLabel(email, name),
          name: isEmailShaped(name) ? toApprovedDisplayLabel(name) : (name || toApprovedDisplayLabel(email)),
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
}
