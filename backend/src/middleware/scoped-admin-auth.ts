import { createMiddleware } from "hono/factory";
import crypto from "node:crypto";
import { resolveOAuthClient } from "../utils/security";
import { getDb } from "../db/mongo";
import { isSuperAdmin, isAppAdmin, isAnyAdmin } from "./admin-roles";
import { verifyGatewaySecret } from "./gateway-trust";
import { checkAdminMfa } from "./admin-mfa";
import { getAuthenticatedUser, checkUserIsClientAdmin } from "./admin-user";
import { extractTargetClientId } from "./admin-context";

/**
 * Scoped-Admin Middleware: App-level operations (managing registered clients or own client config)
 */
export const requireScopedAdmin = createMiddleware(async (c, next) => {
  const reqId = c.get("requestId") || c.req.header("x-request-id") || crypto.randomUUID();
  c.header("x-request-id", reqId);

  // 1. Enforce Gateway Trust Boundary
  if (!verifyGatewaySecret(c)) {
    return c.json(
      {
        error: "forbidden",
        code: "ERR_GATEWAY_FORBIDDEN",
        message: "Direct access to management endpoints forbidden; gateway authentication required",
        requestId: reqId,
      },
      403
    );
  }

  // 2. Enforce User Authentication
  const auth = await getAuthenticatedUser(c);

  if (!auth) {
    return c.json(
      {
        error: "Authentication required",
        code: "ERR_UNAUTHENTICATED",
        message: "Authentication required",
        requestId: reqId,
      },
      401
    );
  }

  // 3. Enforce Admin Role
  if (!isAnyAdmin(auth.user)) {
    return c.json(
      {
        error: "Admin access required",
        code: "ERR_ROLE_FORBIDDEN",
        message: "Admin access required",
        requestId: reqId,
      },
      403
    );
  }

  // 3.5. Enforce Administrative MFA Policy (Slice 3)
  const mfaCheck = checkAdminMfa(c, auth.user, auth.session, reqId);
  if (mfaCheck) return mfaCheck;

  // 4. Enforce mandatory password change for freshly provisioned temporary accounts
  if (auth.user?.mustChangePassword === true) {
    return c.json(
      {
        error: "password_change_required",
        code: "ERR_PASSWORD_CHANGE_REQUIRED",
        message: "Temporary password must be changed before accessing admin operations",
        requestId: reqId,
      },
      403
    );
  }

  // 5. Enforce Scoped Tenant Boundaries & Audience Matching
  const targetClientId = extractTargetClientId(c);
  if (!targetClientId) {
    return c.json(
      {
        error: "forbidden",
        code: "ERR_TARGET_CLIENT_REQUIRED",
        message: "Target application client ID is required for scoped admin operations",
        requestId: reqId,
      },
      403
    );
  }

  const database = await getDb();
  const resolvedClient = await resolveOAuthClient(database, targetClientId);
  const canonicalTargetId = resolvedClient ? resolvedClient.clientId : targetClientId;

  const isGlobal = isSuperAdmin(auth.user);
  const rawScopedId = auth.user?.scopedClientId;
  const scopedClientId = typeof rawScopedId === "string" && rawScopedId.trim().length > 0
    ? rawScopedId.trim()
    : null;

  // Strict Scoped Admin Semantics:
  // Must be either a verified global super admin (scopedClientId === null) managing registered app
  // OR a verified scoped admin whose scopedClientId matches the canonicalTargetId.
  if (!isGlobal) {
    let isAuthorized = scopedClientId === canonicalTargetId;
    if (!isAuthorized) {
      const userIdStr = (auth.user?.id || auth.user?._id)?.toString() || "";
      isAuthorized = await checkUserIsClientAdmin(database, auth.user, userIdStr, canonicalTargetId);
    }
    if (!isAuthorized) {
      return c.json(
        {
          error: "forbidden",
          code: "ERR_CROSS_TENANT_FORBIDDEN",
          message: "Cross-tenant access forbidden: you can only manage your own assigned application",
          requestId: reqId,
        },
        403
      );
    }
  }

  // Strict Bearer Token Audience Validation for Scoped Management APIs:
  if (c.get("authMethod") === "bearer") {
    const hasPlatformAud = c.get("hasPlatformAudience");
    const tokenAudList: string[] = c.get("tokenAudList") || [];

    const audMatchesTarget = tokenAudList.includes(canonicalTargetId);
    const isAllowedAudience = (isGlobal && hasPlatformAud) || audMatchesTarget;

    if (!isAllowedAudience) {
      return c.json(
        {
          error: "forbidden",
          code: "ERR_AUDIENCE_FORBIDDEN",
          message: `Token audience invalid: bearer token audience does not match target application '${canonicalTargetId}'`,
          requestId: reqId,
        },
        403
      );
    }
  }

  c.set("scopedClientId", scopedClientId || null);
  return next();
});

/**
 * Consumer App-Admin Guard: Strictly for consumer app administrative operations for a specific client.
 * USER-REQUIRED POLICY: Super admins must never receive consumer app-admin privileges or enter consumer admin portals.
 */
export const requireConsumerAppAdmin = createMiddleware(async (c, next) => {
  const reqId = c.get("requestId") || c.req.header("x-request-id") || crypto.randomUUID();
  c.header("x-request-id", reqId);

  // 1. Enforce Gateway Trust Boundary
  if (!verifyGatewaySecret(c)) {
    return c.json(
      {
        error: "forbidden",
        code: "ERR_GATEWAY_FORBIDDEN",
        message: "Direct access to management endpoints forbidden; gateway authentication required",
        requestId: reqId,
      },
      403
    );
  }

  // 2. Enforce User Authentication
  const auth = await getAuthenticatedUser(c);

  if (!auth) {
    return c.json(
      {
        error: "unauthorized",
        code: "ERR_UNAUTHENTICATED",
        message: "Authentication required",
        requestId: reqId,
      },
      401
    );
  }

  // 3. Super Admins must NEVER receive consumer app-admin privileges or enter consumer admin portals
  if (isSuperAdmin(auth.user)) {
    return c.json(
      {
        error: "forbidden",
        code: "ERR_SUPER_ADMIN_NOT_CONSUMER_ADMIN",
        message: "Super-Admin identities cannot perform consumer application admin operations. Use an assigned application admin identity.",
        requestId: reqId,
      },
      403
    );
  }

  // 4. Must be an App Admin
  if (!isAppAdmin(auth.user)) {
    return c.json(
      {
        error: "forbidden",
        code: "ERR_ROLE_FORBIDDEN",
        message: "Application administrator privileges required",
        requestId: reqId,
      },
      403
    );
  }

  // 4.5. Enforce Administrative MFA Policy
  const mfaCheck = checkAdminMfa(c, auth.user, auth.session, reqId);
  if (mfaCheck) return mfaCheck;

  // 5. Must change password if temporary
  if (auth.user?.mustChangePassword === true) {
    return c.json(
      {
        error: "password_change_required",
        code: "ERR_PASSWORD_CHANGE_REQUIRED",
        message: "Temporary password must be changed before accessing admin operations",
        requestId: reqId,
      },
      403
    );
  }

  const targetClientId = extractTargetClientId(c);
  if (!targetClientId) {
    return c.json(
      {
        error: "forbidden",
        code: "ERR_TARGET_CLIENT_REQUIRED",
        message: "Target application client ID is required for consumer admin operations",
        requestId: reqId,
      },
      403
    );
  }

  const database = await getDb();
  const resolvedClient = await resolveOAuthClient(database, targetClientId);
  const canonicalTargetId = resolvedClient ? resolvedClient.clientId : targetClientId;

  const userIdStr = (auth.user?.id || auth.user?._id)?.toString() || "";
  const isAuthorized = await checkUserIsClientAdmin(database, auth.user, userIdStr, canonicalTargetId);

  if (!isAuthorized) {
    return c.json(
      {
        error: "forbidden",
        code: "ERR_CROSS_TENANT_FORBIDDEN",
        message: "Cross-tenant access forbidden: you can only manage your own assigned application",
        requestId: reqId,
      },
      403
    );
  }

  c.set("scopedClientId", canonicalTargetId);
  return next();
});
