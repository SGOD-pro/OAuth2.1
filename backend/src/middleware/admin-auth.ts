import { createMiddleware } from "hono/factory";
import crypto from "node:crypto";
import { isSuperAdmin, isAnyAdmin } from "./admin-roles";
import { verifyGatewaySecret } from "./gateway-trust";
import { checkAdminMfa } from "./admin-mfa";
import { getAuthenticatedUser } from "./admin-user";
import { extractTargetClientId } from "./admin-context";

export * from "./admin-roles";
export * from "./admin-keys";
export * from "./admin-membership";
export * from "./admin-token";
export * from "./admin-user";
export * from "./gateway-trust";
export * from "./admin-mfa";
export * from "./admin-context";
export * from "./scoped-admin-auth";

export const requireAdmin = createMiddleware(async (c, next) => {
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

  // 3. Enforce Admin Role (either super-admin or app-admin, but not user or conflicting/unknown)
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

  // 4. Strict Bearer-Token Audience Validation for Central Platform Management APIs:
  // Privileged central management APIs must NOT accept arbitrary registered client audiences.
  if (c.get("authMethod") === "bearer") {
    const targetClientId = extractTargetClientId(c);

    if (!targetClientId) {
      const hasPlatformAud = c.get("hasPlatformAudience");
      if (!hasPlatformAud) {
        return c.json(
          {
            error: "forbidden",
            code: "ERR_AUDIENCE_FORBIDDEN",
            message: "Token audience invalid: Central platform management APIs require platform administrator audience",
            requestId: reqId,
          },
          403
        );
      }
    }
  }

  return next();
});

/**
 * Super-Admin Middleware: Global operations only (client creation, user provisioning, global stats/logs)
 */
export const requireSuperAdmin = createMiddleware(async (c, next) => {
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

  // 4. Enforce Super-Admin Privilege Scope
  if (!isSuperAdmin(auth.user)) {
    return c.json(
      {
        error: "forbidden",
        code: "ERR_SUPER_ADMIN_REQUIRED",
        message: "Super-Admin privileges required for this global administrative operation",
        requestId: reqId,
      },
      403
    );
  }

  // 5. Strict Bearer Token Audience Validation for Central Platform Management APIs:
  if (c.get("authMethod") === "bearer") {
    const hasPlatformAud = c.get("hasPlatformAudience");
    if (!hasPlatformAud) {
      return c.json(
        {
          error: "forbidden",
          code: "ERR_AUDIENCE_FORBIDDEN",
          message: "Token audience invalid: Central platform management APIs require platform administrator audience",
          requestId: reqId,
        },
        403
      );
    }
  }

  return next();
});
