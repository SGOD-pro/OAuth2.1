import { createMiddleware } from "hono/factory";
import crypto from "node:crypto";
import { isAnyAdmin } from "./admin-roles";
import { getAuthenticatedUser } from "./admin-user";

/**
 * Authoritative Administrative MFA Policy Enforcement (Slice 3).
 *
 * Rules:
 * 1. Both super-admin and app-admin roles MUST have enrolled TOTP (twoFactorEnabled === true).
 * 2. Unenrolled administrators receive setup-only authority (can only access setup/recovery routes).
 * 3. Enrolled administrators must have completed MFA in the current session/token.
 * 4. Enrollment flags alone do not prove completed MFA.
 */
export function checkAdminMfa(c: any, user: any, session: any, reqId: string): Response | null {
  if (!isAnyAdmin(user)) return null;

  const path = c.req.path || "";
  const isSetupRoute =
    path.startsWith("/api/auth/two-factor") ||
    path.startsWith("/api/admin/two-factor") ||
    path === "/api/admin/me" ||
    path === "/api/auth/sign-out";

  // 1. Mandatory Enrollment Check
  if (user.twoFactorEnabled !== true) {
    if (!isSetupRoute) {
      return c.json(
        {
          error: "mfa_required",
          code: "ERR_MFA_ENROLLMENT_REQUIRED",
          message: "MFA enrollment is required for administrative accounts. Access is restricted to setup operations until TOTP is enrolled.",
          requestId: reqId,
        },
        403
      );
    }
  } else {
    // 2. Completed Verification Check for Current Session
    const isMfaCompleted = Boolean(session?.twoFactorVerified === true);
    if (!isMfaCompleted) {
      if (!isSetupRoute) {
        return c.json(
          {
            error: "mfa_required",
            code: "ERR_MFA_REQUIRED",
            message: "Two-factor authentication must be completed before accessing administrative operations.",
            requestId: reqId,
          },
          403
        );
      }
    }
  }

  return null;
}

export const requireRecentMfa = createMiddleware(async (c, next) => {
  const reqId = c.get("requestId") || c.req.header("x-request-id") || crypto.randomUUID();
  let session = c.get("session");
  if (!session) {
    const auth = await getAuthenticatedUser(c);
    session = auth?.session;
  }
  const mfaVerifiedAt = session?.mfaVerifiedAt ? new Date(session.mfaVerifiedAt).getTime() : 0;
  const now = Date.now();
  const MAX_MFA_AGE_MS = 15 * 60 * 1000; // 15 minutes

  if (!mfaVerifiedAt || now - mfaVerifiedAt > MAX_MFA_AGE_MS) {
    return c.json(
      {
        error: "mfa_step_up_required",
        code: "ERR_MFA_STEP_UP_REQUIRED",
        message: "Recent two-factor authentication (< 15 minutes) is required for sensitive administrative operations.",
        requestId: reqId,
      },
      403
    );
  }
  return next();
});
