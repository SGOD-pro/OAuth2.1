import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { ObjectId } from "mongodb";
import { verifyAdminBearerToken } from "./admin-token";
import { checkUserIsClientAdmin } from "./admin-membership";

export { checkUserIsClientAdmin, verifyAdminBearerToken };

/**
 * Helper to fetch session and user document once per request and cache on context `c`.
 * Supports Better Auth cookie sessions AND signed OAuth 2.1 RS256 Bearer tokens.
 *
 * TRUST MODEL:
 * 1. RS256 Cryptographic Verification: Tokens must be signed by the IdP private key.
 *    Symmetric (HS256) or unsigned (none) tokens are strictly rejected.
 * 2. Strict Issuer Validation: Issuer must match config.auth.baseURL exactly.
 * 3. Strict Audience Validation: Tokens must have a non-empty audience claim.
 *    - Central platform management operations require platform administrator audience.
 *    - Scoped application operations require matching canonical client audience.
 * 4. Zero Privilege Escalation: Signed token claims can NEVER be elevated by database fallback.
 *    A caller only possesses 'admin' if BOTH the signed token and database record agree.
 * 5. Strict Tenant Scoping: Union of constraints. If either token or database scopes the user,
 *    they are strictly constrained to that application and cannot act globally.
 */
export async function getAuthenticatedUser(c: any): Promise<{ user: any; session: any } | null> {
  const existingUser = c.get("user");
  const existingSession = c.get("session");
  if (existingUser && existingSession) {
    return { user: existingUser, session: existingSession };
  }

  // Check for presence of both Session Cookie and Bearer Token
  const authHeader = c.req.header("authorization") || c.req.header("Authorization");
  const hasBearer = Boolean(authHeader && authHeader.startsWith("Bearer "));

  // Resolve session identity from cookie (authenticated through supported Better Auth verification)
  let cookieSessionUser: any = null;
  let sessionObj: any = null;
  const cookieHeader = c.req.header("cookie") || c.req.header("Cookie");
  if (cookieHeader) {
    try {
      const headers = new Headers();
      headers.set("cookie", cookieHeader);
      const host = c.req.header("host") || c.req.header("Host");
      if (host) headers.set("host", host);
      const origin = c.req.header("origin") || c.req.header("Origin");
      if (origin) headers.set("origin", origin);

      const sessResult = await authProvider.api.getSession({ headers });
      if (sessResult?.session && sessResult?.user) {
        // Enforce expiration
        const expiresAtMs = sessResult.session.expiresAt
          ? new Date(sessResult.session.expiresAt).getTime()
          : 0;
        if (expiresAtMs > Date.now()) {
          const sessionUserId = sessResult.user.id || sessResult.session.userId;
          if (sessionUserId) {
            const database = await getDb();
            const uConditions: any[] = [{ id: sessionUserId }, { id: String(sessionUserId) }];
            if (ObjectId.isValid(sessionUserId) && String(sessionUserId).length === 24) {
              try {
                uConditions.push({ _id: new ObjectId(sessionUserId) });
              } catch {}
            }
            const userDoc = await database.collection("user").findOne({
              $or: uConditions,
            });

            // Account must exist and not be disabled / banned / inactive
            if (userDoc && !userDoc.disabled && userDoc.isActive !== false && !userDoc.banned) {
              // Revocation check
              const sessionCreatedAtMs = sessResult.session.createdAt
                ? new Date(sessResult.session.createdAt).getTime()
                : null;
              let isRevoked = false;
              if (sessionCreatedAtMs) {
                if (userDoc.tokensRevokedBefore && sessionCreatedAtMs < new Date(userDoc.tokensRevokedBefore).getTime()) {
                  isRevoked = true;
                }
                if (userDoc.passwordChangedAt && sessionCreatedAtMs < new Date(userDoc.passwordChangedAt).getTime()) {
                  isRevoked = true;
                }
              }
              if (!isRevoked) {
                const tokenVal = sessResult.session.token;
                const dbSessionDoc = tokenVal
                  ? await database.collection("session").findOne({ token: tokenVal })
                  : (sessResult.session.id ? await database.collection("session").findOne({ id: sessResult.session.id }) : null);

                const sessSession = sessResult.session as any;
                const isTwoFactorVerified = Boolean(
                  sessSession.twoFactorVerified === true ||
                  dbSessionDoc?.twoFactorVerified === true
                );
                const mfaVerifiedAt = dbSessionDoc?.mfaVerifiedAt || sessSession.mfaVerifiedAt || (isTwoFactorVerified ? sessResult.session.createdAt : null);

                cookieSessionUser = {
                  ...sessResult.user,
                  ...userDoc,
                };
                sessionObj = {
                  ...sessResult.session,
                  twoFactorVerified: isTwoFactorVerified,
                  mfaVerifiedAt,
                };
              }
            }
          }
        }
      }
    } catch {
      cookieSessionUser = null;
      sessionObj = null;
    }
  }

  // 1. If Bearer Token is supplied, evaluate OAuth 2.1 RS256 Bearer Token
  if (hasBearer) {
    const token = authHeader.slice(7).trim();
    if (!token) return null;
    return await verifyAdminBearerToken(c, token, cookieHeader, cookieSessionUser);
  }

  // 2. Fall back to Session Cookie if present
  if (cookieSessionUser) {
    let scopedClientId: string | null | undefined;
    if (cookieSessionUser.scopedClientId === null) {
      scopedClientId = null;
    } else if (typeof cookieSessionUser.scopedClientId === "string" && cookieSessionUser.scopedClientId.trim().length > 0) {
      scopedClientId = cookieSessionUser.scopedClientId.trim();
    } else {
      scopedClientId = undefined;
    }

    let role = "user";
    if (cookieSessionUser.role === "super-admin" && (scopedClientId === null || scopedClientId === undefined)) {
      role = "super-admin";
      scopedClientId = null;
    } else if (cookieSessionUser.role === "admin" && scopedClientId === null) {
      role = "super-admin";
      scopedClientId = null;
    } else if (cookieSessionUser.role === "app-admin" && typeof scopedClientId === "string") {
      role = "app-admin";
    } else if (cookieSessionUser.role === "admin" && typeof scopedClientId === "string") {
      role = "app-admin";
    } else if (cookieSessionUser.role === "app-admin" && (scopedClientId === null || scopedClientId === undefined)) {
      role = "app-admin";
      scopedClientId = undefined;
    }

    const fullUser = {
      ...cookieSessionUser,
      role,
      scopedClientId,
    };
    c.set("user", fullUser);
    c.set("session", sessionObj || { id: `session-${fullUser.id}`, userId: fullUser.id });
    c.set("authMethod", "session");
    c.set("hasPlatformAudience", true);

    return { user: fullUser, session: sessionObj || { id: `session-${fullUser.id}`, userId: fullUser.id } };
  }

  return null;
}
