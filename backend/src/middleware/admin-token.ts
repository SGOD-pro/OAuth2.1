import { decodeProtectedHeader, jwtVerify } from "jose";
import { config } from "../config";
import { getDb } from "../db/mongo";
import { ObjectId } from "mongodb";
import { getIdpPublicKey } from "./admin-keys";
import { isSuperAdmin } from "./admin-roles";
import { checkUserIsClientAdmin } from "./admin-membership";

export async function verifyAdminBearerToken(
  c: any,
  token: string,
  cookieHeader: string | null | undefined,
  cookieSessionUser: any
): Promise<{ user: any; session: any } | null> {
  try {
    let kid: string | undefined;
    try {
      const header = decodeProtectedHeader(token);
      kid = header.kid;
    } catch {}
    const publicKey = await getIdpPublicKey(kid);
    if (!publicKey) return null;

    // STRICT ALGORITHM PINNING: strictly require RS256 (rejects HS256, none, forged)
    // STRICT ISSUER VALIDATION: iss must match baseURL
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ["RS256"],
      issuer: config.auth.baseURL,
    });

    // Mandatory Subject Claim
    const sub = payload.sub;
    if (!sub || typeof sub !== "string" || sub.trim().length === 0) {
      return null;
    }

    // Conflicting Credentials Defense:
    // If caller supplied both a cookie session and a bearer token, they must identify the same user.
    // If a session cookie was provided but failed verification (tampered, expired, or invalid), fail closed.
    if (cookieHeader && cookieHeader.includes("better-auth.session_token")) {
      if (!cookieSessionUser) {
        // Tampered, expired, or invalid cookie accompanied by bearer token: fail closed
        return null;
      }
      const sessionUserId = String(cookieSessionUser.id || cookieSessionUser._id || "");
      const sessionEmail = String(cookieSessionUser.email || "").toLowerCase().trim();
      const tokenSub = String(sub).toLowerCase().trim();
      const isSameIdentity = sessionUserId === sub || sessionEmail === tokenSub;
      if (!isSameIdentity) {
        // Conflicting credentials from different accounts: fail closed
        return null;
      }
    }

    // Mandatory Audience Claim
    if (!payload.aud) {
      return null;
    }
    const audList = (Array.isArray(payload.aud) ? payload.aud : [payload.aud])
      .filter((a): a is string => typeof a === "string" && a.trim().length > 0);
    if (audList.length === 0) {
      return null;
    }

    const validPlatformAuds = new Set([
      config.auth.baseURL,
      config.frontendUrl,
    ].filter(Boolean));

    const hasPlatformAudience = audList.some((a) => validPlatformAuds.has(a));

    const database = await getDb();

    // Check if audience is recognized at all by this IdP (platform audience or registered OAuth client)
    if (!hasPlatformAudience) {
      const clientMatch = await database.collection("oauthClient").findOne({
        $or: audList.map((a) => ({ clientId: a })),
      });
      if (!clientMatch) {
        // Token audience is completely unregistered / unknown to this IdP
        return null;
      }
    }

    const orConditions: any[] = [{ id: sub }];
    if (ObjectId.isValid(sub) && sub.length === 24) {
      try {
        orConditions.push({ _id: new ObjectId(sub) });
      } catch {}
    }
    const userDoc = await database.collection("user").findOne({
      $or: orConditions,
    });

    // User MUST exist in database and account must not be disabled/banned
    if (!userDoc || userDoc.disabled === true || userDoc.isActive === false || userDoc.banned === true) {
      return null;
    }

    // Revocation timestamps check: reject replayed tokens issued before revocation or password change
    const tokenIatMs = typeof payload.iat_ms === "number"
      ? payload.iat_ms
      : (payload.iat && typeof payload.iat === "number" ? payload.iat * 1000 : null);
    const tokenVersion = typeof payload.token_version === "number" ? payload.token_version : undefined;

    if (tokenVersion !== undefined && userDoc.tokenVersion !== undefined && tokenVersion < userDoc.tokenVersion) {
      return null;
    }

    if (tokenIatMs !== null) {
      if (userDoc.tokensRevokedBefore) {
        const revokedMs = new Date(userDoc.tokensRevokedBefore).getTime();
        if (tokenIatMs < revokedMs) return null;
      }
      if (userDoc.passwordChangedAt) {
        const passChangedMs = new Date(userDoc.passwordChangedAt).getTime();
        if (tokenIatMs < passChangedMs) return null;
      }
    }

    // Role authorization:
    // Signed token claims must NEVER be elevated by database fallback.
    // If the token explicitly grants 'user' (or omits role), the caller cannot be elevated to 'admin'.
    // An app-admin token can NEVER be elevated to super-admin even if the DB user has platform privileges.
    // Incompatible token and DB roles, or ambiguous legacy credentials, must fail closed.
    let role = "user";
    let scopedClientId: string | null | undefined;

    const rawTokenRole = payload.role;
    const rawTokenScope = payload.scoped_client_id;

    if (rawTokenRole === "super-admin") {
      // Super admin tokens must be unscoped
      if (rawTokenScope !== null && rawTokenScope !== undefined) {
        return null; // A super-admin token cannot carry a client scope
      }
      if (!hasPlatformAudience) {
        return null; // Platform super-admin token requires platform audience
      }
      if (!isSuperAdmin(userDoc)) {
        return null; // Database user must also be verified super-admin
      }
      role = "super-admin";
      scopedClientId = null;
    } else if (rawTokenRole === "app-admin") {
      // App admin tokens must have valid non-empty scope
      if (typeof rawTokenScope !== "string" || rawTokenScope.trim().length === 0) {
        return null; // App admin token requires valid client scope
      }
      const cleanTokenScope = rawTokenScope.trim();
      if (isSuperAdmin(userDoc)) {
        // USER-REQUIRED POLICY: Super admins must never receive consumer app-admin privileges or enter consumer admin portals
        // Never elevate or accept app-admin token for super-admin DB identity
        return null;
      }
      // Verify active client admin membership in database
      const isClientAdmin = await checkUserIsClientAdmin(database, userDoc, sub, cleanTokenScope);
      if (!isClientAdmin) {
        return null;
      }
      role = "app-admin";
      scopedClientId = cleanTokenScope;
    } else if (rawTokenRole === "admin") {
      // Legacy admin token handling:
      // Must have explicit null scope (legacy super-admin) OR non-empty string scope (legacy app-admin).
      // Ambiguous credentials (missing, undefined, empty string) strictly fail closed.
      if (rawTokenScope === null) {
        if (!hasPlatformAudience || !isSuperAdmin(userDoc)) {
          return null;
        }
        role = "super-admin";
        scopedClientId = null;
      } else if (typeof rawTokenScope === "string" && rawTokenScope.trim().length > 0) {
        const cleanTokenScope = rawTokenScope.trim();
        if (isSuperAdmin(userDoc)) {
          return null;
        }
        const isClientAdmin = await checkUserIsClientAdmin(database, userDoc, sub, cleanTokenScope);
        if (!isClientAdmin) {
          return null;
        }
        role = "app-admin";
        scopedClientId = cleanTokenScope;
      } else {
        // Ambiguous legacy credentials: fail closed
        return null;
      }
    } else {
      // Standard user or unrecognized role: cannot possess administrative privileges
      role = "user";
      scopedClientId = undefined;
    }

    const fullUser = {
      ...userDoc,
      id: sub,
      role,
      scopedClientId,
    };

    const isMfaVerified = Boolean(
      payload.mfa === true ||
      (Array.isArray(payload.amr) && payload.amr.includes("mfa"))
    );
    const mfaVerifiedAt = typeof payload.mfa_verified_at === "number"
      ? new Date(payload.mfa_verified_at * 1000)
      : (typeof payload.iat === "number" ? new Date(payload.iat * 1000) : null);

    const bearerSessionObj = {
      id: `token-${sub}`,
      userId: sub,
      twoFactorVerified: isMfaVerified,
      mfaVerifiedAt: isMfaVerified ? mfaVerifiedAt : null,
    };

    c.set("user", fullUser);
    c.set("session", bearerSessionObj);
    c.set("authMethod", "bearer");
    c.set("tokenAudList", audList);
    c.set("hasPlatformAudience", hasPlatformAudience);

    return { user: fullUser, session: bearerSessionObj };
  } catch {
    // Invalid signature, wrong algorithm (e.g. HS256), expired token, wrong issuer, etc.
    return null;
  }
}
