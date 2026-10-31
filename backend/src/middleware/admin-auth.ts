import { createMiddleware } from "hono/factory";
import { importJWK, jwtVerify, decodeProtectedHeader } from "jose";
import { authProvider } from "../utils/auth";
import { getHeaders, resolveOAuthClient, timingSafeEqualStr, isLoopbackHost } from "../utils/security";
import { getDb } from "../db/mongo";
import { ObjectId } from "mongodb";
import { config } from "../config";
import crypto from "node:crypto";

export type DomainRole = "super-admin" | "app-admin" | "user";

export function isSuperAdmin(user: any): boolean {
  if (!user) return false;
  if (user.role === "super-admin") {
    // Super admin role must not have client scoping (null or undefined only; empty string or any other string fails closed)
    return user.scopedClientId === null || user.scopedClientId === undefined;
  }
  // Legacy role: "admin" strictly requires explicit null scope (never infer from missing/undefined/empty)
  if (user.role === "admin" && user.scopedClientId === null) {
    return true;
  }
  return false;
}

export function isAppAdmin(user: any): boolean {
  if (!user) return false;
  if (isSuperAdmin(user)) return false;
  if (user.role === "app-admin") {
    if (typeof user.scopedClientId === "string") {
      return user.scopedClientId.trim().length > 0;
    }
    return true;
  }
  if (user.role === "admin" && typeof user.scopedClientId === "string" && user.scopedClientId.trim().length > 0) {
    return true;
  }
  return false;
}

export function isAnyAdmin(user: any): boolean {
  return isSuperAdmin(user) || isAppAdmin(user);
}

interface CachedPublicKey {
  key: any;
  cachedAt: number;
}
const MAX_PUBLIC_KEY_CACHE_SIZE = 50;
const publicKeyCache = new Map<string, CachedPublicKey>();

function setInPublicKeyCache(keyId: string, entry: CachedPublicKey): void {
  if (publicKeyCache.size >= MAX_PUBLIC_KEY_CACHE_SIZE) {
    const oldestKey = publicKeyCache.keys().next().value;
    if (oldestKey) {
      publicKeyCache.delete(oldestKey);
    }
  }
  publicKeyCache.set(keyId, entry);
}

export function clearPublicKeyCacheForTesting(): void {
  publicKeyCache.clear();
}

export async function getIdpPublicKey(kid?: string): Promise<any> {
  const now = Date.now();
  const cacheKey = kid || "latest";
  const cached = publicKeyCache.get(cacheKey);
  if (cached && now - cached.cachedAt < 60_000) {
    return cached.key;
  }

  const database = await getDb();
  let jwksRecord: any = null;
  let matchedRequestedKid = false;

  if (kid) {
    jwksRecord = await database.collection("jwks").findOne({
      $or: [
        { kid: kid },
        { id: kid },
        ...(ObjectId.isValid(kid) ? [{ _id: new ObjectId(kid) }] : []),
      ],
    });
    if (jwksRecord) {
      matchedRequestedKid = true;
    }
  }

  if (!jwksRecord) {
    jwksRecord = await database.collection("jwks").findOne({}, { sort: { createdAt: -1 } });
  }

  if (!jwksRecord || !jwksRecord.publicKey) {
    return null;
  }

  let jwk: any;
  try {
    jwk = typeof jwksRecord.publicKey === "string" ? JSON.parse(jwksRecord.publicKey) : jwksRecord.publicKey;
  } catch {
    return null;
  }

  const importedKey = await importJWK(jwk, "RS256");
  const cacheEntry = { key: importedKey, cachedAt: now };

  // Only cache under the requested kid if it matched, or if no kid was specified (latest)
  if (cacheKey === "latest" || matchedRequestedKid) {
    setInPublicKeyCache(cacheKey, cacheEntry);
  }
  if (jwksRecord.kid) {
    setInPublicKeyCache(jwksRecord.kid, cacheEntry);
  }

  return importedKey;
}

export async function checkUserIsClientAdmin(
  database: any,
  userDoc: any,
  userIdStr: string,
  clientId: string
): Promise<boolean> {
  if (!database || !clientId || typeof clientId !== "string") return false;
  const cleanClientId = clientId.trim();
  if (!cleanClientId || cleanClientId.startsWith("$")) return false;

  // USER-REQUIRED POLICY: Super admins must never receive consumer app-admin privileges
  if (isSuperAdmin(userDoc)) return false;

  const resolvedUserId = (typeof userIdStr === "string" ? userIdStr : (userDoc?.id || userDoc?._id)?.toString()) || "";
  if (!resolvedUserId || resolvedUserId.startsWith("$")) return false;

  const userConditions: any[] = [{ userId: resolvedUserId }];
  if (ObjectId.isValid(resolvedUserId) && resolvedUserId.length === 24) {
    try {
      userConditions.push({ userId: new ObjectId(resolvedUserId) });
    } catch {}
  }

  // 1. Authoritative check in app_admins by stable userId
  // An inactive, revoked, suspended, or disabled record MUST strictly deny administration
  const appAdmin = await database.collection("app_admins").findOne({
    clientId: cleanClientId,
    $or: userConditions,
  });
  if (appAdmin) {
    const isInactive =
      appAdmin.isActive === false ||
      appAdmin.active === false ||
      appAdmin.disabled === true ||
      appAdmin.revoked === true ||
      ["inactive", "revoked", "suspended", "disabled"].includes(appAdmin.status);
    if (isInactive) return false;
    return true;
  }

  // 2. Authoritative check in user_app_registrations keyed by stable userId and clientId
  const reg = await database.collection("user_app_registrations").findOne({
    clientId: cleanClientId,
    $or: userConditions,
  });
  if (reg) {
    const isRegInactive =
      reg.isActive === false ||
      reg.active === false ||
      reg.disabled === true ||
      reg.revoked === true ||
      ["inactive", "revoked", "suspended", "disabled"].includes(reg.status);
    if (isRegInactive || reg.appRole !== "admin") return false;
    return true;
  }

  // 3. Fallback scopedClientId match if role is app-admin or legacy admin and user is not banned
  if (isAppAdmin(userDoc) && userDoc.scopedClientId === cleanClientId && !userDoc.banned && userDoc.disabled !== true) {
    return true;
  }

  return false;
}

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
async function getAuthenticatedUser(c: any): Promise<{ user: any; session: any } | null> {
  const existingUser = c.get("user");
  const existingSession = c.get("session");
  if (existingUser && existingSession) {
    return { user: existingUser, session: existingSession };
  }

  // Check for presence of both Session Cookie and Bearer Token
  const authHeader = c.req.header("authorization") || c.req.header("Authorization");
  const hasBearer = Boolean(authHeader && authHeader.startsWith("Bearer "));
  let session: any = null;

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
                cookieSessionUser = {
                  ...sessResult.user,
                  ...userDoc,
                };
                sessionObj = sessResult.session;
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

      const orConditions: any[] = [{ id: sub }, { email: sub }];
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
      if (payload.iat && typeof payload.iat === "number") {
        const tokenIatMs = payload.iat * 1000;
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

      c.set("user", fullUser);
      c.set("session", { id: `token-${sub}`, userId: sub });
      c.set("authMethod", "bearer");
      c.set("tokenAudList", audList);
      c.set("hasPlatformAudience", hasPlatformAudience);

      return { user: fullUser, session: { id: `token-${sub}`, userId: sub } };
    } catch {
      // Invalid signature, wrong algorithm (e.g. HS256), expired token, wrong issuer, etc.
      return null;
    }
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

/**
 * Gateway Trust Perimeter Helper:
 * Validates that requests entering management surfaces originate from the trusted
 * API Gateway / reverse proxy.
 *
 * GATEWAY VERIFICATION POLICY:
 * - When configured (minimum 32 characters): strictly requires matching 'x-gateway-secret' header.
 * - In production mode (NODE_ENV === "production"), unconfigured secret fails closed (false).
 * - In development mode (NODE_ENV !== "production"), unconfigured secret permits loopback requests
 *   (localhost, 127.0.0.1, [::1]) with an informational warning.
 *
 * STRICT GATEWAY HEADER CONTRACT:
 * Only 'x-gateway-secret' is accepted. Secondary headers like 'x-internal-secret'
 * are strictly forbidden and return 403 Forbidden.
 */
export function verifyGatewaySecret(c: any): boolean {
  try {
    const configuredSecret = config.internalGatewaySecret;
    const isConfigured = Boolean(
      configuredSecret &&
      typeof configuredSecret === "string" &&
      configuredSecret.trim().length > 0
    );

    if (isConfigured) {
      // STRICT GATEWAY HEADER ENFORCEMENT: Only 'x-gateway-secret' is accepted.
      const gatewayHeader = c.req.header("x-gateway-secret");
      if (!gatewayHeader || typeof gatewayHeader !== "string") {
        return false;
      }

      // Read secrets purely from environment configuration (supports comma-separated values for rotation)
      const allowedSecrets = (configuredSecret as string)
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length >= 32);

      if (allowedSecrets.length === 0) {
        return false;
      }

      for (const secret of allowedSecrets) {
        if (timingSafeEqualStr(gatewayHeader, secret)) {
          return true;
        }
      }
      return false;
    }

    // Unconfigured secret behavior:
    const isProduction = config.env === "production" || process.env.NODE_ENV === "production";
    if (isProduction) {
      return false;
    }

    // Development mode bypass: permit loopback host requests
    const remoteAddress =
      c?.env?.incoming?.socket?.remoteAddress ||
      c?.req?.raw?.socket?.remoteAddress ||
      c?.req?.raw?.connection?.remoteAddress ||
      c?.raw?.socket?.remoteAddress ||
      c?.req?.socket?.remoteAddress;

    if (remoteAddress && typeof remoteAddress === "string" && !isLoopbackHost(remoteAddress)) {
      return false;
    }

    let requestHost = "";
    try {
      const hostHeader = c.req.header("host") || c.req.header("x-forwarded-host") || "";
      if (hostHeader) {
        const url = new URL(`http://${hostHeader}`);
        requestHost = url.hostname;
      } else if (c.req.url) {
        requestHost = new URL(c.req.url).hostname;
      }
    } catch {
      requestHost = (c.req.header("host") || "").replace(/:\d+$/, "");
    }

    if (requestHost && isLoopbackHost(requestHost)) {
      console.warn(
        `[dev-gateway-bypass] INTERNAL_GATEWAY_SECRET is unconfigured. Allowing loopback request from host "${requestHost}". Set INTERNAL_GATEWAY_SECRET to secure administrative endpoints.`
      );
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Standalone middleware to enforce Gateway Trust on management endpoints.
 */
export const requireGatewayTrust = createMiddleware(async (c, next) => {
  if (!verifyGatewaySecret(c)) {
    const reqId = c.get("requestId") || c.req.header("x-request-id") || crypto.randomUUID();
    c.header("x-request-id", reqId);
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
  return next();
});

export function extractTargetClientId(c: any): string | null {
  const paramId = c.req.param("id") || c.req.param("clientId");
  if (paramId && typeof paramId === "string" && paramId.trim().length > 0) {
    return paramId.trim();
  }

  const path = c.req.path || "";
  const clientsMatch = path.match(/^\/api\/admin\/clients\/([^\/?#]+)/);
  if (clientsMatch && clientsMatch[1]) {
    return decodeURIComponent(clientsMatch[1]).trim();
  }
  const appMatch = path.match(/^\/api\/admin\/app\/([^\/?#]+)/);
  if (appMatch && appMatch[1]) {
    return decodeURIComponent(appMatch[1]).trim();
  }

  return null;
}

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
