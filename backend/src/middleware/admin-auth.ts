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
    // Super admin role must not have client scoping
    return !user.scopedClientId || user.scopedClientId === null;
  }
  // Legacy role: "admin" strictly requires explicit null scope (never infer from missing/undefined)
  if (user.role === "admin" && user.scopedClientId === null) {
    return true;
  }
  return false;
}

export function isAppAdmin(user: any): boolean {
  if (!user) return false;
  if (user.role === "app-admin") {
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
  if (!database || !clientId) return false;
  // USER-REQUIRED POLICY: Super admins must never receive consumer app-admin privileges
  if (isSuperAdmin(userDoc)) return false;

  const resolvedUserId = userIdStr || (userDoc?.id || userDoc?._id)?.toString();
  if (!resolvedUserId) return false;

  // 1. Primary scopedClientId match if role is app-admin or legacy admin
  if (isAppAdmin(userDoc) && userDoc.scopedClientId === clientId) {
    return true;
  }

  // 2. Authoritative check in user_app_registrations keyed by stable userId and clientId
  const userConditions: any[] = [{ userId: resolvedUserId }];
  if (ObjectId.isValid(resolvedUserId)) {
    userConditions.push({ userId: new ObjectId(resolvedUserId) });
  }

  const reg = await database.collection("user_app_registrations").findOne({
    clientId,
    $or: userConditions,
    appRole: "admin",
  });
  if (reg) return true;

  // 3. Authoritative check in app_admins by stable userId (email alone never grants privileges)
  const appAdmin = await database.collection("app_admins").findOne({
    clientId,
    $or: userConditions,
    isActive: { $ne: false },
  });
  if (appAdmin) return true;

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

  // 1. Try Better Auth Session (Cookie / Session token)
  const session = await authProvider.api.getSession({
    headers: getHeaders(c),
  });

  if (session && session.user) {
    const database = await getDb();
    const userDoc = await database.collection("user").findOne({
      $or: [{ id: session.user.id }, { _id: (session.user as any)._id }, { email: session.user.email }],
    });

    if (userDoc && (userDoc.disabled === true || userDoc.isActive === false || userDoc.banned === true)) {
      return null;
    }

    let scopedClientId: string | null | undefined;
    if (userDoc?.scopedClientId === null) {
      scopedClientId = null;
    } else if (typeof userDoc?.scopedClientId === "string" && userDoc.scopedClientId.trim().length > 0) {
      scopedClientId = userDoc.scopedClientId.trim();
    } else {
      scopedClientId = undefined;
    }

    let role = userDoc?.role || session.user.role || "user";
    if (userDoc?.role === "super-admin" || (userDoc?.role === "admin" && scopedClientId === null)) {
      role = "super-admin";
      scopedClientId = null;
    } else if (userDoc?.role === "app-admin" || (userDoc?.role === "admin" && typeof scopedClientId === "string")) {
      role = "app-admin";
    }

    const fullUser = {
      ...session.user,
      ...userDoc,
      role,
      scopedClientId,
    };
    c.set("user", fullUser);
    c.set("session", session.session);
    c.set("authMethod", "session");
    c.set("hasPlatformAudience", true);

    return { user: fullUser, session: session.session };
  }

  // 2. Try OAuth 2.1 RS256 Bearer Token
  const authHeader = c.req.header("authorization") || c.req.header("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
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
      if (ObjectId.isValid(sub)) {
        orConditions.push({ _id: new ObjectId(sub) });
      }
      const userDoc = await database.collection("user").findOne({
        $or: orConditions,
      });

      // If user document exists, account must not be disabled
      if (userDoc && (userDoc.disabled === true || userDoc.isActive === false)) {
        return null;
      }

      // Role authorization:
      // Signed token claims must NEVER be elevated by database fallback.
      // If the token explicitly grants 'user' (or omits role), the caller cannot be elevated to 'admin'.
      // If a database record exists, caller only possesses 'admin' if BOTH token and DB agree.
      let role = "user";
      const isTokenAdmin = payload.role === "admin" || payload.role === "super-admin" || payload.role === "app-admin";
      if (isTokenAdmin) {
        if (!userDoc || userDoc.role === "admin" || userDoc.role === "super-admin" || userDoc.role === "app-admin") {
          if (userDoc?.role === "super-admin" || (userDoc?.role === "admin" && userDoc?.scopedClientId === null)) {
            role = "super-admin";
          } else if (userDoc?.role === "app-admin" || (userDoc?.role === "admin" && typeof userDoc?.scopedClientId === "string")) {
            role = "app-admin";
          } else {
            role = (payload.role as string) || "admin";
          }
        }
      }

      // Scoped application binding:
      // Scoping is the union of constraints: if either the signed token or the database
      // specifies a scoped client ID, the caller is strictly constrained to that tenant.
      // A scoped admin can NEVER escalate to Global Super Admin (null/unscoped).
      let tokenScope: string | null | undefined;
      if (payload.scoped_client_id === null) {
        tokenScope = null;
      } else if (typeof payload.scoped_client_id === "string") {
        const trimmed = payload.scoped_client_id.trim();
        tokenScope = trimmed.length > 0 ? trimmed : undefined;
      } else {
        tokenScope = undefined;
      }

      let dbScope: string | null | undefined;
      if (userDoc) {
        if (userDoc.scopedClientId === null) {
          dbScope = null;
        } else if (typeof userDoc.scopedClientId === "string") {
          const trimmed = userDoc.scopedClientId.trim();
          dbScope = trimmed.length > 0 ? trimmed : undefined;
        } else {
          dbScope = undefined;
        }
      } else {
        dbScope = null;
      }

      if (typeof tokenScope === "string" && typeof dbScope === "string" && tokenScope !== dbScope) {
        // Cross-tenant check: allow if caller is an authorized administrator for tokenScope
        const isAuthorizedForTokenScope = await checkUserIsClientAdmin(database, userDoc, sub, tokenScope);
        if (!isAuthorizedForTokenScope) {
          // Cross-tenant identity conflict: token scope and user document scope conflict
          return null;
        }
      }

      let scopedClientId: string | null | undefined;
      if (typeof tokenScope === "string") {
        scopedClientId = tokenScope;
      } else if (typeof dbScope === "string") {
        scopedClientId = dbScope;
      } else if (tokenScope === null && dbScope === null) {
        scopedClientId = null;
      } else {
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
