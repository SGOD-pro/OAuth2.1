import { createMiddleware } from "hono/factory";
import { importJWK, jwtVerify } from "jose";
import { authProvider } from "../utils/auth";
import { getHeaders, resolveOAuthClient, timingSafeEqualStr } from "../utils/security";
import { getDb } from "../db/mongo";
import { config } from "../config";

let cachedPublicKey: any = null;
let lastKeyFetch = 0;

export async function getIdpPublicKey(): Promise<any> {
  const now = Date.now();
  if (cachedPublicKey && now - lastKeyFetch < 60_000) {
    return cachedPublicKey;
  }
  const database = await getDb();
  const jwksRecord = await database.collection("jwks").findOne({}, { sort: { createdAt: -1 } });
  if (!jwksRecord || !jwksRecord.publicKey) {
    return null;
  }
  const jwk = typeof jwksRecord.publicKey === "string" ? JSON.parse(jwksRecord.publicKey) : jwksRecord.publicKey;
  cachedPublicKey = await importJWK(jwk, "RS256");
  lastKeyFetch = now;
  return cachedPublicKey;
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

    if (userDoc && (userDoc.disabled === true || userDoc.isActive === false)) {
      return null;
    }

    const fullUser = { ...session.user, ...userDoc };
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
      const publicKey = await getIdpPublicKey();
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

      const userDoc = await database.collection("user").findOne({
        $or: [{ id: sub }, { _id: sub }, { email: sub }],
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
      if (payload.role === "admin") {
        if (!userDoc || userDoc.role === "admin") {
          role = "admin";
        }
      }

      // Scoped application binding:
      // Scoping is the union of constraints: if either the signed token or the database
      // specifies a scoped client ID, the caller is strictly constrained to that tenant.
      // A scoped admin can NEVER escalate to Global Super Admin (null/unscoped).
      const tokenScope = typeof payload.scoped_client_id === "string" && payload.scoped_client_id.trim().length > 0
        ? payload.scoped_client_id.trim()
        : null;
      const dbScope = typeof userDoc?.scopedClientId === "string" && userDoc.scopedClientId.trim().length > 0
        ? userDoc.scopedClientId.trim()
        : null;

      if (tokenScope && dbScope && tokenScope !== dbScope) {
        // Cross-tenant identity conflict: token scope and user document scope conflict
        return null;
      }

      const scopedClientId = tokenScope || dbScope || null;

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
 * FAIL-CLOSED PRIMITIVE:
 * - Missing configured gateway secret => FAILS (false)
 * - Missing or invalid header => FAILS (false)
 * - Valid secret => SUCCEEDS (true)
 *
 * STRICT GATEWAY HEADER CONTRACT:
 * Only 'x-gateway-secret' is accepted. Secondary headers like 'x-internal-secret'
 * are strictly forbidden and return 403 Forbidden.
 */
function verifyGatewaySecret(c: any): boolean {
  try {
    const configuredSecret = config.internalGatewaySecret;
    if (!configuredSecret || typeof configuredSecret !== "string" || configuredSecret.trim().length === 0) {
      return false;
    }

    // STRICT GATEWAY HEADER ENFORCEMENT: Only 'x-gateway-secret' is accepted.
    const gatewayHeader = c.req.header("x-gateway-secret");
    if (!gatewayHeader || typeof gatewayHeader !== "string") {
      return false;
    }

    // Read secrets purely from environment configuration (supports comma-separated values for rotation)
    const allowedSecrets = configuredSecret
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
  } catch {
    return false;
  }
}

/**
 * Standalone middleware to enforce Gateway Trust on management endpoints.
 */
export const requireGatewayTrust = createMiddleware(async (c, next) => {
  if (!verifyGatewaySecret(c)) {
    return c.json(
      { error: "forbidden", message: "Direct access to management endpoints forbidden; gateway authentication required" },
      403
    );
  }
  return next();
});

export const requireAdmin = createMiddleware(async (c, next) => {
  // 1. Enforce Gateway Trust Boundary
  if (!verifyGatewaySecret(c)) {
    return c.json(
      { error: "forbidden", message: "Direct access to management endpoints forbidden; gateway authentication required" },
      403
    );
  }

  // 2. Enforce User Authentication
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  // 3. Enforce Admin Role
  const role = auth.user?.role;
  if (role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }

  return next();
});

export function isSuperAdmin(user: any): boolean {
  if (!user) return false;
  return user.role === "admin" && (user.scopedClientId == null || user.scopedClientId === "");
}

/**
 * Super-Admin Middleware: Global operations only (client creation, user provisioning, global stats/logs)
 */
export const requireSuperAdmin = createMiddleware(async (c, next) => {
  // 1. Enforce Gateway Trust Boundary
  if (!verifyGatewaySecret(c)) {
    return c.json(
      { error: "forbidden", message: "Direct access to management endpoints forbidden; gateway authentication required" },
      403
    );
  }

  // 2. Enforce User Authentication
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  // 3. Enforce Admin Role
  const role = auth.user?.role;
  if (role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }

  // 4. Enforce Super-Admin Privilege Scope
  if (!isSuperAdmin(auth.user)) {
    return c.json(
      {
        error: "forbidden",
        message: "Super-Admin privileges required for this global administrative operation",
      },
      403
    );
  }

  // 5. Strict Bearer Token Audience Validation for Central Platform Management APIs:
  // Must possess platform administrator audience. Arbitrary registered client IDs are strictly rejected.
  if (c.get("authMethod") === "bearer") {
    const hasPlatformAud = c.get("hasPlatformAudience");
    if (!hasPlatformAud) {
      return c.json(
        {
          error: "forbidden",
          message: "Token audience invalid: Central platform management APIs require platform administrator audience",
        },
        403
      );
    }
  }

  return next();
});

/**
 * Scoped-Admin Middleware: App-level operations only (managing own client config)
 */
export const requireScopedAdmin = createMiddleware(async (c, next) => {
  // 1. Enforce Gateway Trust Boundary
  if (!verifyGatewaySecret(c)) {
    return c.json(
      { error: "forbidden", message: "Direct access to management endpoints forbidden; gateway authentication required" },
      403
    );
  }

  // 2. Enforce User Authentication
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  // 3. Enforce Admin Role
  const role = auth.user?.role;
  if (role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }

  // 4. Enforce mandatory password change for freshly provisioned temporary accounts
  if (auth.user?.mustChangePassword === true) {
    return c.json(
      {
        error: "password_change_required",
        message: "Temporary password must be changed before accessing admin operations",
      },
      403
    );
  }

  // 5. Enforce Scoped Tenant Boundaries & Audience Matching
  const scopedClientId = auth.user?.scopedClientId;
  const targetClientId = c.req.param("id") || c.req.param("clientId");

  const database = await getDb();
  let canonicalTargetId: string | null = null;
  if (targetClientId) {
    const resolvedClient = await resolveOAuthClient(database, targetClientId);
    canonicalTargetId = resolvedClient ? resolvedClient.clientId : targetClientId;
  }

  // If user is scoped to a specific application, resolve canonical tenant identity first
  if (scopedClientId && canonicalTargetId) {
    if (canonicalTargetId !== scopedClientId) {
      return c.json(
        {
          error: "forbidden",
          message: "Cross-tenant access forbidden: you can only manage your own assigned application",
        },
        403
      );
    }
  }

  // Strict Bearer Token Audience Validation for Scoped Management APIs:
  if (c.get("authMethod") === "bearer" && canonicalTargetId) {
    const isGlobal = isSuperAdmin(auth.user);
    const hasPlatformAud = c.get("hasPlatformAudience");
    const tokenAudList: string[] = c.get("tokenAudList") || [];

    // Valid audience for scoped API:
    // Either platform audience (for global super admin), OR the exact target client ID
    const audMatchesTarget = tokenAudList.includes(canonicalTargetId);
    const isAllowedAudience = (isGlobal && hasPlatformAud) || audMatchesTarget;

    if (!isAllowedAudience) {
      return c.json(
        {
          error: "forbidden",
          message: `Token audience invalid: bearer token audience does not match target application '${canonicalTargetId}'`,
        },
        403
      );
    }
  }

  c.set("scopedClientId", scopedClientId || null);
  return next();
});
