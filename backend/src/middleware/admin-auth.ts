import { createMiddleware } from "hono/factory";
import { importJWK, jwtVerify } from "jose";
import { authProvider } from "../utils/auth";
import { getHeaders, resolveOAuthClient, timingSafeEqualStr } from "../utils/security";
import { getDb } from "../db/mongo";
import { config } from "../config";

let cachedPublicKey: any = null;
let lastKeyFetch = 0;

async function getIdpPublicKey(): Promise<any> {
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
 * Helper to fetch session and user document once per request and cache on context `c`
 * Supports Better Auth cookie sessions AND signed OAuth 2.1 RS256 Bearer tokens.
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

    const fullUser = { ...session.user, ...userDoc };
    c.set("user", fullUser);
    c.set("session", session.session);

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

      // Strict Audience Validation
      if (payload.aud) {
        const audList = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        const validAuds = new Set([
          config.auth.baseURL,
          config.frontendUrl,
          "https://oauth21.vercel.app",
        ]);

        let audMatched = audList.some((a) => validAuds.has(a));
        if (!audMatched) {
          const database = await getDb();
          const clientMatch = await database.collection("oauthClient").findOne({
            $or: audList.map((a) => ({ clientId: a })),
          });
          if (clientMatch) {
            audMatched = true;
          }
        }

        if (!audMatched) {
          return null; // Audience mismatch
        }
      }

      const sub = payload.sub;
      if (!sub) return null;

      const database = await getDb();
      const userDoc = await database.collection("user").findOne({
        $or: [{ id: sub }, { _id: sub }, { email: sub }],
      });

      const role = (payload.role as string) || userDoc?.role || "user";
      const scopedClientId = payload.scoped_client_id !== undefined
        ? (payload.scoped_client_id as string | null)
        : (userDoc?.scopedClientId || null);

      const fullUser = {
        ...(userDoc || {}),
        id: sub,
        role,
        scopedClientId,
      };

      c.set("user", fullUser);
      c.set("session", { id: `token-${sub}`, userId: sub });

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
 * Never allows missing secret to result in a trusted request.
 */
function verifyGatewaySecret(c: any): boolean {
  try {
    const configuredSecret = config.internalGatewaySecret;
    if (!configuredSecret || typeof configuredSecret !== "string" || configuredSecret.length === 0) {
      return false;
    }
    const gatewayHeader = c.req.header("x-gateway-secret") || c.req.header("x-internal-secret");
    if (!gatewayHeader || typeof gatewayHeader !== "string") {
      return false;
    }
    return timingSafeEqualStr(gatewayHeader, configuredSecret);
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

  // 5. Enforce Scoped Tenant Boundaries
  const scopedClientId = auth.user?.scopedClientId;
  const targetClientId = c.req.param("id") || c.req.param("clientId");

  // If user is scoped to a specific application, resolve canonical tenant identity first
  if (scopedClientId && targetClientId) {
    const database = await getDb();
    const resolvedClient = await resolveOAuthClient(database, targetClientId);
    const canonicalTargetId = resolvedClient ? resolvedClient.clientId : targetClientId;
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

  c.set("scopedClientId", scopedClientId || null);
  return next();
});
