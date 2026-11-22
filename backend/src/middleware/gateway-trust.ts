import { createMiddleware } from "hono/factory";
import { config } from "../config";
import { timingSafeEqualStr, isLoopbackHost } from "../utils/security";
import crypto from "node:crypto";

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
