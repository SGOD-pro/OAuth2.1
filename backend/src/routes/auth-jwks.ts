import type { Context } from "hono";
import { authProvider } from "../utils/auth";

/**
 * Standard OIDC JWKS Aliases (RFC 7517 / RFC 8414) handler.
 * Forwards requests for /jwks.json and /jwks to /api/auth/jwks.
 */
export async function handleGetJwks(c: Context) {
    const forwardUrl = new URL("/api/auth/jwks", c.req.raw.url);
    const forwardReq = new Request(forwardUrl.toString(), {
        method: "GET",
        headers: c.req.raw.headers,
    });
    return authProvider.handler(forwardReq);
}
