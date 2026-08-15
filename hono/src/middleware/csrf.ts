import { Context, Next } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { config } from "../config";
import { timingSafeEqualStr } from "../utils/security";

const CSRF_HEADER = "x-csrf-token";
const CSRF_COOKIE = "csrf_token";

function generateToken(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

export async function csrfProtection(c: Context, next: Next) {
  const safeMethods = ["GET", "HEAD", "OPTIONS"];

  if (!safeMethods.includes(c.req.method)) {
    const origin = c.req.header("origin");
    const referer = c.req.header("referer");
    const cookieToken = getCookie(c, CSRF_COOKIE);
    const headerToken = c.req.header(CSRF_HEADER);

    // 1. Verify standard double-submit cookie token if provided
    if (cookieToken && headerToken && timingSafeEqualStr(cookieToken, headerToken)) {
      return await next();
    }

    // 2. For cross-origin SPA requests (where browser cookie isolation prevents reading backend cookies),
    // verify the Origin/Referer header strictly matches trusted frontend origins.
    const allowedOrigins = [config.frontendUrl]
      .filter(Boolean)
      .map((o) => o.replace(/\/$/, ""));

    if (origin && allowedOrigins.includes(origin.replace(/\/$/, ""))) {
      return await next();
    }

    if (referer) {
      try {
        const refererOrigin = new URL(referer).origin.replace(/\/$/, "");
        if (allowedOrigins.includes(refererOrigin)) {
          return await next();
        }
      } catch {
        // Invalid referer URL format
      }
    }

    return c.json({ error: "CSRF validation failed: Origin not authorized or missing token" }, 403);
  }

  let token = getCookie(c, CSRF_COOKIE);
  if (!token) {
    token = generateToken();
    setCookie(c, CSRF_COOKIE, token, {
      httpOnly: false,
      sameSite: config.env === "production" ? "none" : "lax",
      secure: config.env === "production",
      path: "/",
    });
  }

  await next();
}
