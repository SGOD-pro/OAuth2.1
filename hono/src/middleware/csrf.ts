import { Context, Next } from "hono";
import { getCookie, setCookie } from "hono/cookie";

const CSRF_HEADER = "x-csrf-token";
const CSRF_COOKIE = "csrf_token";

function generateToken(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

export async function csrfProtection(c: Context, next: Next) {
  const safeMethods = ["GET", "HEAD", "OPTIONS"];

  if (!safeMethods.includes(c.req.method)) {
    const cookieToken = getCookie(c, CSRF_COOKIE);
    const headerToken = c.req.header(CSRF_HEADER);

    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return c.json({ error: "CSRF validation failed" }, 403);
    }
  }

  let token = getCookie(c, CSRF_COOKIE);
  if (!token) {
    token = generateToken();
    setCookie(c, CSRF_COOKIE, token, {
      httpOnly: false,
      sameSite: "Strict",
      secure: process.env.NODE_ENV === "production",
      path: "/",
    });
  }

  await next();
}
