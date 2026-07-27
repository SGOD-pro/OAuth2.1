import { Context, Next } from "hono";
import { incrementRateLimit } from "../db/state";
import { getTrustedClientIp } from "../utils/security";

export async function authRateLimit(c: Context, next: Next) {
  const path = c.req.path;
  if (path === "/api/auth/sign-in/email" || path === "/api/auth/two-factor/verify") {
    const ip = getTrustedClientIp(c.req.raw.headers);
  const now = Date.now();
  const windowMs = 60_000;
    const max = 10;

    const entry = await incrementRateLimit(ip, now, windowMs);
    if (entry.count > max) {
      return c.json({ error: "Too many requests" }, 429);
    }
  }

  await next();
}
