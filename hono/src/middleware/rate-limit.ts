import { Context, Next } from "hono";

const adminRateMap = new Map<string, { count: number; reset: number }>();

export async function adminRateLimit(c: Context, next: Next) {
  const ip =
    c.req.header("x-forwarded-for") ??
    c.req.header("x-real-ip") ??
    "unknown";
  const now = Date.now();
  const windowMs = 60_000;
  const max = 30;

  const entry = adminRateMap.get(ip);
  if (!entry || entry.reset < now) {
    adminRateMap.set(ip, { count: 1, reset: now + windowMs });
  } else {
    entry.count++;
    if (entry.count > max) {
      return c.json({ error: "Too many requests" }, 429);
    }
  }

  await next();
}
