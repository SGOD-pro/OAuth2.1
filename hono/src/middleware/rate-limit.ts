import { Context, Next } from "hono";
import { getRateLimit, putRateLimit } from "../db/dynamo";

export async function adminRateLimit(c: Context, next: Next) {
  const ip =
    c.req.header("x-forwarded-for") ??
    c.req.header("x-real-ip") ??
    "unknown";
  const now = Date.now();
  const windowMs = 60_000;
  const max = 30;

  const entry = await getRateLimit(ip);
  if (!entry || entry.resetAt < now) {
    await putRateLimit(ip, 1, now + windowMs);
  } else {
    entry.count++;
    if (entry.count > max) {
      return c.json({ error: "Too many requests" }, 429);
    }
    await putRateLimit(ip, entry.count, entry.resetAt);
  }

  await next();
}
