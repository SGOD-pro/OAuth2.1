import { Context, Next } from "hono";
import { incrementRateLimit } from "../db/dynamo";
import { getTrustedClientIp } from "../utils/security";

export async function adminRateLimit(c: Context, next: Next) {
  const ip = getTrustedClientIp(c.req.raw.headers);
  const now = Date.now();
  const windowMs = 60_000;
  const max = 30;

  const entry = await incrementRateLimit(ip, now, windowMs);
  if (entry.count > max) {
    return c.json({ error: "Too many requests" }, 429);
  }

  await next();
}
