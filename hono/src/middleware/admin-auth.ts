import type {
  Context,
  Next,
} from "hono";

import { authProvider }
  from "../utils/auth";

export async function
requireAdmin(
  c: Context,
  next: Next
) {
  const session =
    await authProvider.api
      .getSession({
        headers:
          c.req.raw.headers,
      });

  if (!session?.user) {
    return c.json({
      error:
        "Authentication required",
    }, 401);
  }

  if (
    (session.user as any)
      .role !== "admin"
  ) {
    return c.json({
      error:
        "Admin access required",
    }, 403);
  }

  // Store user in context
  c.set("user", session.user);

  await next();
}