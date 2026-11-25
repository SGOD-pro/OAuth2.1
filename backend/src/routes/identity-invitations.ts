import crypto from "node:crypto";
import type { Context } from "hono";
import { getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { hasDangerousMongoKeys } from "../utils/security";
import { claimPrivateAppInvitation, InvitationError } from "../identity/app-invitations";

function getReqId(c: Context): string {
  return (c.get("requestId" as never) as string) || crypto.randomUUID();
}

export async function handleClaimInvitation(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const body = await c.req.raw.clone().json().catch(() => null);
  if (
    !body ||
    typeof body !== "object" ||
    hasDangerousMongoKeys(body) ||
    typeof body.token !== "string" ||
    !body.token.trim()
  ) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }

  let sessionResult: any = null;
  try {
    sessionResult = await authProvider.api.getSession({ headers: c.req.raw.headers });
  } catch {
    sessionResult = null;
  }

  if (!sessionResult?.user) {
    return c.json({ error: "unauthorized", code: "ERR_UNAUTHENTICATED", requestId }, 401);
  }

  const database = await getDb();
  const userId = String(sessionResult.user.id || (sessionResult.user as any)._id);
  const userDoc = await database.collection("user").findOne({ $or: [{ id: userId }, { email: sessionResult.user.email }] });
  const emailVerified = Boolean(userDoc?.emailVerified === true || sessionResult.user.emailVerified === true);

  try {
    const claimed = await claimPrivateAppInvitation({
      database,
      rawToken: body.token.trim(),
      userId,
      userEmail: String(userDoc?.email || sessionResult.user.email || ""),
      emailVerified,
    });
    return c.json({ claimed: true, ...claimed, requestId });
  } catch (err: any) {
    if (err instanceof InvitationError) {
      return c.json({ error: "request_rejected", code: err.code, message: err.message, requestId }, err.status as any);
    }
    return c.json({ error: "server_error", code: "ERR_INVITE_CLAIM_FAILED", requestId }, 500);
  }
}
