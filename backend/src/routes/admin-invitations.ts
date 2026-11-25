import crypto from "node:crypto";
import type { Context } from "hono";
import { getDb } from "../db/mongo";
import { hasDangerousMongoKeys } from "../utils/security";
import {
  InvitationError,
  issuePrivateAppInvitation,
  revokePrivateAppInvitation,
} from "../identity/app-invitations";

function getReqId(c: Context): string {
  return (c.get("requestId" as never) as string) || crypto.randomUUID();
}

export async function handleIssueClientInvitation(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const clientId = c.req.param("clientId") || "";
  const body = await c.req.raw.clone().json().catch(() => null);
  if (
    !body ||
    typeof body !== "object" ||
    hasDangerousMongoKeys(body) ||
    typeof body.email !== "string" ||
    !body.email.trim()
  ) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }

  const user = c.get("user" as never) as any;
  const inviterUserId = String(user?.id || user?._id || "");
  const inviterRole = String(user?.role || "");
  const database = await getDb();

  try {
    const issued = await issuePrivateAppInvitation({
      database,
      clientId,
      targetEmail: body.email.trim(),
      roleCeiling: typeof body.roleCeiling === "string" ? body.roleCeiling : "user",
      inviterUserId,
      inviterRole,
      ttlSeconds: typeof body.ttlSeconds === "number" ? body.ttlSeconds : undefined,
    });
    return c.json(
      {
        inviteId: issued.inviteId,
        clientId: issued.clientId,
        targetEmail: issued.targetEmail,
        roleCeiling: issued.roleCeiling,
        expiresAt: issued.expiresAt,
        requestId,
      },
      201
    );
  } catch (err: any) {
    if (err instanceof InvitationError) {
      return c.json({ error: "request_rejected", code: err.code, message: err.message, requestId }, err.status as any);
    }
    return c.json({ error: "server_error", code: "ERR_INVITE_ISSUE_FAILED", requestId }, 500);
  }
}

export async function handleRevokeClientInvitation(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const clientId = c.req.param("clientId") || "";
  const inviteId = c.req.param("inviteId") || "";
  const database = await getDb();
  const { revoked } = await revokePrivateAppInvitation({ database, clientId, inviteId });
  if (!revoked) {
    return c.json({ error: "not_found", code: "ERR_INVITE_NOT_FOUND", requestId }, 404);
  }
  return c.json({ revoked: true, inviteId, clientId, requestId });
}
