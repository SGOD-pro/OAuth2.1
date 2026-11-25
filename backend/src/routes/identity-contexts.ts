import crypto from "node:crypto";
import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { hasDangerousMongoKeys } from "../utils/security";
import { getBrowserSessionCookieName } from "../identity/browser-session-registry";
import {
  IdentityContextError,
  issueOwnerDashboardContext,
  renewOwnerDashboardContext,
  resolveOwnerDashboardContext,
} from "../identity/owner-contexts";

function getReqId(c: Context): string {
  return (c.get("requestId" as never) as string) || crypto.randomUUID();
}

export async function handleIssueIdentityContext(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const body = await c.req.raw.clone().json().catch(() => null);
  if (
    !body ||
    typeof body !== "object" ||
    hasDangerousMongoKeys(body) ||
    typeof body.entryId !== "string" ||
    !body.entryId.trim()
  ) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }

  const database = await getDb();
  const rawBrowserProof = getCookie(c, getBrowserSessionCookieName());
  try {
    const issued = await issueOwnerDashboardContext({
      database,
      engine: authProvider,
      rawBrowserProof,
      entryId: body.entryId.trim(),
      purpose: typeof body.purpose === "string" ? body.purpose.trim() : undefined,
    });
    return c.json({ ...issued, requestId }, 201);
  } catch (err: any) {
    if (err instanceof IdentityContextError) {
      return c.json({ error: "request_rejected", code: err.code, message: err.message, requestId }, err.status as any);
    }
    return c.json({ error: "server_error", code: "ERR_CONTEXT_ISSUE_FAILED", requestId }, 500);
  }
}

export async function handleGetOwnerContextMe(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const database = await getDb();
  const rawBrowserProof = getCookie(c, getBrowserSessionCookieName());
  const rawContextHandle = c.req.header("x-identity-context") || undefined;
  try {
    const { context, verified } = await resolveOwnerDashboardContext({
      database,
      engine: authProvider,
      rawBrowserProof,
      rawContextHandle,
    });
    const { ObjectId } = await import("mongodb");
    const uFilters: any[] = [{ id: verified.userId }, { _id: verified.userId }];
    if (ObjectId.isValid(verified.userId) && verified.userId.length === 24) uFilters.push({ _id: new ObjectId(verified.userId) });
    const [userDoc, twoFactorDoc] = await Promise.all([
      database.collection("user").findOne({ $or: uFilters }),
      database.collection("twoFactor").findOne({ $or: [{ userId: verified.userId }, ...(ObjectId.isValid(verified.userId) && verified.userId.length === 24 ? [{ userId: new ObjectId(verified.userId) }] : [])] }),
    ]);
    return c.json({
      entryId: verified.entryId,
      userId: verified.userId,
      label: verified.label,
      purpose: context.purpose,
      expiresAt: context.expiresAt,
      totpEnabled: Boolean(userDoc?.twoFactorEnabled && twoFactorDoc?.verified),
      requestId,
    });
  } catch (err: any) {
    if (err instanceof IdentityContextError) {
      return c.json({ error: "unauthorized", code: err.code, message: err.message, requestId }, err.status as any);
    }
    return c.json({ error: "server_error", code: "ERR_CONTEXT_RESOLVE_FAILED", requestId }, 500);
  }
}

export async function handleRenewIdentityContext(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const database = await getDb();
  const rawBrowserProof = getCookie(c, getBrowserSessionCookieName());
  const rawContextHandle = c.req.header("x-identity-context") || undefined;
  try {
    const renewed = await renewOwnerDashboardContext({
      database,
      engine: authProvider,
      rawBrowserProof,
      rawContextHandle,
    });
    return c.json({ ...renewed, requestId });
  } catch (err: any) {
    if (err instanceof IdentityContextError) {
      return c.json({ error: "unauthorized", code: err.code, message: err.message, requestId }, err.status as any);
    }
    return c.json({ error: "server_error", code: "ERR_CONTEXT_RENEW_FAILED", requestId }, 500);
  }
}
