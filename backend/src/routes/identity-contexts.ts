import crypto from "node:crypto";
import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { hasDangerousMongoKeys } from "../utils/security";
import { getBrowserSessionCookieName } from "../identity/browser-session-registry";
import { DEVICE_BINDING_COOKIE, evaluateSessionDeviceRisk, extractCoarseDeviceSignals } from "../identity/device-risk";
import { ObjectId } from "mongodb";
import { recordAuthEvent } from "../db/state";
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
    const ctxDoc = await database.collection("identity_contexts").findOne({ contextId: { $exists: true }, entryId: body.entryId.trim(), revokedAt: null }, { sort: { createdAt: -1 } });
    const sessDoc = ctxDoc?.sessionId && ObjectId.isValid(ctxDoc.sessionId)
      ? await database.collection("session").findOne({ _id: new ObjectId(ctxDoc.sessionId) })
      : null;
    if (ctxDoc && sessDoc?.deviceBinding) {
      const current = extractCoarseDeviceSignals(c.req.raw.headers, getCookie(c, DEVICE_BINDING_COOKIE));
      const risk = evaluateSessionDeviceRisk({ bound: sessDoc.deviceBinding, current });
      if (risk.level === "high") {
        await Promise.all([
          database.collection("session").updateOne({ _id: sessDoc._id }, { $set: { revokedAt: new Date(), revokedReason: "suspected_session_theft" } }),
          database.collection("identity_contexts").updateOne({ _id: ctxDoc._id }, { $set: { revokedAt: new Date() } }),
          recordAuthEvent({ eventType: "device_risk_high", outcome: "denied", userId: ctxDoc.userId, sessionId: ctxDoc.sessionId, reason: risk.reasons.join(",") }),
        ]);
        return c.json({ error: "session_compromised", code: "ERR_SESSION_COMPROMISED", message: "Session revoked due to suspicious device/network change", requestId }, 401);
      }
      if (risk.level === "elevated") {
        await database.collection("identity_contexts").updateOne({ _id: ctxDoc._id }, { $set: { revokedAt: new Date() } });
        await recordAuthEvent({ eventType: "device_risk_elevated", outcome: "denied", userId: ctxDoc.userId, sessionId: ctxDoc.sessionId, reason: risk.reasons.join(",") });
        return c.json({ error: "step_up_required", code: "ERR_STEP_UP_REQUIRED", message: "Additional verification required on new browser", requestId }, 403);
      }
    }
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
