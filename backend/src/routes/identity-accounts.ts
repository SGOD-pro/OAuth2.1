import crypto from "node:crypto";
import type { Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { getDb } from "../db/mongo";
import { hasDangerousMongoKeys } from "../utils/security";
import {
  buildBrowserProofCookieOptions,
  getBrowserSessionCookieName,
  listBrowserSetEntriesWithLiveStatus,
  removeBrowserEntry,
  signOutBrowserEntry,
} from "../identity/browser-session-registry";

function getReqId(c: Context): string {
  return (c.get("requestId" as never) as string) || crypto.randomUUID();
}

export async function handleListBrowserAccounts(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const rawProof = getCookie(c, getBrowserSessionCookieName());
  const database = await getDb();
  const result = await listBrowserSetEntriesWithLiveStatus(database, rawProof);
  if (!result) {
    return c.json({ error: "unauthorized", code: "ERR_BROWSER_PROOF_INVALID", accounts: [], requestId }, 401);
  }
  return c.json({
    capacity: result.capacity,
    accounts: result.accounts,
    requestId,
  });
}

export async function handleSignOutBrowserAccount(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const body = await c.req.raw.clone().json().catch(() => null);
  if (!body || typeof body !== "object" || hasDangerousMongoKeys(body) || typeof body.entryId !== "string" || !body.entryId.trim()) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }
  const database = await getDb();
  const rawProof = getCookie(c, getBrowserSessionCookieName());
  const outcome = await signOutBrowserEntry(database, rawProof, body.entryId.trim());
  if (!outcome.ok) {
    return c.json({ error: "request_rejected", code: outcome.code, requestId }, outcome.status as any);
  }
  setCookie(c, getBrowserSessionCookieName(), outcome.nextRawProof, buildBrowserProofCookieOptions() as any);
  return c.json({ signedOut: true, entryId: outcome.entryId, requestId });
}

export async function handleRemoveBrowserAccount(c: Context): Promise<Response> {
  const requestId = getReqId(c);
  const body = await c.req.raw.clone().json().catch(() => null);
  if (!body || typeof body !== "object" || hasDangerousMongoKeys(body) || typeof body.entryId !== "string" || !body.entryId.trim()) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_INPUT", requestId }, 400);
  }
  const database = await getDb();
  const rawProof = getCookie(c, getBrowserSessionCookieName());
  const outcome = await removeBrowserEntry(database, rawProof, body.entryId.trim());
  if (!outcome.ok) {
    return c.json({ error: "request_rejected", code: outcome.code, requestId }, outcome.status as any);
  }
  setCookie(c, getBrowserSessionCookieName(), outcome.nextRawProof, buildBrowserProofCookieOptions() as any);
  return c.json({ removed: true, entryId: outcome.entryId, requestId });
}
