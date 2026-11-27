import { ObjectId, type Db } from "mongodb";
import type { betterAuth } from "better-auth";
import { makeSignature } from "better-auth/crypto";
import { findActiveBrowserSet, isOrdinaryRole, resolveAndEnrollSession, serializeBrowserProofSetCookie } from "./browser-session-registry";
import { dispatchSelectedEngineSession } from "./selected-engine-session";
import { isAccountDeniedInLedger } from "../utils/account-eligibility";

type SessionEngine = Parameters<typeof dispatchSelectedEngineSession>[0] & ReturnType<typeof betterAuth>;

export interface VerifiedBrowserEntry {
  entryId: string;
  userId: string;
  sessionId: string;
  label: string;
  role: string;
  authTime: number | null;
  mfaTime: number | null;
  createdAt: Date | null;
  tokenVersion: number;
}

export class SessionAdapterError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
  }
}

function idMatch(id: string) {
  const filters: any[] = [{ id }, { _id: id }];
  if (ObjectId.isValid(id)) filters.push({ _id: new ObjectId(id) });
  return { $or: filters };
}

async function resolveSelectedSessionInternal(
  engine: SessionEngine,
  database: Db,
  rawBrowserProof: string | undefined,
  entryId: string
): Promise<VerifiedBrowserEntry & { token: string }> {
  const setDoc = await findActiveBrowserSet(database, rawBrowserProof);
  if (!setDoc) {
    throw new SessionAdapterError("ERR_INVALID_BROWSER_PROOF", "Browser proof is missing, invalid, or expired");
  }

  const entry = setDoc.entries.find((e) => e.entryId === entryId);
  if (!entry || entry.status !== "active") {
    throw new SessionAdapterError("ERR_ENTRY_UNAVAILABLE", "Account entry is not active in this browser set");
  }

  const userDoc = await database.collection("user").findOne(idMatch(entry.userId));
  if (!userDoc || userDoc.disabled === true || userDoc.banned === true || userDoc.isActive === false || userDoc.status === "deleting" || userDoc.status === "deleted" || Boolean(userDoc.deletedAt) || (await isAccountDeniedInLedger(database, entry.userId))) {
    throw new SessionAdapterError("ERR_ACCOUNT_INVALID", "Referenced account is missing or disabled");
  }
  const currentVersion = typeof userDoc.tokenVersion === "number" ? userDoc.tokenVersion : 1;
  if (currentVersion !== entry.sessionVersion) {
    throw new SessionAdapterError("ERR_SESSION_REVOKED", "Account session version has been revoked");
  }

  const sessionDoc = await database.collection("session").findOne(idMatch(entry.sessionId));
  if (
    !sessionDoc ||
    sessionDoc.revokedAt ||
    String(sessionDoc.userId) !== entry.userId ||
    new Date(sessionDoc.expiresAt).getTime() <= Date.now() ||
    typeof sessionDoc.token !== "string" ||
    sessionDoc.token.length === 0
  ) {
    throw new SessionAdapterError("ERR_SESSION_EXPIRED", "Engine session is missing, expired, or revoked");
  }

  // Revalidate through the real Better Auth engine with cookie cache disabled
  const ctx = await engine.$context;
  const sig = await makeSignature(sessionDoc.token, ctx.secret);
  const headers = new Headers();
  headers.set("cookie", `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${sessionDoc.token}.${sig}`)}`);
  const verified = await engine.api.getSession({
    headers,
    query: { disableCookieCache: true, disableRefresh: true },
  });
  if (!verified || verified.user.id !== entry.userId || verified.session.id !== entry.sessionId) {
    throw new SessionAdapterError("ERR_ENGINE_SESSION_INVALID", "Engine session verification failed");
  }

  const rawCreatedAt = sessionDoc.createdAt || verified.session?.createdAt;
  const createdAtDate = rawCreatedAt ? new Date(rawCreatedAt) : null;
  const authTime = createdAtDate && !isNaN(createdAtDate.getTime()) ? Math.floor(createdAtDate.getTime() / 1000) : null;
  const rawMfa = (sessionDoc as any).mfaVerifiedAt || (verified.session as any)?.mfaVerifiedAt;
  const mfaDate = rawMfa ? new Date(rawMfa) : null;
  const mfaTime = mfaDate && !isNaN(mfaDate.getTime()) ? Math.floor(mfaDate.getTime() / 1000) : null;
  if (isOrdinaryRole(userDoc.role) && userDoc.twoFactorEnabled === true && mfaTime === null) {
    throw new SessionAdapterError("ERR_MFA_REQUIRED", "Session predates TOTP enrollment and lacks MFA verification");
  }

  return {
    entryId: entry.entryId,
    userId: entry.userId,
    sessionId: entry.sessionId,
    label: entry.label,
    role: typeof userDoc.role === "string" ? userDoc.role : "user",
    token: sessionDoc.token,
    authTime,
    mfaTime,
    createdAt: createdAtDate,
    tokenVersion: currentVersion,
  };
}

/** Public revalidation helper returning metadata only, never raw session tokens. */
export async function resolveVerifiedBrowserEntry(
  engine: SessionEngine,
  database: Db,
  rawBrowserProof: string | undefined,
  entryId: string
): Promise<VerifiedBrowserEntry> {
  const resolved = await resolveSelectedSessionInternal(engine, database, rawBrowserProof, entryId);
  return {
    entryId: resolved.entryId,
    userId: resolved.userId,
    sessionId: resolved.sessionId,
    label: resolved.label,
    role: resolved.role,
    authTime: resolved.authTime,
    mfaTime: resolved.mfaTime,
    createdAt: resolved.createdAt,
    tokenVersion: resolved.tokenVersion,
  };
}

/** Dispatches authorize/consent request using request-local engine credentials for a validated browser entry. */
export async function dispatchRequestWithBrowserEntry(
  engine: SessionEngine,
  database: Db,
  rawBrowserProof: string | undefined,
  entryId: string,
  request: Request
): Promise<Response> {
  const resolved = await resolveSelectedSessionInternal(engine, database, rawBrowserProof, entryId);
  return dispatchSelectedEngineSession(engine, request, {
    userId: resolved.userId,
    sessionId: resolved.sessionId,
    token: resolved.token,
  });
}

export function extractSessionTokenFromHeaders(headers: Headers): string | null {
  const list: string[] = typeof (headers as any).getSetCookie === "function"
    ? (headers as any).getSetCookie()
    : [headers.get("set-cookie") || ""];
  for (const header of list) {
    const match = header.match(/(?:__Secure-)?better-auth\.session_token=([^;]+)/);
    if (match) return decodeURIComponent(match[1]);
  }
  return null;
}

export async function attachOrdinaryBrowserSessionToResponse(params: {
  database: Db;
  res: Response;
  rawBrowserProof?: string;
  userDoc: any;
  sessionToken?: string | null;
}): Promise<{ response: Response; sessionId: string | null; capacityExceeded?: boolean; nextRawProof?: string; entryId?: string }> {
  const { database, res, rawBrowserProof, userDoc } = params;
  const sessionToken = params.sessionToken ?? extractSessionTokenFromHeaders(res.headers);
  if (!sessionToken) return { response: res, sessionId: null };
  const rawTok = sessionToken.split(".")[0];
  const sessDoc = await database.collection("session").findOne({ token: rawTok }).catch(() => null);
  const sessionId = sessDoc ? String(sessDoc._id || sessDoc.id) : null;
  if (!userDoc || !sessionId || !isOrdinaryRole(userDoc.role)) {
    return { response: res, sessionId };
  }
  const enrolled = await resolveAndEnrollSession({ database, rawBrowserProof, sessionToken, userDoc });
  if (!enrolled) {
    return { response: res, sessionId };
  }
  if (!enrolled.ok) {
    await database.collection("session").deleteOne({ token: rawTok }).catch(() => {});
    return {
      sessionId: null,
      capacityExceeded: true,
      response: new Response(
        JSON.stringify({
          status: false,
          error: "session_set_full",
          code: "ERR_SESSION_SET_FULL",
          capacity: enrolled.capacity,
          message: "Browser account limit reached. Sign out and remove an existing account first.",
        }),
        { status: 409, headers: { "content-type": "application/json", "cache-control": "no-store" } }
      ),
    };
  }
  const headers = new Headers(res.headers);
  headers.append("set-cookie", serializeBrowserProofSetCookie(enrolled.nextRawProof));
  headers.set("x-browser-entry-id", enrolled.entryId);
  return {
    response: new Response(res.body, { status: res.status, headers }),
    sessionId,
    nextRawProof: enrolled.nextRawProof,
    entryId: enrolled.entryId,
  };
}
