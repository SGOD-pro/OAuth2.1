import crypto from "node:crypto";
import { ObjectId, type Db } from "mongodb";
import { ensureIdentityCollectionIndexes } from "../db/indexes";
import { digestToken } from "./registration-crypto";
import { findActiveBrowserSet } from "./browser-session-registry";
import { resolveVerifiedBrowserEntry, SessionAdapterError, type VerifiedBrowserEntry } from "./session-adapter";

export const OWNER_CONTEXT_TTL_SECONDS = 15 * 60;
export const ALLOWED_CONTEXT_PURPOSE = "owner_dashboard" as const;

export interface IdentityContextDoc {
  contextId: string;
  contextDigest: string;
  setId: string;
  entryId: string;
  userId: string;
  sessionId: string;
  purpose: string;
  createdAt: Date;
  expiresAt: Date;
  revokedAt?: Date | null;
}

export class IdentityContextError extends Error {
  constructor(public readonly code: string, public readonly status: number, message: string) {
    super(message);
  }
}

function sessionIdFilter(sessionId: string) {
  const filters: any[] = [{ id: sessionId }, { _id: sessionId }];
  if (ObjectId.isValid(sessionId)) filters.push({ _id: new ObjectId(sessionId) });
  return { $or: filters };
}

export async function issueOwnerDashboardContext(params: {
  database: Db;
  engine: any;
  rawBrowserProof: string | undefined;
  entryId: string;
  purpose?: string;
}): Promise<{ contextHandle: string; expiresAt: Date; purpose: string; account: { entryId: string; label: string } }> {
  const purpose = params.purpose || ALLOWED_CONTEXT_PURPOSE;
  if (purpose !== ALLOWED_CONTEXT_PURPOSE) {
    throw new IdentityContextError("ERR_INVALID_PURPOSE", 400, "Unsupported identity context purpose");
  }

  const { database, engine, rawBrowserProof, entryId } = params;
  await ensureIdentityCollectionIndexes(database);

  const setDoc = await findActiveBrowserSet(database, rawBrowserProof);
  if (!setDoc) {
    throw new IdentityContextError("ERR_BROWSER_PROOF_INVALID", 401, "Browser proof is missing, invalid, or expired");
  }

  let verified: VerifiedBrowserEntry;
  try {
    verified = await resolveVerifiedBrowserEntry(engine, database, rawBrowserProof, entryId);
  } catch (err: any) {
    throw new IdentityContextError(err?.code || "ERR_SESSION_INVALID", 401, err?.message || "Session validation failed");
  }

  const sessionDoc = await database.collection("session").findOne(sessionIdFilter(verified.sessionId));
  if (!sessionDoc || sessionDoc.revokedAt) {
    throw new IdentityContextError("ERR_SESSION_EXPIRED", 401, "Parent session is missing or revoked");
  }
  const parentExpiryMs = new Date(sessionDoc.expiresAt).getTime();
  const nowMs = Date.now();
  if (!Number.isFinite(parentExpiryMs) || parentExpiryMs <= nowMs) {
    throw new IdentityContextError("ERR_SESSION_EXPIRED", 401, "Parent session has expired");
  }

  const expiresAt = new Date(Math.min(nowMs + OWNER_CONTEXT_TTL_SECONDS * 1000, parentExpiryMs));
  const contextHandle = crypto.randomBytes(32).toString("base64url");
  const doc: IdentityContextDoc = {
    contextId: crypto.randomUUID(),
    contextDigest: digestToken(contextHandle),
    setId: setDoc.setId,
    entryId: verified.entryId,
    userId: verified.userId,
    sessionId: verified.sessionId,
    purpose: ALLOWED_CONTEXT_PURPOSE,
    createdAt: new Date(nowMs),
    expiresAt,
    revokedAt: null,
  };
  await database.collection<IdentityContextDoc>("identity_contexts").insertOne(doc);

  return {
    contextHandle,
    expiresAt,
    purpose: ALLOWED_CONTEXT_PURPOSE,
    account: { entryId: verified.entryId, label: verified.label },
  };
}

export async function resolveOwnerDashboardContext(params: {
  database: Db;
  engine: any;
  rawBrowserProof: string | undefined;
  rawContextHandle: string | undefined;
  requiredPurpose?: string;
}): Promise<{ context: IdentityContextDoc; verified: VerifiedBrowserEntry }> {
  const { database, engine, rawBrowserProof, rawContextHandle } = params;
  const requiredPurpose = params.requiredPurpose || ALLOWED_CONTEXT_PURPOSE;

  if (!rawContextHandle || typeof rawContextHandle !== "string" || rawContextHandle.trim().length < 16) {
    throw new IdentityContextError("ERR_CONTEXT_MISSING", 401, "Missing X-Identity-Context header");
  }
  const setDoc = await findActiveBrowserSet(database, rawBrowserProof);
  if (!setDoc) {
    throw new IdentityContextError("ERR_BROWSER_PROOF_INVALID", 401, "Browser proof is missing, invalid, or expired");
  }

  const ctxDoc = await database.collection<IdentityContextDoc>("identity_contexts").findOne({
    contextDigest: digestToken(rawContextHandle.trim()),
    revokedAt: null,
    expiresAt: { $gt: new Date() },
  });
  if (!ctxDoc) {
    throw new IdentityContextError("ERR_CONTEXT_INVALID", 401, "Identity context is missing, expired, or revoked");
  }
  if (ctxDoc.purpose !== requiredPurpose) {
    throw new IdentityContextError("ERR_WRONG_CONTEXT_PURPOSE", 403, "Identity context purpose does not match this route");
  }
  if (ctxDoc.setId !== setDoc.setId) {
    throw new IdentityContextError("ERR_CONTEXT_BROWSER_MISMATCH", 401, "Identity context does not belong to this browser set");
  }

  let verified: VerifiedBrowserEntry;
  try {
    verified = await resolveVerifiedBrowserEntry(engine, database, rawBrowserProof, ctxDoc.entryId);
  } catch (err: any) {
    const code = err instanceof SessionAdapterError ? err.code : "ERR_SESSION_INVALID";
    throw new IdentityContextError(code, 401, err?.message || "Bound session is no longer active");
  }

  if (verified.userId !== ctxDoc.userId || verified.sessionId !== ctxDoc.sessionId) {
    throw new IdentityContextError("ERR_CONTEXT_PRINCIPAL_MISMATCH", 401, "Identity context principal conflicts with active entry");
  }

  return { context: ctxDoc, verified };
}

export async function renewOwnerDashboardContext(params: {
  database: Db;
  engine: any;
  rawBrowserProof: string | undefined;
  rawContextHandle: string | undefined;
}): Promise<{ expiresAt: Date; purpose: string }> {
  const { context } = await resolveOwnerDashboardContext({
    ...params,
    requiredPurpose: ALLOWED_CONTEXT_PURPOSE,
  });
  const sessionDoc = await params.database.collection("session").findOne(sessionIdFilter(context.sessionId));
  if (!sessionDoc || sessionDoc.revokedAt) {
    throw new IdentityContextError("ERR_SESSION_EXPIRED", 401, "Parent session is missing or revoked");
  }
  const parentExpiryMs = new Date(sessionDoc.expiresAt).getTime();
  const nowMs = Date.now();
  if (!Number.isFinite(parentExpiryMs) || parentExpiryMs <= nowMs) {
    throw new IdentityContextError("ERR_SESSION_EXPIRED", 401, "Parent session has expired");
  }
  const expiresAt = new Date(Math.min(nowMs + OWNER_CONTEXT_TTL_SECONDS * 1000, parentExpiryMs));
  await params.database.collection<IdentityContextDoc>("identity_contexts").updateOne(
    { contextId: context.contextId, revokedAt: null },
    { $set: { expiresAt } }
  );
  return { expiresAt, purpose: context.purpose };
}
