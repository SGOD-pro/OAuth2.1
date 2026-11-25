import crypto from "node:crypto";
import { ObjectId, type Db } from "mongodb";
import { config } from "../config";
import { ensureIdentityCollectionIndexes } from "../db/indexes";
import { toApprovedDisplayLabel } from "../utils/security";
import { digestToken } from "./registration-crypto";

export const BROWSER_SESSION_CAPACITY = 10;
export const BROWSER_SET_TTL_SECONDS = 30 * 24 * 3600;

export interface BrowserSessionEntry {
  entryId: string;
  userId: string;
  sessionId: string;
  sessionVersion: number;
  status: "active" | "signed_out";
  label: string;
  addedAt: Date;
  lastUsedAt: Date;
  signedOutAt?: Date | null;
}

export interface BrowserSessionSetDoc {
  setId: string;
  handleDigest: string;
  version: number;
  capacity: number;
  entries: BrowserSessionEntry[];
  createdAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
  updatedAt: Date;
}

export function getBrowserSessionCookieName(): string {
  return config.env === "production" ? "__Host-swyra-browser" : "swyra-browser";
}

export function buildBrowserProofCookieOptions(maxAgeSec = BROWSER_SET_TTL_SECONDS) {
  const isProd = config.env === "production";
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: "Lax" as const,
    path: "/",
    maxAge: Math.max(0, Math.floor(maxAgeSec)),
  };
}

export function serializeBrowserProofSetCookie(rawProof: string, maxAgeSec = BROWSER_SET_TTL_SECONDS): string {
  const name = getBrowserSessionCookieName();
  const opts = buildBrowserProofCookieOptions(maxAgeSec);
  const parts = [`${name}=${encodeURIComponent(rawProof)}`, `Path=${opts.path}`, `Max-Age=${opts.maxAge}`, "HttpOnly", `SameSite=${opts.sameSite}`];
  if (opts.secure) parts.push("Secure");
  return parts.join("; ");
}

export function digestBrowserProof(rawProof: string): string {
  return digestToken(rawProof, "browser-session-set");
}

function generateProofPair() {
  const rawProof = crypto.randomBytes(32).toString("base64url");
  return { rawProof, digest: digestBrowserProof(rawProof) };
}

export function isOrdinaryRole(role: unknown): boolean {
  return !role || role === "user";
}

export async function findActiveBrowserSet(database: Db, rawBrowserProof: string | undefined): Promise<BrowserSessionSetDoc | null> {
  if (!rawBrowserProof || typeof rawBrowserProof !== "string" || rawBrowserProof.trim().length < 16) {
    return null;
  }
  const now = new Date();
  return database.collection<BrowserSessionSetDoc>("browser_session_sets").findOne({
    handleDigest: digestBrowserProof(rawBrowserProof.trim()),
    revokedAt: null,
    expiresAt: { $gt: now },
  });
}

export async function registerAuthenticatedSessionInBrowserSet(params: {
  database: Db;
  rawBrowserProof?: string;
  userId: string;
  sessionId: string;
  sessionVersion: number;
  label: string;
  capacity?: number;
}): Promise<
  | { ok: true; status: "created" | "added" | "updated"; setId: string; entryId: string; nextRawProof: string }
  | { ok: false; status: "capacity_exceeded"; capacity: number; entriesCount: number; setId: string }
> {
  const { database, userId, sessionId, sessionVersion, label } = params;
  await ensureIdentityCollectionIndexes(database);
  const setsCol = database.collection<BrowserSessionSetDoc>("browser_session_sets");
  const now = new Date();
  const capacity = params.capacity ?? BROWSER_SESSION_CAPACITY;
  const expiresAt = new Date(now.getTime() + BROWSER_SET_TTL_SECONDS * 1000);

  let currentSet: BrowserSessionSetDoc | null = await findActiveBrowserSet(database, params.rawBrowserProof);
  if (!currentSet) {
    const entryId = `ent_${crypto.randomBytes(16).toString("base64url")}`;
    const { rawProof, digest } = generateProofPair();
    const doc: BrowserSessionSetDoc = {
      setId: crypto.randomUUID(),
      handleDigest: digest,
      version: 1,
      capacity,
      entries: [{ entryId, userId, sessionId, sessionVersion, status: "active", label, addedAt: now, lastUsedAt: now, signedOutAt: null }],
      createdAt: now,
      expiresAt,
      revokedAt: null,
      updatedAt: now,
    };
    await setsCol.insertOne(doc);
    return { ok: true, status: "created", setId: doc.setId, entryId, nextRawProof: rawProof };
  }

  for (let attempt = 0; attempt < 3; attempt++) {
    const setDoc: BrowserSessionSetDoc = currentSet;
    const existingIdx = setDoc.entries.findIndex((e) => e.userId === userId);
    const setCap = setDoc.capacity ?? BROWSER_SESSION_CAPACITY;
    if (existingIdx < 0 && setDoc.entries.length >= setCap) {
      return { ok: false, status: "capacity_exceeded", capacity: setCap, entriesCount: setDoc.entries.length, setId: setDoc.setId };
    }

    const nextEntries = [...setDoc.entries];
    const entryId = existingIdx >= 0 ? nextEntries[existingIdx].entryId : `ent_${crypto.randomBytes(16).toString("base64url")}`;
    const nextEntry: BrowserSessionEntry = {
      entryId, userId, sessionId, sessionVersion, status: "active", label,
      addedAt: existingIdx >= 0 ? nextEntries[existingIdx].addedAt : now,
      lastUsedAt: now, signedOutAt: null,
    };
    if (existingIdx >= 0) nextEntries[existingIdx] = nextEntry;
    else nextEntries.push(nextEntry);

    const { rawProof, digest } = generateProofPair();
    const updated = await setsCol.findOneAndUpdate(
      { setId: setDoc.setId, handleDigest: setDoc.handleDigest, version: setDoc.version, revokedAt: null },
      { $set: { entries: nextEntries, handleDigest: digest, expiresAt, updatedAt: now }, $inc: { version: 1 } },
      { returnDocument: "after" }
    );
    if (updated) {
      return { ok: true, status: existingIdx >= 0 ? "updated" : "added", setId: setDoc.setId, entryId, nextRawProof: rawProof };
    }
    const reloaded: BrowserSessionSetDoc | null = await setsCol.findOne({ setId: setDoc.setId, revokedAt: null, expiresAt: { $gt: now } });
    if (!reloaded) break;
    currentSet = reloaded;
  }

  throw new Error("Concurrent modification conflict on browser session set");
}

function toIdFilters(ids: string[]) {
  const out: any[] = [];
  for (const id of ids) {
    out.push(id);
    if (ObjectId.isValid(id)) out.push(new ObjectId(id));
  }
  return out;
}

export async function listBrowserSetEntriesWithLiveStatus(database: Db, rawBrowserProof: string | undefined) {
  const setDoc = await findActiveBrowserSet(database, rawBrowserProof);
  if (!setDoc) return null;

  const userIds = Array.from(new Set(setDoc.entries.map((e) => e.userId)));
  const sessionIds = Array.from(new Set(setDoc.entries.map((e) => e.sessionId)));
  const [users, sessions] = await Promise.all([
    userIds.length ? database.collection("user").find({ $or: [{ _id: { $in: toIdFilters(userIds) } }, { id: { $in: userIds } }] }).toArray() : [],
    sessionIds.length ? database.collection("session").find({ $or: [{ _id: { $in: toIdFilters(sessionIds) } }, { id: { $in: sessionIds } }] }).toArray() : [],
  ]);

  const userMap = new Map<string, any>();
  for (const u of users) userMap.set(String(u.id || u._id), u);
  const sessMap = new Map<string, any>();
  for (const s of sessions) sessMap.set(String(s.id || s._id), s);

  const nowMs = Date.now();
  const accounts = setDoc.entries.map((entry) => {
    const userDoc = userMap.get(entry.userId);
    const sessDoc = sessMap.get(entry.sessionId);
    const userValid = Boolean(userDoc && !userDoc.disabled && !userDoc.banned && userDoc.isActive !== false && (userDoc.tokenVersion ?? 1) === entry.sessionVersion);
    const sessValid = Boolean(sessDoc && !sessDoc.revokedAt && String(sessDoc.userId) === entry.userId && new Date(sessDoc.expiresAt).getTime() > nowMs);
    const liveStatus = entry.status === "active" && userValid && sessValid ? "active" : "signed_out";
    return { entryId: entry.entryId, status: liveStatus, label: entry.label, addedAt: entry.addedAt, lastUsedAt: entry.lastUsedAt };
  });

  return { setId: setDoc.setId, capacity: setDoc.capacity ?? BROWSER_SESSION_CAPACITY, accounts };
}

export async function signOutBrowserEntry(database: Db, rawBrowserProof: string | undefined, entryId: string) {
  const initialSet = await findActiveBrowserSet(database, rawBrowserProof);
  if (!initialSet) return { ok: false as const, status: 401, code: "ERR_BROWSER_PROOF_INVALID" };

  const mongoClient = (database as any).client;
  const runAtomic = async (session?: any) => {
    const opt = session ? { session } : {};
    const setDoc = await database.collection<BrowserSessionSetDoc>("browser_session_sets").findOne(
      { setId: initialSet.setId, handleDigest: initialSet.handleDigest, revokedAt: null, expiresAt: { $gt: new Date() } },
      opt
    );
    if (!setDoc) return { kind: "conflict" as const };
    const idx = setDoc.entries.findIndex((e) => e.entryId === entryId);
    if (idx < 0) return { kind: "not_found" as const };

    const target = setDoc.entries[idx];
    const sessIdFilters = toIdFilters([target.sessionId]);
    await database.collection("session").deleteMany(
      { $or: [{ _id: { $in: sessIdFilters } }, { id: target.sessionId }], userId: { $in: toIdFilters([target.userId]) } },
      opt
    );
    if (target.status === "signed_out") {
      return { kind: "ok" as const, entryId, nextRawProof: rawBrowserProof! };
    }

    const now = new Date();
    const nextEntries = [...setDoc.entries];
    nextEntries[idx] = { ...target, status: "signed_out", signedOutAt: now };
    const { rawProof, digest } = generateProofPair();
    const updated = await database.collection<BrowserSessionSetDoc>("browser_session_sets").findOneAndUpdate(
      { setId: setDoc.setId, handleDigest: setDoc.handleDigest, version: setDoc.version, revokedAt: null },
      { $set: { entries: nextEntries, handleDigest: digest, updatedAt: now }, $inc: { version: 1 } },
      { ...opt, returnDocument: "after" }
    );
    if (!updated) throw Object.assign(new Error("Sign-out CAS version conflict"), { casConflict: true });
    return { kind: "ok" as const, entryId, nextRawProof: rawProof };
  };

  try {
    const outcome = mongoClient && typeof mongoClient.startSession === "function"
      ? await (async () => {
          const session = mongoClient.startSession();
          try {
            let out!: Awaited<ReturnType<typeof runAtomic>>;
            await session.withTransaction(async () => { out = await runAtomic(session); });
            return out;
          } finally {
            await session.endSession().catch(() => {});
          }
        })()
      : await runAtomic(undefined);

    if (outcome.kind === "not_found") return { ok: false as const, status: 404, code: "ERR_ACCOUNT_ENTRY_NOT_FOUND" };
    if (outcome.kind === "conflict") return { ok: false as const, status: 409, code: "ERR_CONCURRENT_MODIFICATION" };
    return { ok: true as const, entryId: outcome.entryId, nextRawProof: outcome.nextRawProof };
  } catch (err: any) {
    if (err?.casConflict || err?.code === 112 || err?.codeName === "WriteConflict") {
      return { ok: false as const, status: 409, code: "ERR_CONCURRENT_MODIFICATION" };
    }
    throw err;
  }
}

export async function removeBrowserEntry(database: Db, rawBrowserProof: string | undefined, entryId: string) {
  const live = await listBrowserSetEntriesWithLiveStatus(database, rawBrowserProof);
  if (!live) return { ok: false as const, status: 401, code: "ERR_BROWSER_PROOF_INVALID" };
  const target = live.accounts.find((a) => a.entryId === entryId);
  if (!target) return { ok: false as const, status: 404, code: "ERR_ACCOUNT_ENTRY_NOT_FOUND" };
  if (target.status === "active") return { ok: false as const, status: 409, code: "ERR_SIGNOUT_REQUIRED" };
  const setDoc = await findActiveBrowserSet(database, rawBrowserProof);
  if (!setDoc) return { ok: false as const, status: 401, code: "ERR_BROWSER_PROOF_INVALID" };
  const nextEntries = setDoc.entries.filter((e) => e.entryId !== entryId);
  const { rawProof, digest } = generateProofPair();
  const updated = await database.collection<BrowserSessionSetDoc>("browser_session_sets").findOneAndUpdate(
    { setId: setDoc.setId, handleDigest: setDoc.handleDigest, version: setDoc.version, revokedAt: null },
    { $set: { entries: nextEntries, handleDigest: digest, updatedAt: new Date() }, $inc: { version: 1 } },
    { returnDocument: "after" }
  );
  if (!updated) return { ok: false as const, status: 409, code: "ERR_CONCURRENT_MODIFICATION" };
  return { ok: true as const, entryId, nextRawProof: rawProof };
}

export async function resolveAndEnrollSession(params: {
  database: Db;
  rawBrowserProof?: string;
  sessionToken: string;
  userDoc: any;
}) {
  const token = params.sessionToken.split(".")[0];
  const sessionDoc = await params.database.collection("session").findOne({ token });
  if (!sessionDoc) return null;
  const userId = String(params.userDoc.id || params.userDoc._id);
  const sessionId = String(sessionDoc._id || sessionDoc.id);
  const label = toApprovedDisplayLabel(params.userDoc.email, params.userDoc.username || params.userDoc.name);
  const res = await registerAuthenticatedSessionInBrowserSet({
    database: params.database,
    rawBrowserProof: params.rawBrowserProof,
    userId,
    sessionId,
    sessionVersion: typeof params.userDoc.tokenVersion === "number" ? params.userDoc.tokenVersion : 1,
    label,
  });
  return { ...res, sessionId, userId };
}
