import type { Db } from "mongodb";
import { authProvider } from "../utils/auth";
import { client as defaultMongoClient, getDb } from "../db/mongo";
import { ensureIdentityCollectionIndexes } from "../db/indexes";
import { config } from "../config";
import { isStrongPassword } from "../utils/security";
import {
  computeBrowserBindingHash,
  computeUsernameLookup,
  decryptContactEmail,
  digestToken,
  normalizeUsername,
} from "./registration-crypto";
import {
  CompletionHttpError,
  executeCompletionTransaction,
  getRegistrationTxEngine,
} from "./registration-tx-engine";

export interface RegistrationCompleteTestHooks {
  onBeforePasswordHash?: () => void | Promise<void>;
  onBeforeCommitTransaction?: () => void | Promise<void>;
  onInsideTransactionAfterUser?: () => void | Promise<void>;
  onSessionCreate?: () => void | Promise<void>;
}

let completeHooks: RegistrationCompleteTestHooks | null = null;
export function setRegistrationCompleteTestHooks(hooks: RegistrationCompleteTestHooks | null): void {
  completeHooks = hooks;
}

export interface CompleteRegistrationInput {
  rawBrowser: string | undefined;
  rawProof: string | undefined;
  username: unknown;
  password: unknown;
  acceptedTermsVersion: unknown;
  idempotencyKey?: string;
  clientIp: string | null;
  userAgent: string | null;
  requestHeaders: Headers;
  requestId: string;
}

export interface CompleteRegistrationResult {
  status: number;
  body: Record<string, unknown>;
  clearProofCookie?: boolean;
  sessionSetCookies?: string[];
}

function classifyDuplicateKey(err: any): "username" | "email" | "idempotency" | null {
  if (err?.code !== 11000 && err?.codeName !== "DuplicateKey") return null;
  const msg = String(err?.message || "");
  if (msg.includes("usernameLookup") || msg.includes("identity_lookup")) {
    const keyVal = JSON.stringify(err?.keyValue || {});
    return keyVal.includes('"email"') || msg.includes("email") ? "email" : "username";
  }
  if (msg.includes("completeIdempotencyKey")) return "idempotency";
  if (msg.includes("email")) return "email";
  return null;
}

async function resolveCommittedReplay(
  database: Db,
  completeIdempotencyKey: string,
  browserBindingHash: string,
  requestId: string
): Promise<CompleteRegistrationResult | null> {
  const existing = await database.collection("registration_intents").findOne({
    completeIdempotencyKey,
    browserBindingHash,
    status: "consumed",
  });
  if (!existing?.committedUserId) return null;
  return {
    status: 200,
    clearProofCookie: true,
    body: {
      completed: true,
      idempotentReplay: true,
      sessionEstablished: false,
      requiresSignIn: true,
      redirectTo: "/auth",
      user: { id: String(existing.committedUserId), username: existing.committedUsername ?? null, role: "user" },
      requestId,
    },
  };
}

async function resolveConflictAfterAbort(
  database: Db,
  err: any,
  ctx: { intentId: string; browserBindingHash: string; usernameLookup: string; email: string; idemLookup?: string; requestId: string }
): Promise<CompleteRegistrationResult | null> {
  if (err instanceof CompletionHttpError) {
    return { status: err.httpStatus, body: { error: err.error, code: err.code, requestId: ctx.requestId } };
  }
  const dupKind = classifyDuplicateKey(err);
  if (dupKind === "idempotency" && ctx.idemLookup) {
    return resolveCommittedReplay(database, ctx.idemLookup, ctx.browserBindingHash, ctx.requestId);
  }
  if (dupKind === "username") {
    return { status: 409, body: { error: "conflict", code: "ERR_USERNAME_TAKEN", requestId: ctx.requestId } };
  }
  if (dupKind === "email") {
    return { status: 409, body: { error: "conflict", code: "ERR_EMAIL_ALREADY_REGISTERED", requestId: ctx.requestId } };
  }
  if (err?.code === 112 || err?.codeName === "WriteConflict") {
    const intentState = await database.collection("registration_intents").findOne({ intentId: ctx.intentId }, { projection: { status: 1 } });
    if (intentState?.status === "verified") {
      const takenUser = await database.collection("identity_lookup").findOne({ kind: "username", keyVersion: 1, keyedLookup: ctx.usernameLookup }, { projection: { _id: 1 } });
      if (takenUser) return { status: 409, body: { error: "conflict", code: "ERR_USERNAME_TAKEN", requestId: ctx.requestId } };
      const takenEmail = await database.collection("user").findOne({ email: ctx.email }, { projection: { _id: 1 } });
      if (takenEmail) return { status: 409, body: { error: "conflict", code: "ERR_EMAIL_ALREADY_REGISTERED", requestId: ctx.requestId } };
      return { status: 409, body: { error: "conflict", code: "ERR_CONCURRENT_CONFLICT", requestId: ctx.requestId } };
    }
    return { status: 409, body: { error: "conflict", code: "ERR_PROOF_CONSUMED", requestId: ctx.requestId } };
  }
  return null;
}

export async function completeVerifiedRegistration(input: CompleteRegistrationInput): Promise<CompleteRegistrationResult> {
  const { requestId } = input;
  if (config.identity.registrationMode !== "verified") {
    return { status: 403, body: { error: "registration_disabled", code: "ERR_REGISTRATION_DISABLED", requestId } };
  }
  if (!input.rawBrowser) {
    return { status: 403, body: { error: "unauthorized", code: "ERR_BROWSER_BINDING_REQUIRED", requestId } };
  }

  const browserBindingHash = computeBrowserBindingHash(input.rawBrowser);
  const database = await getDb();
  await ensureIdentityCollectionIndexes(database);

  const idemLookup = input.idempotencyKey?.trim() ? `complete:${browserBindingHash}:${input.idempotencyKey.trim()}` : undefined;
  if (idemLookup) {
    const replay = await resolveCommittedReplay(database, idemLookup, browserBindingHash, requestId);
    if (replay) return replay;
  }
  if (!input.rawProof) {
    return { status: 403, body: { error: "unauthorized", code: "ERR_PROOF_REQUIRED", requestId } };
  }

  const parsedUser = normalizeUsername(input.username);
  if (!parsedUser) {
    return { status: 400, body: { error: "invalid_request", code: "ERR_INVALID_USERNAME", requestId } };
  }
  if (typeof input.password !== "string" || !isStrongPassword(input.password)) {
    return { status: 400, body: { error: "invalid_request", code: "ERR_WEAK_PASSWORD", requestId } };
  }
  const acceptedTermsVersion = typeof input.acceptedTermsVersion === "string" ? input.acceptedTermsVersion.trim() : "";
  if (!acceptedTermsVersion || acceptedTermsVersion.length > 32) {
    return { status: 400, body: { error: "invalid_request", code: "ERR_INVALID_TERMS", requestId } };
  }

  const nowMs = Date.now();
  const proofDigest = digestToken(input.rawProof, "proof");
  const intent = await database.collection("registration_intents").findOne({ browserBindingHash, proofDigest });
  if (!intent) return { status: 403, body: { error: "unauthorized", code: "ERR_PROOF_INVALID", requestId } };
  if (intent.status !== "verified") return { status: 409, body: { error: "conflict", code: "ERR_PROOF_UNAVAILABLE", requestId } };
  if (nowMs >= new Date(intent.expiresAt).getTime() || nowMs >= new Date(intent.proofExpiresAt).getTime()) {
    return { status: 400, body: { error: "expired", code: "ERR_PROOF_EXPIRED", requestId } };
  }
  if (intent.termsVersion && intent.termsVersion !== acceptedTermsVersion) {
    return { status: 400, body: { error: "invalid_request", code: "ERR_TERMS_MISMATCH", requestId } };
  }

  let verifiedEmail: string;
  try {
    verifiedEmail = decryptContactEmail(intent.encryptedEmail, { intentId: intent.intentId, emailLookup: intent.emailLookup });
  } catch {
    return { status: 403, body: { error: "unauthorized", code: "ERR_PROOF_INVALID", requestId } };
  }

  const usernameLookup = computeUsernameLookup(parsedUser.normalized);
  if (await database.collection("user").findOne({ email: verifiedEmail }, { projection: { _id: 1 } })) {
    return { status: 409, body: { error: "conflict", code: "ERR_EMAIL_ALREADY_REGISTERED", requestId } };
  }
  if (await database.collection("identity_lookup").findOne({ kind: "username", keyVersion: 1, keyedLookup: usernameLookup }, { projection: { _id: 1 } })) {
    return { status: 409, body: { error: "conflict", code: "ERR_USERNAME_TAKEN", requestId } };
  }

  await completeHooks?.onBeforePasswordHash?.();
  const mongoClient = (database as any).client ?? defaultMongoClient;
  const txEngine = await getRegistrationTxEngine(database, mongoClient);
  const txContext = await txEngine.engine.$context;
  const passwordHash = await txContext.password.hash(input.password);
  await completeHooks?.onBeforeCommitTransaction?.();

  let createdUserId = "";
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      createdUserId = await executeCompletionTransaction(txEngine, {
        intentId: intent.intentId, browserBindingHash, proofDigest, email: verifiedEmail,
        emailLookup: intent.emailLookup, displayUsername: parsedUser.display, normalizedUsername: parsedUser.normalized,
        usernameLookup, acceptedTermsVersion, passwordHash, idemLookup, clientIp: input.clientIp, userAgent: input.userAgent,
        onInsideAfterUser: completeHooks?.onInsideTransactionAfterUser,
      });
      break;
    } catch (err: any) {
      const isWriteConflict = err?.code === 112 || err?.codeName === "WriteConflict";
      if (isWriteConflict && attempt === 0) {
        const latest = await database.collection("registration_intents").findOne({ intentId: intent.intentId }, { projection: { status: 1 } });
        if (latest?.status === "verified") {
          await new Promise((r) => setTimeout(r, 25));
          continue;
        }
      }
      const mapped = await resolveConflictAfterAbort(database, err, {
        intentId: intent.intentId, browserBindingHash, usernameLookup, email: verifiedEmail, idemLookup, requestId,
      });
      if (mapped) return mapped;
      throw err;
    }
  }

  // Post-commit ordinary session establishment; committed user survives session failure
  let sessionSetCookies: string[] = [];
  let sessionEstablished = false;
  try {
    await completeHooks?.onSessionCreate?.();
    const signInHeaders = new Headers();
    for (const h of ["origin", "user-agent", "x-forwarded-for", "x-real-ip", "host"]) {
      const val = input.requestHeaders.get(h);
      if (val) signInHeaders.set(h, val);
    }
    const signInRes = await (authProvider.api as any).signInEmail({
      body: { email: verifiedEmail, password: input.password },
      headers: signInHeaders,
      asResponse: true,
    });
    if (signInRes?.ok) {
      sessionSetCookies = typeof signInRes.headers?.getSetCookie === "function"
        ? signInRes.headers.getSetCookie()
        : (signInRes.headers?.get("set-cookie") ? [signInRes.headers.get("set-cookie")] : []);
      sessionEstablished = sessionSetCookies.some((c) => c.includes("better-auth.session_token="));
    }
  } catch (sessionErr: any) {
    console.warn("[REG_COMPLETE] Post-commit session establishment failed:", sessionErr?.message || sessionErr);
  }

  return {
    status: 201,
    clearProofCookie: true,
    sessionSetCookies,
    body: {
      completed: true,
      sessionEstablished,
      requiresSignIn: !sessionEstablished,
      redirectTo: sessionEstablished ? undefined : "/auth",
      user: { id: createdUserId, username: parsedUser.display, role: "user" },
      requestId,
    },
  };
}
