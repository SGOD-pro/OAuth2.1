import type { Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { ObjectId } from "mongodb";
import { config } from "../config";
import { getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { getBrowserSessionCookieName } from "../identity/browser-session-registry";
import { IdentityContextError, resolveOwnerDashboardContext } from "../identity/owner-contexts";
import {
  acceptOwnerDeletion,
  DELETION_RECEIPT_COOKIE,
  DELETION_RECEIPT_TTL_MS,
  getDeletionStatusByReceipt,
  type DeletionLedgerStore,
} from "../identity/deletion";

const RECENT_AUTH_WINDOW_MS = 5 * 60 * 1000;

export interface DeletionRouteDeps {
  getDb?: () => Promise<any>;
  startSession?: () => any;
  resolveOwner?: (c: Context, database: any) => Promise<
    | { ok: true; userId: string; sessionId: string }
    | { ok: false; response: Response }
  >;
  requireRecentAuth?: (database: any, sessionId: string, userId: string) => Promise<{ ok: boolean; code?: string; message?: string }>;
  ledgerStore?: DeletionLedgerStore;
}

async function defaultResolveOwner(c: Context, database: any) {
  try {
    const { verified } = await resolveOwnerDashboardContext({
      database,
      engine: authProvider,
      rawBrowserProof: getCookie(c, getBrowserSessionCookieName()),
      rawContextHandle: c.req.header("x-identity-context"),
      requiredPurpose: "owner_dashboard",
    });
    return { ok: true as const, userId: verified.userId, sessionId: verified.sessionId };
  } catch (err) {
    if (err instanceof IdentityContextError) {
      return { ok: false as const, response: c.json({ error: err.code, message: err.message }, err.status as any) };
    }
    throw err;
  }
}

async function defaultRequireRecentAuth(database: any, sessionId: string, userId: string) {
  if (!ObjectId.isValid(sessionId)) {
    return { ok: false, code: "recent_auth_required", message: "Recent authentication required" };
  }
  const sess = await database.collection("session").findOne({ _id: new ObjectId(sessionId) });
  if (!sess) {
    return { ok: false, code: "recent_auth_required", message: "Recent authentication required" };
  }
  // Routine session updatedAt must not count as reauthentication.
  const refTime = Math.max(
    sess.mfaVerifiedAt ? new Date(sess.mfaVerifiedAt).getTime() : 0,
    sess.createdAt ? new Date(sess.createdAt).getTime() : 0
  );
  if (refTime <= 0 || Date.now() - refTime > RECENT_AUTH_WINDOW_MS) {
    return { ok: false, code: "recent_auth_required", message: "Recent authentication required" };
  }
  if (ObjectId.isValid(userId)) {
    const userDoc = await database.collection("user").findOne({ _id: new ObjectId(userId) });
    if (userDoc?.twoFactorEnabled === true) {
      const mfaTime = sess.mfaVerifiedAt ? new Date(sess.mfaVerifiedAt).getTime() : 0;
      if (mfaTime <= 0 || Date.now() - mfaTime > RECENT_AUTH_WINDOW_MS) {
        return { ok: false, code: "mfa_required", message: "Recent MFA verification required" };
      }
    }
  }
  return { ok: true };
}

export function createDeletionHandlers(deps: DeletionRouteDeps = {}) {
  return {
    requestDeletion: async (c: Context) => {
      const database = await (deps.getDb ?? getDb)();
      const owner = await (deps.resolveOwner ?? defaultResolveOwner)(c, database);
      if (!owner.ok) return owner.response;

      const authCheck = deps.requireRecentAuth
        ? await deps.requireRecentAuth(database, owner.sessionId, owner.userId)
        : await defaultRequireRecentAuth(database, owner.sessionId, owner.userId);
      const authOk = typeof authCheck === "boolean" ? authCheck : authCheck.ok;
      if (!authOk) {
        const code = typeof authCheck === "object" && authCheck.code ? authCheck.code : "recent_auth_required";
        const message = typeof authCheck === "object" && authCheck.message ? authCheck.message : "Recent authentication required";
        return c.json({ error: code, message }, 403);
      }

      const body = await c.req.json().catch(() => null);
      if (!body || (body.confirm !== true && body.confirmation !== "DELETE")) {
        return c.json({ error: "confirmation_required", message: "Explicit deletion confirmation required" }, 400);
      }
      const idempotencyKey =
        c.req.header("idempotency-key")?.trim() ||
        (typeof body.idempotencyKey === "string" ? body.idempotencyKey.trim() : undefined);

      try {
        const result = await acceptOwnerDeletion({
          database,
          userId: owner.userId,
          idempotencyKey,
          ledgerStore: deps.ledgerStore,
          startSession: deps.startSession,
        });
        setCookie(c, DELETION_RECEIPT_COOKIE, result.receiptToken, {
          httpOnly: true,
          sameSite: "Lax",
          secure: config.env === "production",
          path: "/api/identity/deletion",
          maxAge: Math.floor(DELETION_RECEIPT_TTL_MS / 1000),
        });
        c.header("Cache-Control", "no-store");
        return c.json(
          {
            operationId: result.operationId,
            status: result.status,
            committedAt: result.committedAt,
          },
          202
        );
      } catch (err: any) {
        if (err?.status === 404) {
          return c.json({ error: "not_found", message: "Account not found" }, 404);
        }
        return c.json({ error: "deletion_unavailable", message: "Deletion acceptance failed; please retry" }, 503);
      }
    },

    getDeletionStatus: async (c: Context) => {
      const database = await (deps.getDb ?? getDb)();
      const rawReceipt = getCookie(c, DELETION_RECEIPT_COOKIE);
      const status = await getDeletionStatusByReceipt(database, rawReceipt);
      if (!status) {
        return c.json({ error: "unauthorized", message: "Valid deletion receipt required" }, 401);
      }
      c.header("Cache-Control", "no-store");
      return c.json(status, 200);
    },
  };
}

const defaultHandlers = createDeletionHandlers();
export const handleRequestOwnerDeletion = defaultHandlers.requestDeletion;
export const handleGetDeletionStatus = defaultHandlers.getDeletionStatus;
