import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { ObjectId } from "mongodb";
import { getDb } from "../db/mongo";
import { authProvider } from "../utils/auth";
import { getBrowserSessionCookieName } from "../identity/browser-session-registry";
import { IdentityContextError, resolveOwnerDashboardContext } from "../identity/owner-contexts";
import { AccountKeyAccessError, type AccountKeyProvider } from "../identity/account-key-provider";
import { ProtectedFieldError } from "../identity/protected-envelope";
import type { ProtectedProfileCollection } from "../identity/protected-profile-store";
import {
  enqueueOwnerExportJob,
  ExportArtifactError,
  getOwnerExportJobStatus,
  readOwnerExportArtifact,
} from "../identity/export-jobs";

const RECENT_AUTH_WINDOW_MS = 5 * 60 * 1000;

export interface OwnerExportRouteDeps {
  getDb?: () => Promise<any>;
  resolveOwner?: (c: Context, database: any) => Promise<
    | { ok: true; userId: string; sessionId: string }
    | { ok: false; response: Response }
  >;
  protectedProfileStore?: ProtectedProfileCollection;
  accountKeyProvider?: AccountKeyProvider;
  migrationMode?: "compat" | "strict";
}

async function resolveOwner(c: Context, database: any) {
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

async function requireRecentAuth(database: any, sessionId: string): Promise<boolean> {
  if (!ObjectId.isValid(sessionId)) return false;
  const sess = await database.collection("session").findOne({ _id: new ObjectId(sessionId) });
  if (!sess) return false;
  // Routine session updatedAt must not count as reauthentication.
  const refTime = Math.max(
    sess.mfaVerifiedAt ? new Date(sess.mfaVerifiedAt).getTime() : 0,
    sess.createdAt ? new Date(sess.createdAt).getTime() : 0
  );
  return refTime > 0 && Date.now() - refTime <= RECENT_AUTH_WINDOW_MS;
}

function mapExportError(c: Context, err: unknown): Response | null {
  if (err instanceof ExportArtifactError) {
    return c.json({ error: err.code, message: err.message }, err.status as any);
  }
  if (err instanceof AccountKeyAccessError) {
    const status = err.code === "provider_outage" ? 503 : err.code === "key_not_found" ? 404 : 403;
    return c.json({ error: err.code, message: err.message }, status as any);
  }
  if (err instanceof ProtectedFieldError) {
    const status = err.code === "profile_not_found" ? 404 : 500;
    return c.json({ error: err.code, message: err.message }, status as any);
  }
  return null;
}

export function createOwnerExportHandlers(deps: OwnerExportRouteDeps = {}) {
  return {
    createExport: async (c: Context) => {
      const database = await (deps.getDb ?? getDb)();
      const owner = await (deps.resolveOwner ?? resolveOwner)(c, database);
      if (!owner.ok) return owner.response;

      if (!(await requireRecentAuth(database, owner.sessionId))) {
        return c.json({ error: "recent_auth_required", message: "Recent authentication required" }, 403);
      }

      const body = await c.req.json().catch(() => ({}));
      const idempotencyKey =
        c.req.header("idempotency-key")?.trim() ||
        (typeof body?.idempotencyKey === "string" ? body.idempotencyKey.trim() : undefined);

      const job = await enqueueOwnerExportJob(database, owner.userId, { idempotencyKey });
      return c.json(job, 202);
    },

    getExportStatus: async (c: Context) => {
      const database = await (deps.getDb ?? getDb)();
      const owner = await (deps.resolveOwner ?? resolveOwner)(c, database);
      if (!owner.ok) return owner.response;

      const jobId = c.req.param("jobId")?.trim() || "";
      if (!jobId) return c.json({ error: "invalid_job_id", message: "Job ID required" }, 400);

      const status = await getOwnerExportJobStatus(database, owner.userId, jobId);
      if (!status) {
        return c.json({ error: "not_found", message: "Export job not found" }, 404);
      }
      return c.json(status, 200);
    },

    downloadExport: async (c: Context) => {
      const database = await (deps.getDb ?? getDb)();
      const owner = await (deps.resolveOwner ?? resolveOwner)(c, database);
      if (!owner.ok) return owner.response;

      const jobId = c.req.param("jobId")?.trim() || "";
      if (!jobId) return c.json({ error: "invalid_job_id", message: "Job ID required" }, 400);

      try {
        const payload = await readOwnerExportArtifact(database, owner.userId, jobId, {
          protectedProfileStore: deps.protectedProfileStore,
          accountKeyProvider: deps.accountKeyProvider,
          migrationMode: deps.migrationMode,
        });
        c.header("Cache-Control", "no-store");
        c.header("Content-Disposition", `attachment; filename="swyra-account-export-${jobId.replace(/[^a-zA-Z0-9_-]/g, "")}.json"`);
        return c.json(payload, 200);
      } catch (err) {
        const mapped = mapExportError(c, err);
        if (mapped) return mapped;
        throw err;
      }
    },
  };
}

const defaultHandlers = createOwnerExportHandlers();
export const handleCreateOwnerExport = defaultHandlers.createExport;
export const handleGetOwnerExportStatus = defaultHandlers.getExportStatus;
export const handleDownloadOwnerExport = defaultHandlers.downloadExport;
