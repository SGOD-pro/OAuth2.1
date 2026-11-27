import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import { config } from "../config";
import { ensureIdentityCollectionIndexes } from "../db/indexes";
import { AccountKeyAccessError, type AccountKeyProvider } from "./account-key-provider";
import { prepareOwnerExport, type OwnerExportPayload } from "./owner-export";
import { openProtectedField, ProtectedFieldError, sealProtectedField, type ProtectedEnvelope } from "./protected-envelope";
import type { ProtectedProfileCollection } from "./protected-profile-store";

export const EXPORT_JOB_RETENTION_MS = 24 * 60 * 60 * 1000;
export const EXPORT_DOWNLOAD_WINDOW_MS = 5 * 60 * 1000;
export const EXPORT_LEASE_DURATION_MS = 30_000;
export const MAX_EXPORT_ATTEMPTS = 3;

export type ExportJobStatus = "queued" | "processing" | "completed" | "failed" | "expired" | "suppressed";

export type StoredExportArtifact =
  | { mode: "account_key"; envelope: ProtectedEnvelope }
  | { mode: "server_envelope"; nonce: string; ciphertext: string; tag: string; schemaVersion: number };

export interface ExportJobDeps {
  protectedProfileStore?: ProtectedProfileCollection;
  accountKeyProvider?: AccountKeyProvider;
  migrationMode?: "compat" | "strict";
  retentionMs?: number;
  downloadWindowMs?: number;
}

export class ExportArtifactError extends Error {
  constructor(
    public readonly code: "not_found" | "export_expired" | "export_not_ready" | "download_expired" | "decrypt_failed",
    public readonly status: number,
    message: string
  ) {
    super(message);
    this.name = "ExportArtifactError";
  }
}

function deriveServerExportKey(): Buffer {
  return crypto.createHash("sha256").update(`swyra-export-artifact-v1:${config.auth.secret}`).digest();
}

function sealServerArtifact(ownerUserId: string, jobId: string, plaintext: string): StoredExportArtifact {
  const key = deriveServerExportKey();
  const nonce = crypto.randomBytes(12);
  try {
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(Buffer.from(JSON.stringify([ownerUserId, "export_jobs", jobId]), "utf8"));
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return { mode: "server_envelope", nonce: nonce.toString("base64url"), ciphertext: ciphertext.toString("base64url"), tag: cipher.getAuthTag().toString("base64url"), schemaVersion: 1 };
  } finally {
    key.fill(0);
  }
}

function openServerArtifact(ownerUserId: string, jobId: string, artifact: Extract<StoredExportArtifact, { mode: "server_envelope" }>): string {
  const key = deriveServerExportKey();
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(artifact.nonce, "base64url"));
    decipher.setAAD(Buffer.from(JSON.stringify([ownerUserId, "export_jobs", jobId]), "utf8"));
    decipher.setAuthTag(Buffer.from(artifact.tag, "base64url"));
    return Buffer.concat([decipher.update(Buffer.from(artifact.ciphertext, "base64url")), decipher.final()]).toString("utf8");
  } catch {
    throw new ExportArtifactError("decrypt_failed", 500, "Failed to decrypt export artifact");
  } finally {
    key.fill(0);
  }
}

function formatEnqueued(doc: any): { jobId: string; status: ExportJobStatus; createdAt: string; expiresAt: string } {
  return {
    jobId: doc.jobId,
    status: doc.status,
    createdAt: new Date(doc.createdAt).toISOString(),
    expiresAt: new Date(doc.expiresAt).toISOString(),
  };
}

export async function enqueueOwnerExportJob(
  database: any,
  ownerUserId: string,
  options: { idempotencyKey?: string; retentionMs?: number } = {}
): Promise<{ jobId: string; status: ExportJobStatus; createdAt: string; expiresAt: string }> {
  await ensureIdentityCollectionIndexes(database);
  const col = database.collection("export_jobs");
  const now = new Date();
  const idem = options.idempotencyKey?.trim() || undefined;

  if (idem) {
    const existing = await col.findOne({ ownerUserId, idempotencyKey: idem, expiresAt: { $gt: now } });
    if (existing) return formatEnqueued(existing);
  } else {
    const active = await col.findOne({ ownerUserId, status: { $in: ["queued", "processing"] }, expiresAt: { $gt: now } }, { sort: { createdAt: -1 } });
    if (active) return formatEnqueued(active);
  }

  const jobId = `exp_${crypto.randomUUID().replace(/-/g, "")}`;
  const expiresAt = new Date(now.getTime() + (options.retentionMs ?? EXPORT_JOB_RETENTION_MS));
  const doc: Record<string, any> = {
    jobId,
    ownerUserId,
    status: "queued" as ExportJobStatus,
    fence: 0,
    attemptCount: 0,
    nextAttemptAt: now,
    createdAt: now,
    updatedAt: now,
    expiresAt,
  };
  if (idem) doc.idempotencyKey = idem;

  try {
    await col.insertOne(doc);
    return formatEnqueued(doc);
  } catch (err: any) {
    if (err?.code === 11000 && idem) {
      const winner = await col.findOne({ ownerUserId, idempotencyKey: idem });
      if (winner) return formatEnqueued(winner);
    }
    throw err;
  }
}

export async function getOwnerExportJobStatus(database: any, ownerUserId: string, jobId: string) {
  const job = await database.collection("export_jobs").findOne({ jobId, ownerUserId });
  if (!job) return null;

  const nowMs = Date.now();
  const expired = new Date(job.expiresAt).getTime() <= nowMs;
  const status: ExportJobStatus = expired ? "expired" : job.status;
  const dlExpMs = job.downloadExpiresAt ? new Date(job.downloadExpiresAt).getTime() : 0;
  const downloadAvailable = !expired && status === "completed" && Boolean(job.encryptedArtifact) && dlExpMs > nowMs;

  return {
    jobId: String(job.jobId),
    status,
    createdAt: new Date(job.createdAt).toISOString(),
    expiresAt: new Date(job.expiresAt).toISOString(),
    completedAt: job.completedAt ? new Date(job.completedAt).toISOString() : null,
    downloadExpiresAt: job.downloadExpiresAt ? new Date(job.downloadExpiresAt).toISOString() : null,
    downloadAvailable,
    errorCode: job.errorCode ? String(job.errorCode) : null,
  };
}

async function isOwnerDeniedForExport(database: any, ownerUserId: string): Promise<boolean> {
  const userFilter = ObjectId.isValid(ownerUserId) && ownerUserId.length === 24 ? { _id: new ObjectId(ownerUserId) } : { id: ownerUserId };
  const [userDoc, ledgerDoc] = await Promise.all([
    database.collection("user").findOne(userFilter),
    database.collection("deletion_ledger").findOne({ userId: ownerUserId }),
  ]);
  if (ledgerDoc || !userDoc) return true;
  return Boolean(userDoc.disabled || userDoc.banned || userDoc.isActive === false || ["inactive", "deleting", "deleted"].includes(userDoc.status) || userDoc.deletedAt);
}

export async function readOwnerExportArtifact(
  database: any,
  ownerUserId: string,
  jobId: string,
  deps: ExportJobDeps = {}
): Promise<OwnerExportPayload> {
  const job = await database.collection("export_jobs").findOne({ jobId, ownerUserId });
  if (!job) {
    throw new ExportArtifactError("not_found", 404, "Export job not found");
  }
  if (await isOwnerDeniedForExport(database, ownerUserId)) {
    throw new ExportArtifactError("export_expired", 410, "Export job is no longer available");
  }

  const nowMs = Date.now();
  if (new Date(job.expiresAt).getTime() <= nowMs) {
    throw new ExportArtifactError("export_expired", 410, "Export job has expired");
  }
  if (job.status !== "completed" || !job.encryptedArtifact) {
    throw new ExportArtifactError("export_not_ready", 409, "Export artifact is not ready for download");
  }
  if (job.downloadExpiresAt && new Date(job.downloadExpiresAt).getTime() <= nowMs) {
    throw new ExportArtifactError("download_expired", 410, "Export download window has expired");
  }

  const artifact = job.encryptedArtifact as StoredExportArtifact;
  let plaintext: string;
  if (artifact.mode === "account_key") {
    if (!deps.accountKeyProvider) {
      throw new ExportArtifactError("decrypt_failed", 500, "Account key provider unavailable");
    }
    plaintext = await openProtectedField({
      provider: deps.accountKeyProvider,
      accountId: ownerUserId,
      collection: "export_jobs",
      recordId: jobId,
      fieldPurpose: "export.artifact",
      envelope: artifact.envelope,
    });
  } else {
    plaintext = openServerArtifact(ownerUserId, jobId, artifact);
  }
  return JSON.parse(plaintext) as OwnerExportPayload;
}

async function failFencedJob(col: any, jobId: string, leaseOwner: string, fence: number, errorCode: string, status: ExportJobStatus = "failed") {
  await col.updateOne(
    { jobId, leaseOwner, fence, status: "processing" },
    {
      $set: { status, errorCode, updatedAt: new Date() },
      $unset: { leaseOwner: "", leaseExpiry: "", encryptedArtifact: "" },
    }
  );
}

export async function processNextExportJob(database: any, deps: ExportJobDeps = {}): Promise<boolean> {
  const col = database.collection("export_jobs");
  const now = new Date();
  const leaseOwner = crypto.randomUUID();

  const claimed = await col.findOneAndUpdate(
    {
      $or: [
        { status: "queued", nextAttemptAt: { $lte: now }, expiresAt: { $gt: now } },
        { status: "processing", leaseExpiry: { $lt: now }, expiresAt: { $gt: now } },
      ],
    },
    {
      $set: { status: "processing", leaseOwner, leaseExpiry: new Date(now.getTime() + EXPORT_LEASE_DURATION_MS), updatedAt: now },
      $inc: { fence: 1 },
    },
    { sort: { nextAttemptAt: 1, createdAt: 1 }, returnDocument: "after" }
  );
  const job = claimed && (claimed.value !== undefined ? claimed.value : claimed);
  if (!job) return false;

  const fence = job.fence as number;
  const expiresMs = new Date(job.expiresAt).getTime();
  if (expiresMs <= Date.now()) {
    await failFencedJob(col, job.jobId, leaseOwner, fence, "export_expired", "expired");
    return true;
  }

  const attemptsDone = (job.attemptCount ?? 0) + 1;
  try {
    if (await isOwnerDeniedForExport(database, job.ownerUserId)) {
      await failFencedJob(col, job.jobId, leaseOwner, fence, "account_deleting", "suppressed");
      return true;
    }
    const payload = await prepareOwnerExport(database, job.ownerUserId, {
      protectedProfileStore: deps.protectedProfileStore,
      accountKeyProvider: deps.accountKeyProvider,
      migrationMode: deps.migrationMode,
    });
    if (!payload) {
      await failFencedJob(col, job.jobId, leaseOwner, fence, "account_not_found");
      return true;
    }

    const serialized = JSON.stringify(payload);
    const encryptedArtifact: StoredExportArtifact = deps.accountKeyProvider
      ? {
          mode: "account_key",
          envelope: await sealProtectedField({
            provider: deps.accountKeyProvider, accountId: job.ownerUserId, collection: "export_jobs", recordId: job.jobId, fieldPurpose: "export.artifact", plaintext: serialized,
          }),
        }
      : sealServerArtifact(job.ownerUserId, job.jobId, serialized);

    if (await isOwnerDeniedForExport(database, job.ownerUserId)) {
      await failFencedJob(col, job.jobId, leaseOwner, fence, "account_deleting", "suppressed");
      return true;
    }
    const completedAt = new Date();
    const dlWindow = deps.downloadWindowMs ?? EXPORT_DOWNLOAD_WINDOW_MS;
    const downloadExpiresAt = new Date(Math.min(completedAt.getTime() + dlWindow, expiresMs));
    await col.updateOne(
      { jobId: job.jobId, leaseOwner, fence, status: "processing" },
      {
        $set: { status: "completed", encryptedArtifact, attemptCount: attemptsDone, completedAt, downloadExpiresAt, updatedAt: completedAt },
        $unset: { leaseOwner: "", leaseExpiry: "", lastErrorCode: "", errorCode: "" },
      }
    );
  } catch (err: any) {
    if (err instanceof AccountKeyAccessError && err.code === "provider_outage") {
      const remainingMs = expiresMs - Date.now();
      if (attemptsDone < MAX_EXPORT_ATTEMPTS && remainingMs > 50) {
        const backoffMs = Math.min(remainingMs - 10, 150 * (2 ** (attemptsDone - 1)));
        await col.updateOne(
          { jobId: job.jobId, leaseOwner, fence, status: "processing" },
          {
            $set: { status: "queued", attemptCount: attemptsDone, nextAttemptAt: new Date(Date.now() + backoffMs), lastErrorCode: err.code, updatedAt: new Date() },
            $unset: { leaseOwner: "", leaseExpiry: "", encryptedArtifact: "" },
          }
        );
        return true;
      }
    }
    const code = err instanceof AccountKeyAccessError || err instanceof ProtectedFieldError ? err.code : "export_failed";
    await failFencedJob(col, job.jobId, leaseOwner, fence, code);
  }
  return true;
}
