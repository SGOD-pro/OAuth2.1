import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import { client } from "../db/mongo";
import { ensureIdentityCollectionIndexes } from "../db/indexes";
import { digestToken } from "./registration-crypto";

export const DELETION_RECEIPT_COOKIE = "swyra_deletion_receipt";
export const DELETION_RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;

export interface DeletionLedgerRecord {
  userId: string;
  operationId: string;
  denialVersion: number;
  status: "deleting" | "key_destruction_pending" | "erased" | "purged";
  committedAt: Date;
}

export interface DeletionLedgerStore {
  recordDeletionDenial(params: {
    userId: string;
    operationId: string;
    committedAt: Date;
  }): Promise<DeletionLedgerRecord>;
  isDenied(userId: string): Promise<boolean>;
}

/**
 * Independent deletion denial ledger backed by MongoDB `deletion_ledger`.
 * Written before the account DB transaction so partial failures fail closed and
 * retries converge on the same `operationId`.
 */
export class MongoDeletionLedgerStore implements DeletionLedgerStore {
  constructor(private readonly database: any) {}

  async recordDeletionDenial(params: {
    userId: string;
    operationId: string;
    committedAt: Date;
  }): Promise<DeletionLedgerRecord> {
    await ensureIdentityCollectionIndexes(this.database);
    const col = this.database.collection("deletion_ledger");
    try {
      const res = await col.findOneAndUpdate(
        { userId: params.userId },
        {
          $setOnInsert: {
            userId: params.userId,
            operationId: params.operationId,
            denialVersion: 1,
            status: "deleting",
            committedAt: params.committedAt,
          },
        },
        { upsert: true, returnDocument: "after" }
      );
      const doc = res && (res.value !== undefined ? res.value : res);
      return doc as DeletionLedgerRecord;
    } catch (err: any) {
      if (err?.code === 11000) {
        const existing = await col.findOne({ userId: params.userId });
        if (existing) return existing as DeletionLedgerRecord;
      }
      throw err;
    }
  }

  async isDenied(userId: string): Promise<boolean> {
    const doc = await this.database.collection("deletion_ledger").findOne({ userId });
    return Boolean(doc);
  }
}

function buildUserIdFilters(userId: string): any[] {
  const filters: any[] = [{ userId }];
  if (ObjectId.isValid(userId) && userId.length === 24) {
    filters.push({ userId: new ObjectId(userId) });
  }
  return filters;
}

export async function acceptOwnerDeletion(params: {
  database: any;
  userId: string;
  idempotencyKey?: string;
  ledgerStore?: DeletionLedgerStore;
  startSession?: () => any;
}): Promise<{
  operationId: string;
  status: "deleting" | "key_destruction_pending" | "erased" | "purged";
  committedAt: string;
  receiptToken: string;
}> {
  const { database, userId } = params;
  await ensureIdentityCollectionIndexes(database);
  const ledger = params.ledgerStore ?? new MongoDeletionLedgerStore(database);
  const now = new Date();
  const candidateOpId = `del_${crypto.randomUUID().replace(/-/g, "")}`;

  // Step A: Durable independent ledger denial before account transaction.
  // No cross-store atomicity is assumed; if Step B fails, retries converge on ledger.operationId.
  const ledgerEntry = await ledger.recordDeletionDenial({
    userId,
    operationId: candidateOpId,
    committedAt: now,
  });
  const operationId = ledgerEntry.operationId;
  const receiptToken = crypto.randomBytes(32).toString("base64url");
  const receiptDigest = digestToken(receiptToken, "deletion_receipt");
  const receiptExpiresAt = new Date(now.getTime() + DELETION_RECEIPT_TTL_MS);
  let finalStatus: "deleting" | "key_destruction_pending" | "erased" | "purged" = "deleting";
  let committedAt = ledgerEntry.committedAt || now;

  const runTx = async () => {
    const mongoSession = (params.startSession ?? (() => client.startSession()))();
    try {
      await mongoSession.withTransaction(async () => {
        const jobsCol = database.collection("deletion_jobs");
        const existingJob = await jobsCol.findOne({ userId }, { session: mongoSession });
        if (existingJob) {
          await jobsCol.updateOne(
            { userId },
            { $set: { receiptDigest, receiptExpiresAt, updatedAt: now } },
            { session: mongoSession }
          );
          finalStatus = existingJob.state || "deleting";
          committedAt = new Date(existingJob.createdAt || now);
          return;
        }

        const userObjectId = ObjectId.isValid(userId) && userId.length === 24 ? new ObjectId(userId) : null;
        const userFilter = userObjectId ? { $or: [{ _id: userObjectId }, { id: userId }] } : { id: userId };
        const userDoc = await database.collection("user").findOne(userFilter, { session: mongoSession });
        if (!userDoc) {
          throw Object.assign(new Error("Account not found"), { status: 404, code: "not_found" });
        }
        const nextTokenVersion = (typeof userDoc.tokenVersion === "number" ? userDoc.tokenVersion : 1) + 1;

        await database.collection("user").updateOne(
          userFilter,
          {
            $set: {
              status: "deleting",
              disabled: true,
              isActive: false,
              deletingAt: now,
              tokensRevokedBefore: now,
              tokenVersion: nextTokenVersion,
              updatedAt: now,
            },
            $inc: { sessionVersion: 1 },
          },
          { session: mongoSession }
        );

        await jobsCol.insertOne(
          {
            operationId,
            userId,
            state: "deleting",
            denialVersion: ledgerEntry.denialVersion,
            receiptDigest,
            receiptExpiresAt,
            ...(params.idempotencyKey ? { idempotencyKey: params.idempotencyKey } : {}),
            createdAt: committedAt,
            updatedAt: now,
          },
          { session: mongoSession }
        );

        const uFilters = buildUserIdFilters(userId);
        await Promise.all([
          database.collection("session").deleteMany({ $or: uFilters }, { session: mongoSession }),
          database.collection("identity_contexts").updateMany(
            { userId, revokedAt: null },
            { $set: { revokedAt: now } },
            { session: mongoSession }
          ),
          database.collection("browser_session_sets").updateMany(
            { entries: { $elemMatch: { userId, status: "active" } } },
            {
              $set: {
                "entries.$[elem].status": "signed_out",
                "entries.$[elem].sessionId": null,
                "entries.$[elem].signedOutAt": now,
              },
              $inc: { version: 1 },
            },
            { session: mongoSession, arrayFilters: [{ "elem.userId": userId, "elem.status": "active" }] }
          ),
          database.collection("oauthRefreshToken").deleteMany({ $or: uFilters }, { session: mongoSession }),
          database.collection("oauthAccessToken").deleteMany({ $or: uFilters }, { session: mongoSession }),
          database.collection("oauthAuthorizationCode").deleteMany({ $or: uFilters }, { session: mongoSession }),
          database.collection("oauth_token_families").updateMany(
            { $or: uFilters, status: { $ne: "revoked" } },
            { $set: { status: "revoked", revokedAt: now } },
            { session: mongoSession }
          ),
          database.collection("export_jobs").updateMany(
            { ownerUserId: userId, status: { $in: ["queued", "processing", "completed"] } },
            {
              $set: { status: "suppressed", errorCode: "account_deleting", updatedAt: now },
              $unset: { encryptedArtifact: "", leaseOwner: "", leaseExpiry: "" },
            },
            { session: mongoSession }
          ),
        ]);
      });
    } finally {
      await mongoSession.endSession();
    }
  };

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await runTx();
      break;
    } catch (err: any) {
      const isConflict = err?.code === 11000 || err?.code === 112 || err?.errorLabels?.includes?.("TransientTransactionError");
      if (isConflict && attempt < 2) {
        await new Promise((r) => setTimeout(r, 15 * (attempt + 1)));
        continue;
      }
      throw err;
    }
  }

  return {
    operationId,
    status: finalStatus,
    committedAt: new Date(committedAt).toISOString(),
    receiptToken,
  };
}

export async function reconcilePendingLedgerDeletions(
  database: any,
  options: { maxBatch?: number; startSession?: () => any } = {}
): Promise<{ reconciledCount: number }> {
  await ensureIdentityCollectionIndexes(database);
  const maxBatch = Math.max(1, Math.min(options.maxBatch ?? 20, 100));
  const ledgerEntries = await database.collection("deletion_ledger").find({}).limit(maxBatch).toArray();
  let reconciledCount = 0;

  for (const entry of ledgerEntries) {
    const existingJob = await database.collection("deletion_jobs").findOne({ userId: entry.userId });
    if (existingJob) continue;

    await acceptOwnerDeletion({
      database,
      userId: String(entry.userId),
      startSession: options.startSession,
      ledgerStore: {
        async recordDeletionDenial() {
          return entry as DeletionLedgerRecord;
        },
        async isDenied() {
          return true;
        },
      },
    });
    reconciledCount += 1;
  }

  return { reconciledCount };
}

export async function getDeletionStatusByReceipt(database: any, rawReceipt: string | undefined) {
  if (!rawReceipt || rawReceipt.trim().length < 16) return null;
  const receiptDigest = digestToken(rawReceipt.trim(), "deletion_receipt");
  const job = await database.collection("deletion_jobs").findOne({
    receiptDigest,
    receiptExpiresAt: { $gt: new Date() },
  });
  if (!job) return null;

  return {
    operationId: String(job.operationId),
    status: String(job.state || "deleting"),
    committedAt: new Date(job.createdAt).toISOString(),
    updatedAt: new Date(job.updatedAt).toISOString(),
  };
}
