import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import { AccountKeyAccessError, type AccountKeyProvider } from "./account-key-provider";
import { ensureIdentityCollectionIndexes } from "../db/indexes";

const CLEANUP_LEASE_MS = 30_000;

export interface DeletionCleanupDeps {
  accountKeyProvider?: AccountKeyProvider;
  keyRefsProvider?: (database: any, userId: string) => Promise<string[]>;
}

function buildUserIdFilters(userId: string): any[] {
  const filters: any[] = [{ userId }];
  if (ObjectId.isValid(userId) && userId.length === 24) {
    filters.push({ userId: new ObjectId(userId) });
  }
  return filters;
}

async function collectAccountKeyRefs(database: any, userId: string, deps: DeletionCleanupDeps): Promise<string[]> {
  const refs = new Set<string>();
  if (deps.keyRefsProvider) {
    for (const r of await deps.keyRefsProvider(database, userId)) refs.add(r);
  }
  const [userDoc, profDoc] = await Promise.all([
    database.collection("user").findOne(ObjectId.isValid(userId) && userId.length === 24 ? { _id: new ObjectId(userId) } : { id: userId }),
    database.collection("identity_profiles").findOne({ userId }),
  ]);
  if (typeof userDoc?.keyRef === "string" && userDoc.keyRef) refs.add(userDoc.keyRef);
  if (typeof profDoc?.nameEnvelope?.keyRef === "string") refs.add(profDoc.nameEnvelope.keyRef);
  if (typeof profDoc?.emailEnvelope?.keyRef === "string") refs.add(profDoc.emailEnvelope.keyRef);
  return [...refs];
}

export async function processNextDeletionCleanupJob(
  database: any,
  deps: DeletionCleanupDeps = {}
): Promise<boolean> {
  await ensureIdentityCollectionIndexes(database);
  const jobsCol = database.collection("deletion_jobs");
  const ledgerCol = database.collection("deletion_ledger");
  const now = new Date();
  const leaseOwner = crypto.randomUUID();

  const claimed = await jobsCol.findOneAndUpdate(
    {
      state: { $in: ["deleting", "key_destruction_pending"] },
      $or: [
        { leaseExpiry: { $exists: false } },
        { leaseExpiry: null },
        { leaseExpiry: { $lt: now } },
      ],
    },
    {
      $set: { leaseOwner, leaseExpiry: new Date(now.getTime() + CLEANUP_LEASE_MS), updatedAt: now },
      $inc: { fence: 1 },
    },
    { sort: { updatedAt: 1 }, returnDocument: "after" }
  );
  const job = claimed && (claimed.value !== undefined ? claimed.value : claimed);
  if (!job) return false;

  const userId = String(job.userId);
  const fence = job.fence as number;
  const uFilters = buildUserIdFilters(userId);
  const keyRefs: string[] = Array.isArray(job.keyInventory) && job.keyInventory.length > 0
    ? job.keyInventory
    : await collectAccountKeyRefs(database, userId, deps);

  try {
    if (job.state === "deleting") {
      // Phase 1: Deny/schedule destruction on all account keys before purging profile envelopes
      if (deps.accountKeyProvider && keyRefs.length > 0) {
        for (const keyRef of keyRefs) {
          try {
            await deps.accountKeyProvider.denyAccess(userId, keyRef, `deletion:${job.operationId}`);
          } catch (err) {
            if (!(err instanceof AccountKeyAccessError && (err.code === "key_scheduled_destruction" || err.code === "key_destroyed" || err.code === "key_not_found"))) {
              throw err;
            }
          }
          try {
            await deps.accountKeyProvider.scheduleDestruction(userId, keyRef);
          } catch (err) {
            if (!(err instanceof AccountKeyAccessError && err.code === "key_not_found")) {
              throw err;
            }
          }
        }
      }

      // Phase 2: Purge residual credentials, lookups, consents, sessions, and profile envelopes
      await Promise.all([
        database.collection("account").deleteMany({ $or: uFilters }),
        database.collection("twoFactor").deleteMany({ $or: uFilters }),
        database.collection("totp_used_steps").deleteMany({ userId }),
        database.collection("identity_lookup").deleteMany({ userId }),
        database.collection("identity_profiles").deleteMany({ userId }),
        database.collection("oauthConsent").deleteMany({ $or: uFilters }),
        database.collection("user_app_registrations").deleteMany({ $or: uFilters }),
        database.collection("export_jobs").deleteMany({ ownerUserId: userId }),
      ]);

      await Promise.all([
        jobsCol.updateOne(
          { operationId: job.operationId, leaseOwner, fence },
          { $set: { state: "key_destruction_pending", keyInventory: keyRefs, updatedAt: new Date() }, $unset: { leaseOwner: "", leaseExpiry: "" } }
        ),
        ledgerCol.updateOne(
          { userId },
          { $set: { status: "key_destruction_pending", updatedAt: new Date() } }
        ),
        database.collection("user").updateOne(
          ObjectId.isValid(userId) && userId.length === 24 ? { _id: new ObjectId(userId) } : { id: userId },
          { $set: { status: "key_destruction_pending", updatedAt: new Date() } }
        ),
      ]);
      return true;
    }

    if (job.state === "key_destruction_pending") {
      let allDestroyed = true;
      if (deps.accountKeyProvider && keyRefs.length > 0) {
        for (const keyRef of keyRefs) {
          try {
            const st = await deps.accountKeyProvider.getKeyState(userId, keyRef);
            if (st.state !== "destroyed") {
              allDestroyed = false;
              break;
            }
          } catch (err) {
            if (err instanceof AccountKeyAccessError && err.code === "key_not_found") {
              continue;
            }
            throw err;
          }
        }
      }

      if (!allDestroyed) {
        await jobsCol.updateOne(
          { operationId: job.operationId, leaseOwner, fence },
          { $set: { updatedAt: new Date() }, $unset: { leaseOwner: "", leaseExpiry: "" } }
        );
        return true;
      }

      // Final phase: scrubbed tombstone preserving opaque _id/status/tokenVersion, removing PII
      const deletedAt = new Date();
      const userFilter = ObjectId.isValid(userId) && userId.length === 24 ? { _id: new ObjectId(userId) } : { id: userId };
      await Promise.all([
        database.collection("user").updateOne(
          userFilter,
          {
            $set: { status: "purged", disabled: true, isActive: false, deletedAt, updatedAt: deletedAt },
            $unset: { email: "", name: "", username: "", usernameNormalized: "", usernameLookup: "", keyRef: "" },
          }
        ),
        jobsCol.updateOne(
          { operationId: job.operationId, leaseOwner, fence },
          {
            $set: { state: "purged", erasedAt: deletedAt, purgedAt: deletedAt, updatedAt: deletedAt },
            $unset: { leaseOwner: "", leaseExpiry: "" },
          }
        ),
        ledgerCol.updateOne(
          { userId },
          { $set: { status: "purged", erasedAt: deletedAt, updatedAt: deletedAt } }
        ),
      ]);
      return true;
    }
  } catch {
    await jobsCol.updateOne(
      { operationId: job.operationId, leaseOwner, fence },
      { $set: { updatedAt: new Date() }, $unset: { leaseOwner: "", leaseExpiry: "" } }
    );
  }
  return true;
}

/**
 * Quarantine restore replay (P7.4): restores an older user snapshot into quarantine,
 * replays independent `deletion_ledger` denials, and prevents deleted accounts from resurrecting.
 */
export async function restoreSnapshotInQuarantine(
  database: any,
  snapshotUsers: any[]
): Promise<{ restoredActiveCount: number; quarantinedDeletedCount: number }> {
  await ensureIdentityCollectionIndexes(database);
  const ledgerDocs = await database.collection("deletion_ledger").find({}).toArray();
  const deniedByUser = new Map<string, any>(ledgerDocs.map((d: any) => [String(d.userId), d]));

  let restoredActiveCount = 0;
  let quarantinedDeletedCount = 0;
  const now = new Date();

  for (const snapUser of snapshotUsers) {
    const uid = String(snapUser._id || snapUser.id);
    const denial = deniedByUser.get(uid);
    if (denial) {
      await database.collection("user").updateOne(
        { _id: snapUser._id },
        {
          $set: {
            status: denial.status || "deleting",
            disabled: true,
            isActive: false,
            deletedAt: denial.committedAt || now,
            tokensRevokedBefore: now,
            tokenVersion: Math.max((snapUser.tokenVersion ?? 1) + 1, 2),
            updatedAt: now,
          },
          $unset: { email: "", name: "", username: "", usernameNormalized: "", usernameLookup: "", keyRef: "" },
        },
        { upsert: true }
      );
      await Promise.all([
        database.collection("session").deleteMany({ $or: buildUserIdFilters(uid) }),
        database.collection("oauthRefreshToken").deleteMany({ $or: buildUserIdFilters(uid) }),
        database.collection("oauthAccessToken").deleteMany({ $or: buildUserIdFilters(uid) }),
        database.collection("identity_profiles").deleteMany({ userId: uid }),
      ]);
      quarantinedDeletedCount += 1;
    } else {
      await database.collection("user").updateOne(
        { _id: snapUser._id },
        { $set: snapUser },
        { upsert: true }
      );
      restoredActiveCount += 1;
    }
  }

  return { restoredActiveCount, quarantinedDeletedCount };
}
