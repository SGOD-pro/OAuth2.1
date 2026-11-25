import { ObjectId } from "mongodb";
import { hashToken } from "../utils/security";

export interface SelectedSessionIssuanceFence {
  transactionId: string;
  expectedSelectionRevision: number;
  expectedSessionId: string;
  expectedEntryId: string;
  expectedBrowserSetId?: string;
  expectedUserId?: string;
}

export async function resolveSessionFenceFromTransaction(
  database: any,
  transactionId: string
): Promise<SelectedSessionIssuanceFence | undefined> {
  try {
    const tx = await database.collection("oauth_transactions").findOne({
      transactionId,
      status: "pending",
      expiresAt: { $gt: new Date() },
    });
    if (tx?.selectedSessionId && tx.selectedEntryId) {
      return {
        transactionId: tx.transactionId,
        expectedSelectionRevision: typeof tx.selectionRevision === "number" ? tx.selectionRevision : 1,
        expectedSessionId: tx.selectedSessionId,
        expectedEntryId: tx.selectedEntryId,
        expectedBrowserSetId: tx.browserSetId || undefined,
        expectedUserId: tx.selectedUserId || tx.userId || undefined,
      };
    }
  } catch {}
  return undefined;
}

export async function commitSelectedSessionLinearization(
  database: any,
  fence: SelectedSessionIssuanceFence,
  code?: string
): Promise<boolean> {
  const mongoClient = (database as any).client;
  const runAtomicGuard = async (session?: any): Promise<boolean> => {
    const opt = session ? { session } : {};
    const now = new Date();

    const txMatch: Record<string, any> = {
      transactionId: fence.transactionId,
      status: "pending",
      expiresAt: { $gt: now },
      selectionRevision: fence.expectedSelectionRevision,
      selectedSessionId: fence.expectedSessionId,
      selectedEntryId: fence.expectedEntryId,
    };
    if (fence.expectedBrowserSetId) txMatch.browserSetId = fence.expectedBrowserSetId;
    const txUpdateSet: Record<string, any> = { lastCodeIssuedAt: now };
    if (code) txUpdateSet.issuedCodeHash = hashToken(code, "base64url");

    const txUpdated = await database.collection("oauth_transactions").findOneAndUpdate(
      txMatch,
      { $set: txUpdateSet },
      { ...opt, returnDocument: "after" }
    );
    const txDoc = txUpdated && (txUpdated.value !== undefined ? txUpdated.value : txUpdated);
    if (!txDoc) return false;

    const sessFilters: any[] = [{ id: fence.expectedSessionId }];
    if (ObjectId.isValid(fence.expectedSessionId) && fence.expectedSessionId.length === 24) {
      sessFilters.push({ _id: new ObjectId(fence.expectedSessionId) });
    }
    const sessMatch: Record<string, any> = {
      $or: sessFilters,
      expiresAt: { $gt: now },
      revokedAt: { $exists: false },
    };
    if (fence.expectedUserId) {
      const uid = fence.expectedUserId;
      sessMatch.$and = [
        {
          $or: [
            { userId: uid },
            ...(ObjectId.isValid(uid) && uid.length === 24 ? [{ userId: new ObjectId(uid) }] : []),
          ],
        },
      ];
    }
    const sessUpdated = await database.collection("session").findOneAndUpdate(
      sessMatch,
      { $set: { lastCodeIssuedAt: now } },
      { ...opt, returnDocument: "after" }
    );
    const sessDoc = sessUpdated && (sessUpdated.value !== undefined ? sessUpdated.value : sessUpdated);
    if (!sessDoc) return false;

    if (fence.expectedBrowserSetId) {
      const setDoc = await database.collection("browser_session_sets").findOne(
        {
          setId: fence.expectedBrowserSetId,
          revokedAt: null,
          expiresAt: { $gt: now },
          entries: {
            $elemMatch: {
              entryId: fence.expectedEntryId,
              sessionId: fence.expectedSessionId,
              status: "active",
            },
          },
        },
        opt
      );
      if (!setDoc) return false;
    }

    return true;
  };

  if (mongoClient && typeof mongoClient.startSession === "function") {
    const session = mongoClient.startSession();
    try {
      let ok = false;
      await session.withTransaction(async () => {
        ok = await runAtomicGuard(session);
        if (!ok) await session.abortTransaction();
      });
      return ok;
    } catch {
      return false;
    } finally {
      await session.endSession().catch(() => {});
    }
  }
  return runAtomicGuard(undefined);
}
