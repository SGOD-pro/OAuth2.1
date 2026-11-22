import { getDb } from "./mongo";
import { ensureTtlIndexes } from "./indexes";
import { recordAdminAudit } from "./audit-events";

export interface TokenFamilyDoc {
  _id?: any;
  familyId: string;
  clientId: string;
  userId?: string;
  activeTokenHash: string;
  consumedTokenHashes: string[];
  status: "active" | "revoked";
  tokenVersion?: number;
  createdAt: Date;
  updatedAt: Date;
  revokedAt?: Date;
  rotating?: boolean;
  rotatingAt?: Date;
  rotationOwner?: string;
}

export async function registerTokenFamily(
  familyId: string,
  clientId: string,
  userId: string | undefined,
  initialTokenHash: string,
  tokenVersion?: number
): Promise<void> {
  const trimmedClientId = clientId?.trim();
  if (!trimmedClientId) {
    throw new Error("registerTokenFamily requires a non-empty clientId");
  }
  await ensureTtlIndexes();
  const db = await getDb();

  await db.collection<TokenFamilyDoc>("oauth_token_families").insertOne({
    familyId,
    clientId: trimmedClientId,
    userId,
    activeTokenHash: initialTokenHash,
    consumedTokenHashes: [],
    status: "active",
    tokenVersion: typeof tokenVersion === "number" ? tokenVersion : 1,
    createdAt: new Date(),
    updatedAt: new Date(),
  });
}

export async function verifyAndRotateTokenFamily(
  incomingTokenHash: string,
  newTokenHash: string,
  userId?: string,
  nowMs: number = Date.now(),
  expectedClientId?: string,
  tokenVersion?: number,
  leaseOwner?: string
): Promise<{
  valid: boolean;
  replayed: boolean;
  familyId?: string;
  clientId?: string;
  userId?: string;
  clientMismatch?: boolean;
}> {
  await ensureTtlIndexes();
  const db = await getDb();

  // 1. Authoritative lookup in MongoDB
  const doc = await db.collection<TokenFamilyDoc>("oauth_token_families").findOne({
    $or: [
      { activeTokenHash: incomingTokenHash },
      { consumedTokenHashes: incomingTokenHash },
    ],
  });

  if (!doc) {
    return { valid: false, replayed: false };
  }

  // 1b. Defense-in-depth: Cross-client isolation boundary
  if (expectedClientId && (!doc.clientId || doc.clientId !== expectedClientId)) {
    return {
      valid: false,
      replayed: false,
      familyId: doc.familyId,
      clientId: doc.clientId,
      userId: doc.userId,
      clientMismatch: true,
    };
  }

  // 2. Check if family is already revoked
  if (doc.status === "revoked") {
    return { valid: false, replayed: true, familyId: doc.familyId, clientId: doc.clientId };
  }

  // 3. Replay Detection
  if (doc.consumedTokenHashes.includes(incomingTokenHash)) {
    const rotationTime = (doc as any).rotatedAt || doc.updatedAt;
    const timeSinceRotation = rotationTime ? Math.max(0, nowMs - new Date(rotationTime).getTime()) : 10000;
    const isWithinGraceWindow = timeSinceRotation < 2000;

    if (isWithinGraceWindow) {
      return { valid: false, replayed: false, familyId: doc.familyId, clientId: doc.clientId, userId: doc.userId };
    }

    // Cascade-revoke the entire family on true replay theft
    await db.collection<TokenFamilyDoc>("oauth_token_families").updateOne(
      { _id: doc._id, ...(doc.clientId ? { clientId: doc.clientId } : {}) },
      { $set: { status: "revoked", revokedAt: new Date() } }
    );

    if (doc.clientId && doc.userId) {
      const filter = { clientId: doc.clientId, userId: doc.userId };
      await Promise.all([
        db.collection("oauthAccessToken").deleteMany(filter),
        db.collection("oauthRefreshToken").deleteMany(filter),
        db.collection("oauthAuthorizationCode").deleteMany(filter),
      ]);
    } else {
      console.warn(`[TOKEN_FAMILY_REPLAY] Warning: Family ${doc.familyId} has missing userId/clientId; revoking family record only to prevent cross-user DoS`);
    }

    await recordAdminAudit({
      action: "token_family_revoked_on_replay",
      targetClientId: doc.clientId,
      targetUserId: doc.userId,
      details: { familyId: doc.familyId, replayedTokenHash: incomingTokenHash },
      timestamp: new Date(),
    });

    return { valid: false, replayed: true, familyId: doc.familyId, clientId: doc.clientId, userId: doc.userId };
  }

  // If caller only provided a dummy hash for replay-checking without rotating
  if (newTokenHash === "dummy" || !newTokenHash) {
    return {
      valid: doc.activeTokenHash === incomingTokenHash,
      replayed: false,
      familyId: doc.familyId,
      clientId: doc.clientId,
      userId: doc.userId,
    };
  }

  // 4. Legitimate Rotation with Atomic Compare-and-Swap (CAS)
  if (doc.activeTokenHash === incomingTokenHash) {
    const filter: Record<string, any> = {
      _id: doc._id,
      activeTokenHash: incomingTokenHash,
      status: "active",
      ...(expectedClientId ? { clientId: expectedClientId } : (doc.clientId ? { clientId: doc.clientId } : {})),
    };
    if (leaseOwner) {
      filter.rotationOwner = leaseOwner;
    }

    const updateResult = await db.collection<TokenFamilyDoc>("oauth_token_families").updateOne(
      filter,
      {
        $push: { consumedTokenHashes: incomingTokenHash },
        $set: {
          activeTokenHash: newTokenHash,
          updatedAt: new Date(),
          rotating: false,
          ...(userId && !doc.userId ? { userId } : {}),
          ...(typeof tokenVersion === "number" ? { tokenVersion } : (typeof doc.tokenVersion === "number" ? { tokenVersion: doc.tokenVersion } : { tokenVersion: 1 })),
        },
        $unset: { rotationOwner: "" },
      }
    );

    if (updateResult.modifiedCount === 0) {
      return {
        valid: false,
        replayed: false,
        familyId: doc.familyId,
        clientId: doc.clientId,
        userId: doc.userId || userId,
      };
    }

    return {
      valid: true,
      replayed: false,
      familyId: doc.familyId,
      clientId: doc.clientId,
      userId: doc.userId || userId,
    };
  }

  return { valid: false, replayed: false };
}
