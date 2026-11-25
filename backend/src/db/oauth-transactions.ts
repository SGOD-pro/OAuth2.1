import { getDb } from "./mongo";
import { ensureTtlIndexes } from "./indexes";

export interface OAuthTransactionDoc {
  _id?: any;
  transactionId: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  prompt?: string | null;
  maxAge?: number | null;
  nonce?: string | null;
  scope?: string | null;
  userId?: string;
  browserSetId?: string | null;
  selectedEntryId?: string | null;
  selectedUserId?: string | null;
  selectedSessionId?: string | null;
  sessionVersion?: number | null;
  tokenVersion?: number | null;
  selectionRevision: number;
  authTime?: number | null;
  mfaTime?: number | null;
  selectedAt?: Date | null;
  status: "pending" | "consumed" | "expired";
  createdAt: Date;
  expiresAt: Date;
}

export async function createOAuthTransaction(data: {
  transactionId: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  prompt?: string | null;
  maxAge?: number | null;
  nonce?: string | null;
  scope?: string | null;
  userId?: string;
  ttlSeconds?: number;
}): Promise<OAuthTransactionDoc> {
  await ensureTtlIndexes();
  const db = await getDb();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + (data.ttlSeconds ?? 600) * 1000);
  const doc: OAuthTransactionDoc = {
    transactionId: data.transactionId,
    clientId: data.clientId,
    redirectUri: data.redirectUri,
    state: data.state,
    codeChallenge: data.codeChallenge,
    codeChallengeMethod: data.codeChallengeMethod,
    prompt: data.prompt ?? null,
    maxAge: data.maxAge ?? null,
    nonce: data.nonce ?? null,
    scope: data.scope ?? null,
    userId: data.userId,
    selectionRevision: 0,
    status: "pending",
    createdAt: now,
    expiresAt,
  };
  await db.collection<OAuthTransactionDoc>("oauth_transactions").insertOne(doc);
  return doc;
}

export async function getOAuthTransaction(criteria: {
  transactionId?: string;
  state?: string;
}): Promise<OAuthTransactionDoc | null> {
  await ensureTtlIndexes();
  const db = await getDb();
  const query: any = { status: "pending", expiresAt: { $gt: new Date() } };
  if (criteria.transactionId) query.transactionId = criteria.transactionId;
  else if (criteria.state) query.state = criteria.state;
  else return null;
  return db.collection<OAuthTransactionDoc>("oauth_transactions").findOne(query);
}

export async function bindOAuthTransactionSelection(params: {
  transactionId: string;
  expectedRevision: number;
  browserSetId: string;
  entryId: string;
  userId: string;
  sessionId: string;
  sessionVersion: number;
  tokenVersion: number;
  authTime?: number | null;
  mfaTime?: number | null;
}): Promise<OAuthTransactionDoc | null> {
  const db = await getDb();
  const now = new Date();
  const revMatch = params.expectedRevision === 0
    ? { $or: [{ selectionRevision: 0 }, { selectionRevision: { $exists: false } }] }
    : { selectionRevision: params.expectedRevision };
  return db.collection<OAuthTransactionDoc>("oauth_transactions").findOneAndUpdate(
    { transactionId: params.transactionId, status: "pending", expiresAt: { $gt: now }, ...revMatch },
    {
      $set: {
        browserSetId: params.browserSetId,
        selectedEntryId: params.entryId,
        selectedUserId: params.userId,
        selectedSessionId: params.sessionId,
        sessionVersion: params.sessionVersion,
        tokenVersion: params.tokenVersion,
        authTime: params.authTime,
        mfaTime: params.mfaTime ?? null,
        selectedAt: now,
        userId: params.userId,
      },
      $inc: { selectionRevision: 1 },
    },
    { returnDocument: "after" }
  );
}

export async function consumeOAuthTransaction(transactionId: string): Promise<boolean> {
  await ensureTtlIndexes();
  const db = await getDb();
  const res = await db.collection<OAuthTransactionDoc>("oauth_transactions").updateOne(
    { transactionId, status: "pending" },
    { $set: { status: "consumed", consumedAt: new Date() } as any }
  );
  return res.modifiedCount > 0;
}
