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
  userId?: string;
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
  userId?: string;
  ttlSeconds?: number;
}): Promise<OAuthTransactionDoc> {
  await ensureTtlIndexes();
  const db = await getDb();
  const now = new Date();
  const ttl = data.ttlSeconds ?? 600; // 10 minutes default
  const expiresAt = new Date(now.getTime() + ttl * 1000);

  const doc: OAuthTransactionDoc = {
    transactionId: data.transactionId,
    clientId: data.clientId,
    redirectUri: data.redirectUri,
    state: data.state,
    codeChallenge: data.codeChallenge,
    codeChallengeMethod: data.codeChallengeMethod,
    userId: data.userId,
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

  if (criteria.state) {
    query.state = criteria.state;
  } else if (criteria.transactionId) {
    query.transactionId = criteria.transactionId;
  } else {
    return null;
  }

  return db.collection<OAuthTransactionDoc>("oauth_transactions").findOne(query);
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
