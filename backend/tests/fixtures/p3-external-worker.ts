import { MongoClient } from "mongodb";
import { signOutBrowserEntry } from "../../src/identity/browser-session-registry";
import { bindOAuthTransactionSelection } from "../../src/db/oauth-transactions";
import { setTestDbOverride } from "../../src/db/mongo";

async function main() {
  const [, , action, argsJson] = process.argv;
  if (!action || !argsJson) {
    process.exit(1);
  }
  const args = JSON.parse(argsJson);
  const client = new MongoClient(args.mongoUri);
  await client.connect();
  const db = client.db(args.dbName || undefined);
  setTestDbOverride(db);

  try {
    if (action === "sign-out") {
      const res = await signOutBrowserEntry(db, args.rawBrowserProof, args.entryId);
      if (!res.ok) process.exit(2);
      process.exit(0);
    }
    if (action === "reselect") {
      const res = await bindOAuthTransactionSelection({
        transactionId: args.transactionId,
        expectedRevision: args.expectedRevision,
        browserSetId: args.browserSetId,
        entryId: args.entryId,
        userId: args.userId,
        sessionId: args.sessionId,
        sessionVersion: args.sessionVersion ?? 1,
        tokenVersion: args.tokenVersion ?? 1,
        authTime: args.authTime ?? Math.floor(Date.now() / 1000),
      });
      if (!res) process.exit(3);
      process.exit(0);
    }
    process.exit(1);
  } finally {
    await client.close().catch(() => {});
  }
}

main().catch(() => process.exit(1));
