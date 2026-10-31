import { MongoClient } from "mongodb";
import dotenv from "dotenv";
import { migrateLegacyAppAdmins, selfHealAppAdmins } from "../src/utils/admin-sync";

dotenv.config({ path: ".env" });

async function syncDb(client: MongoClient, dbName: string, dryRun: boolean) {
  const db = client.db(dbName);
  console.log(`\n========================================`);
  console.log(`  Database: ${dbName} (${dryRun ? "DRY RUN" : "APPLY"})`);
  console.log(`========================================`);

  const result = await migrateLegacyAppAdmins(db, { dryRun });

  console.log(`\nMigration Summary for ${dbName}:`);
  console.log(`  - Migrated: ${result.migratedCount}`);
  console.log(`  - Conflicts: ${result.conflictCount}`);
  console.log(`  - Skipped/Duplicates: ${result.skippedCount}`);

  if (result.conflicts.length > 0) {
    console.log(`\n  Conflict Details:`);
    for (const c of result.conflicts) {
      console.log(`    * [CONFLICT] Client: ${c.clientId}, Email: ${c.email}, Reason: ${c.reason}`);
    }
  }

  if (result.migrated.length > 0) {
    console.log(`\n  Migrated Records:`);
    for (const m of result.migrated) {
      console.log(`    * [MIGRATED] Client: ${m.clientId}, Email: ${m.email} -> UserId: ${m.userId} (Status: ${m.status})`);
    }
  }

  if (!dryRun) {
    console.log(`\nRunning background self-heal for active identities in ${dbName}...`);
    await selfHealAppAdmins(db);
    console.log(`Self-heal complete.`);
  }
}

async function main() {
  const uri = process.env.MONGO_URI;
  if (!uri) {
    console.error("MONGO_URI not found in environment");
    process.exit(1);
  }

  const isApply = process.argv.includes("--apply");
  const dryRun = !isApply;

  console.log(`\n======================================================`);
  console.log(`  SWYRA AUTH -- APPLICATION ADMIN MIGRATION RUNNER`);
  if (dryRun) {
    console.log(`  MODE: DRY RUN (Auditing only, no database mutations)`);
    console.log(`  To apply changes to database, pass --apply flag`);
  } else {
    console.log(`  MODE: APPLY (Mutating database records with audit trail)`);
  }
  console.log(`======================================================`);

  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 30000 });
  await client.connect();

  try {
    await syncDb(client, "oauthservice", dryRun);
    await syncDb(client, "oauthservice-dev", dryRun);
  } finally {
    await client.close();
  }

  console.log(`\nMigration process finished successfully.`);
}

main().catch((err) => {
  console.error("Migration failed:", err?.message || err);
  process.exit(1);
});
