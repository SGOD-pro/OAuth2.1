import { getDb, closeDb } from "../src/db/mongo";
import { getOriginCache } from "../src/db/state";

async function run() {
  console.log("Setting up database and TTL indexes...");
  
  // The state.ts functions automatically call ensureTtlIndexes()
  // We can just call getOriginCache with a dummy value to trigger it
  await getOriginCache("dummy-setup-origin");

  // Ensure all existing accounts conform to Better Auth 1.6+ issuer schema
  const db = await getDb();
  await db.collection("account").updateMany(
    { providerId: "credential", issuer: { $exists: false } },
    { $set: { issuer: "local:credential" } }
  );
  await db.collection("account").updateMany(
    { providerId: "google", issuer: { $exists: false } },
    { $set: { issuer: "local:oauth:google" } }
  );

  // Application admin management & revocation indexes
  await db.collection("app_admins").createIndex(
    { clientId: 1, email: 1 },
    { unique: true, name: "app_admins_client_email_unique" }
  );
  await db.collection("app_admins").createIndex(
    { clientId: 1 },
    { name: "app_admins_client_lookup" }
  );
  await db.collection("app_admin_revoked_tokens").createIndex(
    { expiresAt: 1 },
    { expireAfterSeconds: 0, name: "app_admin_revoked_tokens_ttl" }
  );
  
  console.log("Database setup complete. TTL indexes and account schema migrations applied.");
  await closeDb();
}

run().catch(async (e) => {
  console.error(e);
  await closeDb();
  process.exit(1);
});
