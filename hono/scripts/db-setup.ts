import { getDb, closeDb } from "../src/db/mongo";
import { getOriginCache } from "../src/db/state";

async function run() {
  console.log("Setting up database and TTL indexes...");
  
  // The state.ts functions automatically call ensureTtlIndexes()
  // We can just call getOriginCache with a dummy value to trigger it
  await getOriginCache("dummy-setup-origin");
  
  console.log("Database setup complete. TTL indexes applied.");
  await closeDb();
}

run().catch(async (e) => {
  console.error(e);
  await closeDb();
  process.exit(1);
});
