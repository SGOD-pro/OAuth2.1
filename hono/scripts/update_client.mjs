/**
 * update_client.mjs — One-off MongoDB patch helper.
 *
 * SECURITY RULES (read before running):
 * 1. NEVER hardcode credentials or client IDs in this file.
 * 2. NEVER use this script to write raw/plaintext client secrets into MongoDB.
 *    All client secret management MUST go through authProvider.api.adminCreateOAuthClient
 *    or adminUpdateOAuthClient so Better Auth can hash them correctly.
 * 3. Read connection URI and target clientId from environment variables only.
 *
 * Usage (from hono/):
 *   MONGO_URI="mongodb+srv://..." CLIENT_ID="..." node --env-file=.env scripts/update_client.mjs
 */

import { MongoClient } from "mongodb";

const uri = process.env.MONGO_URI;
const clientId = process.env.TARGET_CLIENT_ID;

if (!uri) {
  console.error("ERROR: MONGO_URI environment variable is not set.");
  process.exit(1);
}
if (!clientId) {
  console.error("ERROR: TARGET_CLIENT_ID environment variable is not set.");
  process.exit(1);
}

const client = new MongoClient(uri);
await client.connect();
const db = client.db();

await db.collection("oauthClient").updateOne(
  { clientId },
  { $addToSet: { allowedOrigins: "http://localhost:5175" } }
);

await db.collection("origin_cache").deleteMany({});

console.log(`Updated allowedOrigins for clientId=${clientId} and cleared origin_cache`);
await client.close();
