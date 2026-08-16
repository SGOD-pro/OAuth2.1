/**
 * make-public-client.ts
 *
 * One-time utility: converts an existing confidential OAuth client to a PUBLIC
 * client by nulling out its clientSecret in MongoDB.
 *
 * A public client (SPA, mobile app) uses PKCE to secure the authorization
 * code flow and MUST NOT require a client_secret at the token endpoint.
 *
 * Usage (run from hono/ directory):
 *   npx tsx scripts/make-public-client.ts <CLIENT_ID>
 *
 * Example:
 *   npx tsx scripts/make-public-client.ts dcxvzMTGtSKXpNdrSYqNDJKZlDLjuomp
 */

import { MongoClient } from "mongodb";
import * as dotenv from "dotenv";
import * as path from "path";
import * as readline from "readline";

dotenv.config({ path: path.resolve(process.cwd(), ".env") });

const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error("MONGO_URI is not set in .env");
  process.exit(1);
}

const clientId = process.argv[2];
if (!clientId) {
  console.error("Usage: npx tsx scripts/make-public-client.ts <CLIENT_ID>");
  process.exit(1);
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
function confirm(question: string): Promise<boolean> {
  return new Promise(resolve =>
    rl.question(question, ans => { rl.close(); resolve(ans.trim().toLowerCase() === "y"); })
  );
}

async function main() {
  const mongo = new MongoClient(MONGO_URI!);
  await mongo.connect();
  const db = mongo.db();

  const existing = await db.collection("oauthClient").findOne({ clientId });
  if (!existing) {
    console.error(`No client found with clientId: ${clientId}`);
    await mongo.close();
    process.exit(1);
  }

  console.log(`\nClient Name : ${existing.name}`);
  console.log(`Client ID   : ${existing.clientId}`);
  console.log(`Has Secret  : ${existing.clientSecret ? "YES (will be nulled)" : "Already null"}`);
  console.log(`Redirect    : ${(existing.redirectUris || []).join(", ")}\n`);

  const ok = await confirm("Convert to PUBLIC client (removes clientSecret)? [y/N] ");
  if (!ok) { console.log("Aborted."); await mongo.close(); process.exit(0); }

  await db.collection("oauthClient").updateOne(
    { clientId },
    { $set: { isPublicClient: true, clientSecret: null } }
  );

  console.log(`\nClient "${existing.name}" is now a PUBLIC client.`);
  console.log("Token endpoint accepts PKCE code_verifier without client_secret.\n");
  await mongo.close();
}

main().catch(err => { console.error("Script failed:", err); process.exit(1); });
