import { MongoClient } from "mongodb";
import { config } from "dotenv";
import { randomBytes } from "crypto";
config();

const clientId = "dcxvzMTGtSKXpNdrSYqNDJKZlDLjuomp";
const newSecret = randomBytes(32).toString("base64url");

const m = new MongoClient(process.env.MONGO_URI);
await m.connect();
const db = m.db();
const r = await db.collection("oauthClient").updateOne(
  { clientId },
  { $set: { clientSecret: newSecret, isPublicClient: false } }
);
console.log("Updated:", r.modifiedCount);
console.log("\n==============================");
console.log("New Client Secret:", newSecret);
console.log("==============================\n");
console.log("COPY this into:");
console.log("  backend/.env  -> CLIENT_SECRET=<above>");
await m.close();
