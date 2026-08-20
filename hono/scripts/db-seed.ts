import crypto from "crypto";
import { getDb, closeDb } from "../src/db/mongo";

function hashSecret(secret: string): string {
  return crypto.createHash("sha256").update(secret).digest("base64url");
}

async function seed() {
  console.log("Seeding default demo OAuth 2.1 clients into MongoDB...");
  const db = await getDb();

  const nextClientId = "qMoXkZwvWnZJRmFhpiTyzLMozZYrwvlF";
  const nextSecret = "HQEFWhArRpYvjySBrzSbtBBlOpeZDpHY";
  const nextHashedSecret = hashSecret(nextSecret);

  const expressClientId = "VyhlDhjmztsAsFphQjBsmXiSXjfpFoug";
  const expressSecret = "HSqJGpkNCkMJqUicZLFIoNdDyCsNOABI";
  const expressHashedSecret = hashSecret(expressSecret);

  await db.collection("oauthClient").deleteMany({
    $or: [
      { id: { $in: [nextClientId, expressClientId] } },
      { clientId: { $in: [nextClientId, expressClientId] } },
      { client_id: { $in: [nextClientId, expressClientId] } }
    ]
  });

  const now = new Date();

  await db.collection("oauthClient").insertMany([
    {
      id: nextClientId,
      clientId: nextClientId,
      client_id: nextClientId,
      clientSecret: nextHashedSecret,
      client_secret: nextHashedSecret,
      name: "Next.js Demo App",
      client_name: "Next.js Demo App",
      redirectUris: ["http://localhost:3001/api/auth/callback"],
      redirect_uris: ["http://localhost:3001/api/auth/callback"],
      allowedOrigins: ["http://localhost:3001"],
      allowed_origins: ["http://localhost:3001"],
      disabled: false,
      is_active: true,
      skipConsent: false,
      isDev: true,
      is_dev: true,
      createdAt: now,
      updatedAt: now
    },
    {
      id: expressClientId,
      clientId: expressClientId,
      client_id: expressClientId,
      clientSecret: expressHashedSecret,
      client_secret: expressHashedSecret,
      name: "React Express Demo App",
      client_name: "React Express Demo App",
      redirectUris: ["http://localhost:4000/auth/callback", "http://localhost:5175"],
      redirect_uris: ["http://localhost:4000/auth/callback", "http://localhost:5175"],
      allowedOrigins: ["http://localhost:4000", "http://localhost:5175"],
      allowed_origins: ["http://localhost:4000", "http://localhost:5175"],
      disabled: false,
      is_active: true,
      skipConsent: false,
      isDev: true,
      is_dev: true,
      createdAt: now,
      updatedAt: now
    }
  ]);

  console.log("Successfully seeded Next.js and React Express demo OAuth clients.");
  await closeDb();
}

seed().catch(async (err) => {
  console.error("Failed to seed database:", err);
  await closeDb();
  process.exit(1);
});
