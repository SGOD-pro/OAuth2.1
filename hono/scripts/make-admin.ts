import { getDb, closeDb } from "../src/db/mongo";
import * as readline from "readline/promises";
import { userInfo } from "os";

async function run() {
  const email = process.argv[2];
  if (!email) {
    console.error("Usage: npx tsx scripts/make-admin.ts <email>");
    process.exit(1);
  }

  const db = await getDb();
  const user = await db.collection("user").findOne({ email });

  if (!user) {
    console.error(`User with email ${email} not found.`);
    await closeDb();
    process.exit(1);
  }

  if (user.role === "admin") {
    console.log(`User ${email} is already an admin.`);
    await closeDb();
    process.exit(0);
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const answer = await rl.question(`Are you sure you want to promote ${email} to admin? Type YES to confirm: `);
  
  if (answer !== "YES") {
    console.log("Aborted.");
    rl.close();
    await closeDb();
    process.exit(0);
  }

  rl.close();

  await db.collection("user").updateOne({ _id: user._id }, { $set: { role: "admin" } });
  
  const runner = userInfo().username;
  const timestamp = new Date().toISOString();
  
  console.log(`[${timestamp}] Promotion logged: User ${email} promoted to admin by ${runner}.`);
  
  await closeDb();
}

run().catch(async (e) => {
  console.error(e);
  await closeDb();
  process.exit(1);
});
