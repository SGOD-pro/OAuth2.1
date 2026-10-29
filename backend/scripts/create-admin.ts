import { getDb, closeDb } from "../src/db/mongo";
import { hashPassword } from "better-auth/crypto";
import { isStrongPassword } from "../src/utils/security";
import { ObjectId } from "mongodb";

async function run() {
  const email = process.argv[2];
  const password = process.argv[3];
  const name = process.argv[4] || "Administrator";

  if (!email || !password) {
    console.log("\n❌ Usage: npm run admin:create -- <email> <password> [name]\n");
    console.log("Example:");
    console.log("  npm run admin:create -- swyra@auth2.1.com \"AdminPassword@123!\"\n");
    process.exit(1);
  }

  if (!isStrongPassword(password)) {
    console.error(
      "\n❌ Password is too weak. It must be 12–128 characters and contain:\n" +
      "  - At least one uppercase letter (A-Z)\n" +
      "  - At least one lowercase letter (a-z)\n" +
      "  - At least one number (0-9)\n" +
      "  - At least one special symbol (!@#$%^&*...)\n"
    );
    process.exit(1);
  }

  const db = await getDb();
  const hashedPassword = await hashPassword(password);
  const now = new Date();

  // Find user by email
  let user = await db.collection("user").findOne({ email });
  let userObjId: ObjectId;

  if (user) {
    console.log(`\nℹ️ Found existing user record for "${email}". Updating role to admin...`);
    userObjId = user._id instanceof ObjectId ? user._id : new ObjectId(String(user._id));

    await db.collection("user").updateOne(
      { _id: user._id },
      {
        $set: {
          role: "admin",
          scopedClientId: null,
          emailVerified: true,
          updatedAt: now,
        },
      }
    );
  } else {
    console.log(`\nCreating new user record for "${email}"...`);
    userObjId = new ObjectId();

    await db.collection("user").insertOne({
      _id: userObjId,
      name,
      email,
      emailVerified: true,
      role: "admin",
      scopedClientId: null,
      banned: false,
      createdAt: now,
      updatedAt: now,
    });
  }

  // Delete any stale account entries for this user / email
  await db.collection("account").deleteMany({
    $or: [
      { userId: userObjId },
      { userId: String(userObjId) },
      { accountId: String(userObjId) },
      { accountId: email },
    ]
  });

  // Better-Auth MongoDB adapter stores userId as an ObjectId reference
  await db.collection("account").insertOne({
    _id: new ObjectId(),
    userId: userObjId,
    accountId: String(userObjId),
    providerId: "credential",
    issuer: "local:credential",
    password: hashedPassword,
    createdAt: now,
    updatedAt: now,
  });

  console.log(`✅ Stored credential with ObjectId reference in 'account' collection.`);

  const normalizedEmail = email.toLowerCase().trim();
  const conflictingAppAdmins = await db.collection("app_admins").find({ email: normalizedEmail }).toArray();
  if (conflictingAppAdmins.length > 0) {
    console.log(`\n⚠️ Notice: Email "${email}" is also registered as an App Admin in 'app_admins' for:`);
    conflictingAppAdmins.forEach((a: any) => console.log(`   - Client ID: ${a.clientId}`));
    console.log(`🛡️ Your Global Super Admin account (scopedClientId: null) is protected against demotion during cold starts.`);
    if (process.argv.includes("--clean-scoped")) {
      const del = await db.collection("app_admins").deleteMany({ email: normalizedEmail });
      console.log(`🧹 Removed ${del.deletedCount} conflicting record(s) from 'app_admins'.`);
    } else {
      console.log(`💡 Tip: Pass --clean-scoped if you wish to remove this email from 'app_admins'.`);
    }
  }

  console.log(`\n🎉 Success! Admin user is ready:`);
  console.log(`   Email: ${email}`);
  console.log(`   Role : admin`);
  console.log(`\nYou can now log in at: https://oauth21.vercel.app/admin/login\n`);

  await closeDb();
}

run().catch(async (e) => {
  console.error(e);
  await closeDb();
  process.exit(1);
});
