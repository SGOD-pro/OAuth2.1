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
    console.log(`\nℹ️ Found existing user record for "${email}". Updating role to super-admin...`);
    userObjId = user._id instanceof ObjectId ? user._id : new ObjectId(String(user._id));

    await db.collection("user").updateOne(
      { _id: user._id },
      {
        $set: {
          role: "super-admin",
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
      role: "super-admin",
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
    console.log(`\n⚠️ Notice: Email "${email}" was registered as an App Admin in 'app_admins' for:`);
    conflictingAppAdmins.forEach((a: any) => console.log(`   - Client ID: ${a.clientId}`));
    console.log(`🛡️ Mutually exclusive role policy: Removing conflicting app-admin records for Global Super Admin.`);
    const delAdmins = await db.collection("app_admins").deleteMany({ email: normalizedEmail });
    const delRegs = await db.collection("user_app_registrations").deleteMany({
      $or: [{ userId: String(userObjId) }, { userId: userObjId }],
      appRole: "admin",
    });
    console.log(`🧹 Cleaned ${delAdmins.deletedCount} app_admins and ${delRegs.deletedCount} admin registration record(s).`);
  }

  console.log(`\n🎉 Success! Global Super Admin user is ready:`);
  console.log(`   Email: ${email}`);
  console.log(`   Role : super-admin`);
  console.log(`\nYou can now log in at: https://oauth21.vercel.app/admin/login\n`);

  await closeDb();
}

run().catch(async (e) => {
  console.error(e);
  await closeDb();
  process.exit(1);
});
