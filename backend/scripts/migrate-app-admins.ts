import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";

dotenv.config({ path: ".env" });

async function syncDb(dbName: string) {
  const uri = process.env.MONGO_URI;
  if (!uri) {
    console.error("MONGO_URI not found");
    process.exit(1);
  }

  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 30000 });
  await client.connect();
  const db = client.db(dbName);
  console.log(`\n========================================`);
  console.log(`  Syncing App Admins in database: ${dbName}`);
  console.log(`========================================`);

  const admins = await db.collection("app_admins").find({}).toArray();
  console.log(`Found ${admins.length} documents in app_admins`);

  let syncedCount = 0;

  for (const admin of admins) {
    if (!admin.email || !admin.clientId) {
      console.log(`Skipping invalid admin doc: ${admin._id} (missing email or clientId)`);
      continue;
    }

    const email = admin.email.toLowerCase().trim();
    const name = admin.name || "Administrator";
    const clientId = admin.clientId;
    const hashedPassword = admin.password;
    const isActive = admin.isActive !== false;
    const now = new Date();

    console.log(`Processing admin: ${email} for client: ${clientId}`);

    // 1. Upsert into user collection
    let user = await db.collection("user").findOne({ email });
    let userId: ObjectId;
    const isSuperAdmin = user && user.role === "admin" && user.scopedClientId === null;

    if (user) {
      userId = user._id;
      if (!isSuperAdmin) {
        const updateDoc: any = {
          name: name || user.name || "Administrator",
          role: "admin",
          emailVerified: true,
          banned: !isActive,
          updatedAt: now,
        };
        if (!user.scopedClientId || user.scopedClientId === clientId) {
          updateDoc.scopedClientId = clientId;
        }
        await db.collection("user").updateOne(
          { _id: userId },
          { $set: updateDoc }
        );
        console.log(`  -> Updated existing user (${userId.toString()}) to role: admin, scopedClientId: ${updateDoc.scopedClientId || user.scopedClientId}`);
      } else {
        console.log(`  🛡️ Preserved Global Super Admin (${userId.toString()}): skipped mutating scopedClientId, password, and banned.`);
      }
    } else {
      userId = new ObjectId();
      const newUserDoc = {
        _id: userId,
        name: name,
        email: email,
        emailVerified: true,
        role: "admin",
        banned: !isActive,
        twoFactorEnabled: false,
        scopedClientId: clientId,
        createdAt: admin.createdAt || now,
        updatedAt: now,
      };
      await db.collection("user").insertOne(newUserDoc);
      console.log(`  -> Created new user doc (${userId.toString()})`);
    }

    const userIdStr = userId.toString();

    // 2. Upsert into account collection if not Super Admin
    if (hashedPassword && !isSuperAdmin) {
      const existingAccount = await db.collection("account").findOne({
        $or: [
          { userId: userId },
          { userId: userIdStr },
          { accountId: userIdStr },
          { accountId: email },
        ],
        providerId: "credential",
      });

      if (existingAccount) {
        await db.collection("account").updateOne(
          { _id: existingAccount._id },
          {
            $set: {
              password: hashedPassword,
              updatedAt: now,
            },
          }
        );
        console.log(`  -> Updated credential password in existing account doc (${existingAccount._id.toString()})`);
      } else {
        const newAccountDoc = {
          _id: new ObjectId(),
          userId: userId,
          accountId: userIdStr,
          providerId: "credential",
          issuer: "local:credential",
          password: hashedPassword,
          createdAt: admin.createdAt || now,
          updatedAt: now,
        };
        await db.collection("account").insertOne(newAccountDoc);
        console.log(`  -> Created new credential account doc with hashed password`);
      }
    }

    // 3. Ensure membership in user_app_registrations with appRole: "admin"
    await db.collection("user_app_registrations").updateOne(
      {
        clientId: clientId,
        $or: [{ userId: userIdStr }, { userId: userId }],
      },
      {
        $set: {
          userId: userIdStr,
          clientId: clientId,
          appRole: "admin",
          registeredAt: admin.createdAt || now,
        },
      },
      { upsert: true }
    );
    console.log(`  -> Ensured user_app_registrations membership for client ${clientId} with appRole: admin`);

    syncedCount++;
  }

  console.log(`\nSuccessfully synced ${syncedCount} app admin(s) in ${dbName}.`);
  await client.close();
}

async function main() {
  await syncDb("oauthservice");
  await syncDb("oauthservice-dev");
}

main().catch((err) => {
  console.error("Migration failed:", err);
  process.exit(1);
});
