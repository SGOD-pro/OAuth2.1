import { ObjectId, Db } from "mongodb";

export interface SyncAppAdminParams {
  email: string;
  clientId: string;
  name?: string;
  hashedPassword?: string;
  isActive?: boolean;
  previousEmail?: string;
  createdAt?: Date;
}

/**
 * Synchronize an Application Administrator's identity into Better Auth's
 * centralized `user` and `account` collections, as well as `user_app_registrations`.
 *
 * Guarantees:
 * 1. The admin exists in `user` with role: "admin", scopedClientId: canonicalClientId.
 * 2. If password/hash is provided, the admin has a credential account in `account` with the hashed password.
 * 3. The admin has explicit membership in `user_app_registrations` for private app access.
 * 4. Password updates, name changes, email updates, and active/inactive state sync cleanly.
 */
export async function syncAppAdminIdentity(
  database: Db,
  params: SyncAppAdminParams
): Promise<void> {
  const { email, clientId, name, hashedPassword, isActive, previousEmail, createdAt } = params;
  if (!email || !clientId) return;

  const normalizedEmail = email.toLowerCase().trim();
  const now = new Date();

  // If email was changed, update existing user doc if it was scoped to this client
  if (previousEmail && previousEmail.toLowerCase().trim() !== normalizedEmail) {
    const prevNormalized = previousEmail.toLowerCase().trim();
    await database.collection("user").updateOne(
      { email: prevNormalized, scopedClientId: clientId },
      { $set: { email: normalizedEmail, updatedAt: now } }
    );
  }

  // 1. Upsert into user collection
  let user = await database.collection("user").findOne({ email: normalizedEmail });
  let userId: ObjectId;

  if (user) {
    userId = user._id;
    const userUpdate: any = {
      role: "admin",
      scopedClientId: clientId,
      emailVerified: true,
      updatedAt: now,
    };
    if (name) userUpdate.name = name;
    if (typeof isActive === "boolean") userUpdate.banned = !isActive;

    await database.collection("user").updateOne(
      { _id: userId },
      { $set: userUpdate }
    );
  } else {
    userId = new ObjectId();
    const newUserDoc = {
      _id: userId,
      name: name || "Administrator",
      email: normalizedEmail,
      emailVerified: true,
      role: "admin",
      banned: isActive === false,
      twoFactorEnabled: false,
      scopedClientId: clientId,
      createdAt: createdAt || now,
      updatedAt: now,
    };
    await database.collection("user").insertOne(newUserDoc);
  }

  const userIdStr = userId.toString();

  // 2. Upsert into account collection if hashedPassword provided
  if (hashedPassword) {
    const existingAccount = await database.collection("account").findOne({
      $or: [
        { userId: userId },
        { userId: userIdStr },
        { accountId: userIdStr },
        { accountId: normalizedEmail },
      ],
      providerId: "credential",
    });

    if (existingAccount) {
      await database.collection("account").updateOne(
        { _id: existingAccount._id },
        {
          $set: {
            password: hashedPassword,
            updatedAt: now,
          },
        }
      );
    } else {
      await database.collection("account").insertOne({
        _id: new ObjectId(),
        userId: userId,
        accountId: userIdStr,
        providerId: "credential",
        issuer: "local:credential",
        password: hashedPassword,
        createdAt: createdAt || now,
        updatedAt: now,
      });
    }
  }

  // 3. Ensure explicit assignment in user_app_registrations for private client access
  const existingReg = await database.collection("user_app_registrations").findOne({
    clientId: clientId,
    $or: [{ userId: userIdStr }, { userId: userId }],
  });

  if (!existingReg) {
    await database.collection("user_app_registrations").insertOne({
      userId: userIdStr,
      clientId: clientId,
      registeredAt: createdAt || now,
    });
  }
}

/**
 * Remove an Application Administrator's scoping and membership.
 */
export async function removeAppAdminIdentity(
  database: Db,
  params: {
    email: string;
    clientId: string;
  }
): Promise<void> {
  const { email, clientId } = params;
  if (!email || !clientId) return;

  const normalizedEmail = email.toLowerCase().trim();
  const user = await database.collection("user").findOne({ email: normalizedEmail });

  if (user) {
    const userIdStr = (user.id || user._id).toString();
    if (user.scopedClientId === clientId) {
      await database.collection("user").updateOne(
        { _id: user._id },
        { $set: { role: "user", scopedClientId: null, updatedAt: new Date() } }
      );
    }
    await database.collection("user_app_registrations").deleteMany({
      clientId: clientId,
      $or: [{ userId: userIdStr }, { userId: user._id }],
    });
  }
}

/**
 * Self-healing sweep: scan all app_admins and ensure they are synced to user and account.
 */
export async function selfHealAppAdmins(database: Db): Promise<void> {
  try {
    const admins = await database.collection("app_admins").find({}).toArray();
    for (const a of admins) {
      if (!a.email || !a.clientId) continue;
      await syncAppAdminIdentity(database, {
        email: a.email,
        clientId: a.clientId,
        name: a.name,
        hashedPassword: a.password,
        isActive: a.isActive !== false,
        createdAt: a.createdAt,
      });
    }
  } catch (err: any) {
    console.warn("[APP_ADMIN_SELF_HEAL] Warning during background self-heal sweep:", err?.message || err);
  }
}
