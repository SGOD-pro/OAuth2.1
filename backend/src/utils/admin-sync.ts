import { ObjectId, Db } from "mongodb";
import { recordSyncAudit } from "./admin-sync-audit";

export interface SyncAppAdminParams {
  userId?: string;
  email: string;
  clientId: string;
  name?: string;
  hashedPassword?: string;
  isActive?: boolean;
  previousEmail?: string;
  createdAt?: Date;
}

export async function syncAppAdminIdentity(
  database: Db,
  params: SyncAppAdminParams
): Promise<{ userId: string } | null> {
  const { userId: explicitUserId, email, clientId, name, hashedPassword, isActive, previousEmail, createdAt } = params;
  if (!email || !clientId) return null;

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

  // 1. Resolve user by immutable userId (if provided) or by email (if initial creation)
  let user: any = null;
  let userId: ObjectId;

  if (explicitUserId) {
    const rawId = String(explicitUserId).trim();
    const userConditions: any[] = [
      { id: rawId },
      ...(ObjectId.isValid(rawId) ? [{ _id: new ObjectId(rawId) }] : [{ _id: rawId }]),
    ];
    user = await database.collection("user").findOne({ $or: userConditions });

    if (!user) {
      console.warn(`[ADMIN_SYNC] Identity mismatch: User with ID "${rawId}" does not exist. Refusing to bind assignment to a different user.`);
      return null;
    }
  } else {
    user = await database.collection("user").findOne({ email: normalizedEmail });
  }

  const isSuperAdmin = Boolean(
    user &&
    (user.role === "super-admin" || (user.role === "admin" && user.scopedClientId === null))
  );

  // USER-REQUIRED POLICY: Reject assigning an existing super-admin identity as an app admin
  if (isSuperAdmin) {
    console.warn(`[ADMIN_SYNC] Identity conflict: ${normalizedEmail} is a Global Super Admin. Skipped assignment as App Admin for client "${clientId}" (mutually exclusive roles).`);
    return null;
  }

  if (user) {
    userId = user._id instanceof ObjectId ? user._id : new ObjectId(String(user._id));
    const userIdStr = userId.toString();

    let isBanned = false;
    if (typeof isActive === "boolean") {
      if (!isActive) {
        const otherActive = await database.collection("app_admins").findOne({
          $or: [{ userId: userIdStr }, { email: normalizedEmail }, { _id: user._id }],
          clientId: { $ne: clientId },
          isActive: { $ne: false },
        });
        isBanned = !otherActive;
      } else {
        isBanned = false;
      }
    }

    const userUpdate: any = {
      role: "app-admin",
      emailVerified: true,
      updatedAt: now,
      banned: isBanned,
    };

    if (isActive !== false) {
      if (!user.scopedClientId || user.scopedClientId === clientId) {
        userUpdate.scopedClientId = clientId;
      }
    } else if (user.scopedClientId === clientId) {
      const otherActive = await database.collection("app_admins").findOne({
        $or: [{ userId: userIdStr }, { email: normalizedEmail }, { _id: user._id }],
        clientId: { $ne: clientId },
        isActive: { $ne: false },
      });
      userUpdate.scopedClientId = otherActive?.clientId || null;
    }

    if (name) userUpdate.name = name;

    await database.collection("user").updateOne(
      { _id: user._id },
      { $set: userUpdate }
    );
  } else {
    userId = new ObjectId();
    const newUserDoc = {
      _id: userId,
      name: name || "Administrator",
      email: normalizedEmail,
      emailVerified: true,
      role: "app-admin",
      banned: isActive === false,
      twoFactorEnabled: false,
      scopedClientId: clientId,
      createdAt: createdAt || now,
      updatedAt: now,
    };
    await database.collection("user").insertOne(newUserDoc);
  }

  const userIdStr = userId.toString();

  // 2. Upsert into account collection if hashedPassword provided AND not Super Admin
  if (hashedPassword && !isSuperAdmin) {
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

  // 3. Ensure explicit assignment in user_app_registrations for private client access with appRole: "admin"
  if (isActive === false) {
    await database.collection("user_app_registrations").deleteMany({
      clientId: clientId,
      $or: [{ userId: userIdStr }, { userId: userId }],
    });
  } else {
    const existingReg = await database.collection("user_app_registrations").findOne({
      clientId: clientId,
      $or: [{ userId: userIdStr }, { userId: userId }],
    });
    const isExistingRevoked =
      existingReg &&
      (existingReg.isActive === false ||
        existingReg.active === false ||
        existingReg.disabled === true ||
        existingReg.revoked === true ||
        ["inactive", "revoked", "suspended", "disabled"].includes(existingReg.status));

    if (isExistingRevoked) {
      console.warn(`[ADMIN_SYNC] Explicit revocation in user_app_registrations for user ${userIdStr} and client ${clientId} preserved; skipping reactivation.`);
      return null;
    }

    await database.collection("user_app_registrations").updateOne(
      {
        clientId: clientId,
        $or: [{ userId: userIdStr }, { userId: userId }],
      },
      {
        $set: {
          userId: userIdStr,
          clientId: clientId,
          appRole: "admin",
          registeredAt: createdAt || now,
        },
      },
      { upsert: true }
    );
  }

  await recordSyncAudit(database, {
    action: user ? "admin_identity_synced" : "admin_identity_created",
    targetClientId: clientId,
    targetUserId: userIdStr,
    details: {
      email: normalizedEmail,
      name: name || user?.name || "Administrator",
      scopedClientId: isSuperAdmin ? null : (user?.scopedClientId || clientId),
      isSuperAdmin: Boolean(isSuperAdmin),
    },
    timestamp: now,
  });

  return { userId: userIdStr };
}

// Re-export removal, audit, migration, and self-heal modules for seamless backwards compatibility
export { removeAppAdminIdentity } from "./admin-remove";
export { recordSyncAudit } from "./admin-sync-audit";
export {
  type MigrateLegacyAppAdminsOptions,
  type MigrationConflict,
  type MigratedRecord,
  type MigrationResult,
  migrateLegacyAppAdmins,
} from "./admin-migration";
export { selfHealAppAdmins } from "./admin-heal";
