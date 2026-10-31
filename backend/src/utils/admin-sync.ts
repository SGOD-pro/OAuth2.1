import { ObjectId, Db } from "mongodb";

export interface SyncAppAdminParams {
  /**
   * Application administrator email. Required to key user upsert and Better Auth account synchronization.
   */
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
export async function recordSyncAudit(
  database: Db,
  entry: {
    action: string;
    targetClientId: string;
    targetUserId: string;
    details?: Record<string, unknown>;
    timestamp?: Date;
  }
): Promise<void> {
  try {
    await database.collection("admin_audit").insertOne({
      ...entry,
      timestamp: entry.timestamp || new Date(),
    });
  } catch (err: any) {
    console.warn("[ADMIN_SYNC_AUDIT] Failed to record admin audit entry:", err?.message || err);
  }
}

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
  const isSuperAdmin = Boolean(
    user &&
    (user.role === "super-admin" || (user.role === "admin" && user.scopedClientId === null))
  );

  // USER-REQUIRED POLICY: Reject assigning an existing super-admin identity as an app admin.
  // One identity cannot simultaneously be super-admin and app-admin.
  if (isSuperAdmin) {
    console.warn(`[ADMIN_SYNC] Identity conflict: ${normalizedEmail} is a Global Super Admin. Skipped assignment as App Admin for client "${clientId}" (mutually exclusive roles).`);
    return;
  }

  if (user) {
    userId = user._id instanceof ObjectId ? user._id : new ObjectId(String(user._id));
    const userIdStr = userId.toString();

    // USER-REQUIRED POLICY: Changing one app assignment must not ban or modify unrelated assignments.
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
}

/**
 * Remove an Application Administrator's scoping and membership.
 */
export async function removeAppAdminIdentity(
  database: Db,
  params: {
    email?: string;
    userId?: string | ObjectId;
    clientId: string;
  }
): Promise<void> {
  const { email, userId, clientId } = params;
  if ((!email && !userId) || !clientId) return;

  const normalizedEmail = email ? email.toLowerCase().trim() : undefined;
  const userQuery: any[] = [];
  if (normalizedEmail) userQuery.push({ email: normalizedEmail });
  if (userId) {
    userQuery.push({ _id: userId });
    userQuery.push({ id: userId.toString() });
    if (typeof userId === "string" && ObjectId.isValid(userId)) {
      userQuery.push({ _id: new ObjectId(userId) });
    }
  }

  const user = await database.collection("user").findOne({ $or: userQuery });

  if (user) {
    const userEmail = (user.email || normalizedEmail || "").toLowerCase().trim();
    const userIdStr = (user.id || user._id).toString();
    const isSuperAdmin = Boolean(
      user.role === "super-admin" ||
      (user.role === "admin" && user.scopedClientId === null)
    );

    // Delete membership for the specified clientId first
    await database.collection("user_app_registrations").deleteMany({
      clientId: clientId,
      $or: [{ userId: userIdStr }, { userId: user._id }],
    });

    if (!isSuperAdmin) {
      // Check if user still administers other applications via app_admins or user_app_registrations
      // Key authoritative checks by stable userId, including fallback to normalized email
      const adminQueryConditions: any[] = [];
      adminQueryConditions.push({ userId: userIdStr });
      if (user._id) adminQueryConditions.push({ userId: user._id });
      if (userEmail) adminQueryConditions.push({ email: userEmail });

      const otherAdmins = await database.collection("app_admins").find({
        $or: adminQueryConditions,
        clientId: { $ne: clientId },
        isActive: { $ne: false },
      }).sort({ clientId: 1 }).toArray();

      const regQueryConditions: any[] = [
        { userId: userIdStr },
        ...(user._id ? [{ userId: user._id }] : []),
      ];

      const otherRegistrations = await database.collection("user_app_registrations").find({
        $or: regQueryConditions,
        clientId: { $ne: clientId },
        appRole: "admin",
      }).sort({ clientId: 1 }).toArray();

      const survivingClientIds = new Set<string>();
      for (const a of otherAdmins) {
        if (a.clientId) survivingClientIds.add(a.clientId);
      }
      for (const r of otherRegistrations) {
        if (r.clientId) survivingClientIds.add(r.clientId);
      }

      if (survivingClientIds.size > 0) {
        // User remains an app admin for another client; update scopedClientId deterministically
        const sortedClients = Array.from(survivingClientIds).sort();
        const nextClientId = sortedClients[0];
        await database.collection("user").updateOne(
          { _id: user._id },
          { $set: { role: "app-admin", scopedClientId: nextClientId, updatedAt: new Date() } }
        );
        await recordSyncAudit(database, {
          action: "admin_identity_repointed",
          targetClientId: nextClientId,
          targetUserId: userIdStr,
          details: {
            removedClientId: clientId,
            newScopedClientId: nextClientId,
            email: userEmail,
            remainingClientIds: sortedClients,
          },
          timestamp: new Date(),
        });
      } else {
        // Zero remaining admin assignments: demote back to standard user
        await database.collection("user").updateOne(
          { _id: user._id },
          { $set: { role: "user", scopedClientId: null, updatedAt: new Date() } }
        );
        await recordSyncAudit(database, {
          action: "admin_identity_demoted",
          targetClientId: clientId,
          targetUserId: userIdStr,
          details: {
            removedClientId: clientId,
            previousRole: user.role,
            newRole: "user",
            email: userEmail,
          },
          timestamp: new Date(),
        });
      }
    }
  }
}

/**
 * Explicit migration for legacy app_admins records lacking a stable userId.
 *
 * Rules:
 * 1. An email-only record is migrated ONLY if exactly one user matches that email.
 * 2. If zero or multiple users match that email, or the user is a super-admin, reject as conflict.
 * 3. Never grant privileges to a different userId just because the email matches.
 */
export async function migrateLegacyAppAdmins(
  database: Db,
): Promise<{ migratedCount: number; conflictCount: number }> {
  let migratedCount = 0;
  let conflictCount = 0;
  try {
    const legacyRecords = await database.collection("app_admins").find({
      $or: [
        { userId: { $exists: false } },
        { userId: null },
        { userId: "" },
      ],
    }).toArray();

    for (const record of legacyRecords) {
      if (!record.email || !record.clientId) {
        conflictCount++;
        continue;
      }
      const normalizedEmail = record.email.toLowerCase().trim();
      const users = await database.collection("user").find({ email: normalizedEmail }).toArray();

      if (users.length !== 1) {
        conflictCount++;
        await recordSyncAudit(database, {
          action: "legacy_admin_migration_conflict",
          targetClientId: record.clientId,
          targetUserId: "unresolved",
          details: {
            adminDocId: record._id?.toString() || "unknown",
            email: normalizedEmail,
            matchingUserCount: users.length,
            reason: users.length === 0 ? "No user document found" : "Multiple ambiguous users found for email",
          },
          timestamp: new Date(),
        });
        continue;
      }

      const targetUser = users[0];
      const isSuperAdmin = Boolean(
        targetUser.role === "super-admin" ||
        (targetUser.role === "admin" && targetUser.scopedClientId === null)
      );

      if (isSuperAdmin) {
        conflictCount++;
        await recordSyncAudit(database, {
          action: "legacy_admin_migration_conflict",
          targetClientId: record.clientId,
          targetUserId: (targetUser.id || targetUser._id)?.toString() || "unknown",
          details: {
            adminDocId: record._id?.toString() || "unknown",
            email: normalizedEmail,
            reason: "Cannot migrate super-admin identity to consumer app admin",
          },
          timestamp: new Date(),
        });
        continue;
      }

      const stableUserId = (targetUser.id || targetUser._id)?.toString() || "";
      if (!stableUserId) {
        conflictCount++;
        continue;
      }

      // Check for duplicate record for the same client and userId
      const existingUserAdmin = await database.collection("app_admins").findOne({
        _id: { $ne: record._id },
        clientId: record.clientId,
        $or: [{ userId: stableUserId }, ...(ObjectId.isValid(stableUserId) ? [{ userId: new ObjectId(stableUserId) }] : [])],
      });

      if (existingUserAdmin) {
        if (record._id) {
          if (typeof database.collection("app_admins").deleteOne === "function") {
            await database.collection("app_admins").deleteOne({ _id: record._id });
          } else {
            await database.collection("app_admins").deleteMany({ _id: record._id });
          }
        }
        continue;
      }

      if (record._id) {
        await database.collection("app_admins").updateOne(
          { _id: record._id },
          {
            $set: {
              userId: stableUserId,
              updatedAt: new Date(),
            },
          }
        );
      }

      if (record.isActive !== false && !["inactive", "revoked", "suspended", "disabled"].includes(record.status)) {
        await database.collection("user_app_registrations").updateOne(
          {
            clientId: record.clientId,
            $or: [{ userId: stableUserId }, ...(ObjectId.isValid(stableUserId) ? [{ userId: new ObjectId(stableUserId) }] : [])],
          },
          {
            $set: {
              userId: stableUserId,
              clientId: record.clientId,
              appRole: "admin",
              status: "active",
              registeredAt: record.createdAt || new Date(),
            },
          },
          { upsert: true }
        );
      }

      migratedCount++;
      await recordSyncAudit(database, {
        action: "legacy_admin_migrated_to_user_id",
        targetClientId: record.clientId,
        targetUserId: stableUserId,
        details: {
          adminDocId: record._id?.toString() || "unknown",
          email: normalizedEmail,
        },
        timestamp: new Date(),
      });
    }
  } catch (err: any) {
    console.warn("[LEGACY_ADMIN_MIGRATION] Error during migration:", err?.message || err);
  }

  return { migratedCount, conflictCount };
}

/**
 * Self-healing sweep: scan all app_admins and ensure they are synced to user and account.
 */
export async function selfHealAppAdmins(database: Db): Promise<void> {
  try {
    // 1. Explicitly migrate any legacy email-only records to stable user IDs
    await migrateLegacyAppAdmins(database);

    // 2. Only self-heal active app_admins records; deactivated or deleted assignments must not be resurrected
    const admins = await database.collection("app_admins").find({
      isActive: { $ne: false },
      active: { $ne: false },
      disabled: { $ne: true },
      revoked: { $ne: true },
      status: { $nin: ["inactive", "revoked", "suspended", "disabled"] },
    }).toArray();
    for (const a of admins) {
      if (!a.email || !a.clientId) continue;
      const isRecordActive =
        a.isActive !== false &&
        a.active !== false &&
        a.disabled !== true &&
        a.revoked !== true &&
        !["inactive", "revoked", "suspended", "disabled"].includes(a.status);
      if (!isRecordActive) continue;

      await syncAppAdminIdentity(database, {
        email: a.email,
        clientId: a.clientId,
        name: a.name,
        hashedPassword: a.password,
        isActive: true,
        createdAt: a.createdAt,
      });
    }
  } catch (err: any) {
    console.warn("[APP_ADMIN_SELF_HEAL] Warning during background self-heal sweep:", err?.message || err);
  }
}
