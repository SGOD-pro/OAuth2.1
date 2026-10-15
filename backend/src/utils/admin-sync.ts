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
  const isSuperAdmin = user && user.role === "admin" && user.scopedClientId === null;

  if (user) {
    userId = user._id instanceof ObjectId ? user._id : new ObjectId(String(user._id));

    // Never demote, alter password, or ban a Global Super Admin!
    if (!isSuperAdmin) {
      const userUpdate: any = {
        role: "admin",
        emailVerified: true,
        updatedAt: now,
      };

      // Only assign scopedClientId if user doesn't already have one or is already scoped to this client
      if (!user.scopedClientId || user.scopedClientId === clientId) {
        userUpdate.scopedClientId = clientId;
      }
      if (name) userUpdate.name = name;
      if (typeof isActive === "boolean") userUpdate.banned = !isActive;

      await database.collection("user").updateOne(
        { _id: user._id },
        { $set: userUpdate }
      );
    }
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
    const isSuperAdmin = user.role === "admin" && user.scopedClientId === null;

    // Delete membership for the specified clientId first
    await database.collection("user_app_registrations").deleteMany({
      clientId: clientId,
      $or: [{ userId: userIdStr }, { userId: user._id }],
    });

    if (!isSuperAdmin) {
      // Check if user still administers other applications via app_admins or user_app_registrations
      const adminQueryConditions: any[] = [];
      if (userEmail) adminQueryConditions.push({ email: userEmail });
      adminQueryConditions.push({ userId: userIdStr });
      if (user._id) adminQueryConditions.push({ userId: user._id });

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
        // User remains an admin for another client; update scopedClientId deterministically
        const sortedClients = Array.from(survivingClientIds).sort();
        const nextClientId = sortedClients[0];
        await database.collection("user").updateOne(
          { _id: user._id },
          { $set: { role: "admin", scopedClientId: nextClientId, updatedAt: new Date() } }
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
            previousRole: "admin",
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
