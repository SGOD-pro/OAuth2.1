import { ObjectId, Db } from "mongodb";
import { recordSyncAudit } from "./admin-sync-audit";

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
