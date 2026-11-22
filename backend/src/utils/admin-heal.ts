import { ObjectId, Db } from "mongodb";
import { syncAppAdminIdentity } from "./admin-sync";

/**
 * Self-healing sweep: scan all app_admins and ensure they are synced to user and account.
 */
export async function selfHealAppAdmins(database: Db): Promise<void> {
  try {
    const admins = await database.collection("app_admins").find({
      isActive: { $ne: false },
      active: { $ne: false },
      disabled: { $ne: true },
      revoked: { $ne: true },
      status: { $nin: ["inactive", "revoked", "suspended", "disabled"] },
    }).toArray();

    for (const a of admins) {
      if (!a.clientId) continue;

      const isRecordActive =
        a.isActive !== false &&
        a.active !== false &&
        a.disabled !== true &&
        a.revoked !== true &&
        !["inactive", "revoked", "suspended", "disabled"].includes(a.status);
      if (!isRecordActive) continue;

      const rawUserId = a.userId ? String(a.userId).trim() : "";
      if (!rawUserId) {
        continue;
      }

      const userConditions: any[] = [
        { id: rawUserId },
        ...(ObjectId.isValid(rawUserId) ? [{ _id: new ObjectId(rawUserId) }] : [{ _id: rawUserId }]),
      ];
      const targetUser = await database.collection("user").findOne({ $or: userConditions });

      if (!targetUser) {
        continue;
      }

      const isSuperAdmin = Boolean(
        targetUser.role === "super-admin" || (targetUser.role === "admin" && targetUser.scopedClientId === null)
      );
      if (isSuperAdmin) {
        continue;
      }

      const existingReg = await database.collection("user_app_registrations").findOne({
        clientId: a.clientId,
        $or: [
          { userId: rawUserId },
          ...(ObjectId.isValid(rawUserId) ? [{ userId: new ObjectId(rawUserId) }] : []),
        ],
      });
      const isRegRevoked =
        existingReg &&
        (existingReg.isActive === false ||
          existingReg.active === false ||
          existingReg.disabled === true ||
          existingReg.revoked === true ||
          ["inactive", "revoked", "suspended", "disabled"].includes(existingReg.status));

      if (isRegRevoked) {
        continue;
      }

      await syncAppAdminIdentity(database, {
        userId: rawUserId,
        email: targetUser.email || a.email,
        clientId: a.clientId,
        name: a.name || targetUser.name,
        hashedPassword: a.password,
        isActive: true,
        createdAt: a.createdAt,
      });
    }
  } catch (err: any) {
    console.warn("[APP_ADMIN_SELF_HEAL] Warning during background self-heal sweep:", err?.message || err);
  }
}
