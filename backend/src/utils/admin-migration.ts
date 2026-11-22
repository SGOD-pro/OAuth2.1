import { ObjectId, Db } from "mongodb";
import { recordSyncAudit } from "./admin-sync-audit";
import {
  MigrateLegacyAppAdminsOptions,
  MigrationConflict,
  MigratedRecord,
  MigrationResult,
} from "./admin-migration-types";

export {
  type MigrateLegacyAppAdminsOptions,
  type MigrationConflict,
  type MigratedRecord,
  type MigrationResult,
};

async function recordConflict(
  database: Db,
  dryRun: boolean,
  targetClientId: string,
  targetUserId: string,
  details: Record<string, unknown>
): Promise<void> {
  if (!dryRun) {
    await recordSyncAudit(database, {
      action: "legacy_admin_migration_conflict",
      targetClientId,
      targetUserId,
      details,
      timestamp: new Date(),
    });
  }
}

/**
 * Explicit migration for legacy app_admins records lacking a stable userId.
 */
export async function migrateLegacyAppAdmins(
  database: Db,
  options: MigrateLegacyAppAdminsOptions = {},
): Promise<MigrationResult> {
  const dryRun = Boolean(options.dryRun);
  let migratedCount = 0;
  let conflictCount = 0;
  let skippedCount = 0;
  const conflicts: MigrationConflict[] = [];
  const migrated: MigratedRecord[] = [];

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
        conflicts.push({
          adminDocId: record._id?.toString() || "unknown",
          clientId: record.clientId || "unknown",
          email: record.email || "unknown",
          reason: "Missing email or clientId",
        });
        continue;
      }
      const normalizedEmail = record.email.toLowerCase().trim();
      const users = await database.collection("user").find({ email: normalizedEmail }).toArray();

      if (users.length !== 1) {
        conflictCount++;
        const reason = users.length === 0 ? "No user document found" : "Multiple ambiguous users found for email";
        const adminDocId = record._id?.toString() || "unknown";
        conflicts.push({ adminDocId, clientId: record.clientId, email: normalizedEmail, reason });
        await recordConflict(database, dryRun, record.clientId, "unresolved", {
          adminDocId, email: normalizedEmail, matchingUserCount: users.length, reason,
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
        const reason = "Cannot migrate super-admin identity to consumer app admin";
        const adminDocId = record._id?.toString() || "unknown";
        const targetUserId = (targetUser.id || targetUser._id)?.toString() || "unknown";
        conflicts.push({ adminDocId, clientId: record.clientId, email: normalizedEmail, reason });
        await recordConflict(database, dryRun, record.clientId, targetUserId, { adminDocId, email: normalizedEmail, reason });
        continue;
      }

      const stableUserId = (targetUser.id || targetUser._id)?.toString() || "";
      if (!stableUserId) {
        conflictCount++;
        conflicts.push({
          adminDocId: record._id?.toString() || "unknown",
          clientId: record.clientId,
          email: normalizedEmail,
          reason: "User document missing valid id",
        });
        continue;
      }

      // Check for potential email reuse: if user was created after the legacy record was established
      if (record.createdAt && targetUser.createdAt) {
        const recTime = new Date(record.createdAt).getTime();
        const userTime = new Date(targetUser.createdAt).getTime();
        if (!isNaN(recTime) && !isNaN(userTime) && userTime > recTime + 60_000) {
          conflictCount++;
          const reason = "Potential email reuse: user account created after legacy admin assignment";
          const adminDocId = record._id?.toString() || "unknown";
          conflicts.push({ adminDocId, clientId: record.clientId, email: normalizedEmail, reason });
          await recordConflict(database, dryRun, record.clientId, stableUserId, {
            adminDocId, email: normalizedEmail, reason, assignmentCreatedAt: record.createdAt, userCreatedAt: targetUser.createdAt,
          });
          continue;
        }
      }

      const isRecordRevoked =
        record.isActive === false ||
        record.active === false ||
        record.disabled === true ||
        record.revoked === true ||
        ["inactive", "revoked", "suspended", "disabled"].includes(record.status);

      const userConditions = [
        { userId: stableUserId },
        ...(ObjectId.isValid(stableUserId) ? [{ userId: new ObjectId(stableUserId) }] : []),
      ];

      // Check for duplicate record for the same client and userId
      const existingUserAdmin = await database.collection("app_admins").findOne({
        _id: { $ne: record._id },
        clientId: record.clientId,
        $or: userConditions,
      });

      if (existingUserAdmin) {
        const isExistingRevoked =
          existingUserAdmin.isActive === false ||
          existingUserAdmin.active === false ||
          existingUserAdmin.disabled === true ||
          existingUserAdmin.revoked === true ||
          ["inactive", "revoked", "suspended", "disabled"].includes(existingUserAdmin.status);

        if (!dryRun) {
          if (isRecordRevoked || isExistingRevoked) {
            await database.collection("app_admins").updateOne(
              { _id: existingUserAdmin._id },
              { $set: { isActive: false, revoked: true, status: "revoked", updatedAt: new Date() } }
            );
          }
          if (record._id) {
            if (typeof database.collection("app_admins").deleteOne === "function") {
              await database.collection("app_admins").deleteOne({ _id: record._id });
            } else {
              await database.collection("app_admins").deleteMany({ _id: record._id });
            }
          }
        }
        skippedCount++;
        continue;
      }

      // Check whether an explicit revocation exists in user_app_registrations
      const existingReg = await database.collection("user_app_registrations").findOne({
        clientId: record.clientId,
        $or: userConditions,
      });

      const isExistingRegRevoked =
        existingReg &&
        (existingReg.isActive === false ||
          existingReg.active === false ||
          existingReg.disabled === true ||
          existingReg.revoked === true ||
          ["inactive", "revoked", "suspended", "disabled"].includes(existingReg.status));

      if (isExistingRegRevoked && !isRecordRevoked) {
        conflictCount++;
        const reason = "Explicit revocation in user_app_registrations prevents automatic privilege elevation";
        const adminDocId = record._id?.toString() || "unknown";
        conflicts.push({ adminDocId, clientId: record.clientId, email: normalizedEmail, reason });
        await recordConflict(database, dryRun, record.clientId, stableUserId, { adminDocId, email: normalizedEmail, reason });
        continue;
      }

      if (dryRun) {
        migratedCount++;
        migrated.push({
          adminDocId: record._id?.toString() || "unknown",
          clientId: record.clientId,
          email: normalizedEmail,
          userId: stableUserId,
          status: isRecordRevoked ? "revoked" : "active",
        });
        continue;
      }

      // Apply migration
      if (record._id) {
        await database.collection("app_admins").updateOne(
          { _id: record._id },
          {
            $set: {
              userId: stableUserId,
              updatedAt: new Date(),
              ...(isRecordRevoked ? { isActive: false, revoked: true, status: record.status || "revoked" } : {}),
            },
          }
        );
      }

      if (isRecordRevoked) {
        await database.collection("user_app_registrations").deleteMany({
          clientId: record.clientId,
          $or: userConditions,
        });
      } else {
        await database.collection("user_app_registrations").updateOne(
          {
            clientId: record.clientId,
            $or: userConditions,
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
      migrated.push({
        adminDocId: record._id?.toString() || "unknown",
        clientId: record.clientId,
        email: normalizedEmail,
        userId: stableUserId,
        status: isRecordRevoked ? "revoked" : "active",
      });
      await recordSyncAudit(database, {
        action: "legacy_admin_migrated_to_user_id",
        targetClientId: record.clientId,
        targetUserId: stableUserId,
        details: {
          adminDocId: record._id?.toString() || "unknown",
          email: normalizedEmail,
          status: isRecordRevoked ? "revoked" : "active",
        },
        timestamp: new Date(),
      });
    }
  } catch (err: any) {
    console.warn("[LEGACY_ADMIN_MIGRATION] Error during migration:", err?.message || err);
  }

  return { migratedCount, conflictCount, skippedCount, conflicts, migrated };
}
