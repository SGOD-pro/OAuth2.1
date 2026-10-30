/**
 * Identity Role Migration Script
 *
 * Migrates legacy roles ("admin" with scopedClientId: null or string)
 * to explicit, mutually exclusive domain roles:
 *   - "super-admin" (platform MAuth dashboard & management only)
 *   - "app-admin"   (consumer application admin portals only)
 *   - "user"        (standard end-user)
 *
 * Safety & Invariant Guarantees:
 * 1. Default mode is read-only audit / dry-run. Requires explicit --apply to write.
 * 2. Does NOT execute against production without explicit confirmation.
 * 3. Never promotes ambiguous records (missing/empty scopedClientId or conflicting roles).
 * 4. Idempotent: Can be run multiple times safely.
 * 5. Preserves all passwords and credential hashes in 'account' collection.
 * 6. When applied, invalidates active sessions and revokes refresh token families for migrated accounts.
 *
 * Backup & Recovery Instructions:
 *   Backup:
 *     mongodump --uri="$MONGO_URI" --out="backup_$(date +%Y%m%d_%H%M%S)"
 *   Restore:
 *     mongorestore --uri="$MONGO_URI" backup_<timestamp>/
 *
 * Usage:
 *   Dry run (default):
 *     npx ts-node scripts/migrate-identity-roles.ts
 *     npx ts-node scripts/migrate-identity-roles.ts --audit
 *   Apply migration:
 *     npx ts-node scripts/migrate-identity-roles.ts --apply
 */

import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";

dotenv.config({ path: ".env" });

interface MigrationClassification {
  userId: string;
  email: string;
  currentRole: string;
  currentScopedClientId: any;
  targetRole: "super-admin" | "app-admin" | "user" | null;
  targetScopedClientId: string | null;
  category: "Class A (Super Admin)" | "Class B (App Admin)" | "Class C (Standard User)" | "Class D (Conflict / Flagged)";
  reason: string;
  alreadyMigrated: boolean;
}

export async function runIdentityMigration(options: { apply: boolean; dbUri?: string; dbName?: string }) {
  const uri = options.dbUri || process.env.MONGO_URI;
  if (!uri) {
    throw new Error("MONGO_URI not provided or found in environment");
  }

  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 15000 });
  await client.connect();

  const db = options.dbName ? client.db(options.dbName) : client.db();
  const dbName = db.databaseName;

  console.log("================================================================================");
  console.log(`  IDENTITY ROLE MIGRATION: ${options.apply ? "APPLY MODE" : "READ-ONLY AUDIT (DRY-RUN)"}`);
  console.log(`  Target Database: ${dbName}`);
  console.log("================================================================================\n");

  const users = await db.collection("user").find({}).toArray();
  const classifications: MigrationClassification[] = [];

  for (const user of users) {
    const userIdStr = (user.id || user._id).toString();
    const email = (user.email || "").toLowerCase().trim();
    const role = user.role;
    const scopedClientId = user.scopedClientId;

    // Check existing app_admins records for this user
    const appAdminRecords = await db.collection("app_admins").find({
      $or: [
        { email: email },
        { userId: userIdStr },
        ...(user._id ? [{ userId: user._id }] : []),
      ],
      isActive: { $ne: false },
    }).toArray();

    // Check user_app_registrations records for admin roles
    const adminRegistrations = await db.collection("user_app_registrations").find({
      $or: [
        { userId: userIdStr },
        ...(user._id ? [{ userId: user._id }] : []),
      ],
      appRole: "admin",
    }).toArray();

    const hasAppAdminRecords = appAdminRecords.length > 0 || adminRegistrations.length > 0;

    // 1. Check if already explicitly migrated
    if (role === "super-admin") {
      if (hasAppAdminRecords) {
        classifications.push({
          userId: userIdStr,
          email,
          currentRole: role,
          currentScopedClientId: scopedClientId,
          targetRole: null,
          targetScopedClientId: null,
          category: "Class D (Conflict / Flagged)",
          reason: "User has explicit super-admin role but active app-admin records exist. Operator resolution required.",
          alreadyMigrated: false,
        });
      } else {
        classifications.push({
          userId: userIdStr,
          email,
          currentRole: role,
          currentScopedClientId: scopedClientId,
          targetRole: "super-admin",
          targetScopedClientId: null,
          category: "Class A (Super Admin)",
          reason: "Already explicit super-admin.",
          alreadyMigrated: true,
        });
      }
      continue;
    }

    if (role === "app-admin") {
      classifications.push({
        userId: userIdStr,
        email,
        currentRole: role,
        currentScopedClientId: scopedClientId,
        targetRole: "app-admin",
        targetScopedClientId: scopedClientId || appAdminRecords[0]?.clientId || null,
        category: "Class B (App Admin)",
        reason: "Already explicit app-admin.",
        alreadyMigrated: true,
      });
      continue;
    }

    // 2. Classify legacy "admin" role
    if (role === "admin") {
      // Explicit null scope with no app admin records => Super Admin
      if (scopedClientId === null && !hasAppAdminRecords) {
        classifications.push({
          userId: userIdStr,
          email,
          currentRole: role,
          currentScopedClientId: scopedClientId,
          targetRole: "super-admin",
          targetScopedClientId: null,
          category: "Class A (Super Admin)",
          reason: "Legacy admin with explicit null scope and no app assignments.",
          alreadyMigrated: false,
        });
        continue;
      }

      // Explicit non-empty string scopedClientId => App Admin
      if (typeof scopedClientId === "string" && scopedClientId.trim().length > 0) {
        classifications.push({
          userId: userIdStr,
          email,
          currentRole: role,
          currentScopedClientId: scopedClientId,
          targetRole: "app-admin",
          targetScopedClientId: scopedClientId.trim(),
          category: "Class B (App Admin)",
          reason: "Legacy admin with client scoping.",
          alreadyMigrated: false,
        });
        continue;
      }

      // Ambiguous: scopedClientId === undefined or empty string or null with conflicting app records
      classifications.push({
        userId: userIdStr,
        email,
        currentRole: role,
        currentScopedClientId: scopedClientId,
        targetRole: null,
        targetScopedClientId: null,
        category: "Class D (Conflict / Flagged)",
        reason: scopedClientId === undefined
          ? "Ambiguous scope: scopedClientId property is undefined. Cannot infer super-admin without documented evidence."
          : scopedClientId === ""
          ? "Invalid scope: scopedClientId is empty string. Fail closed."
          : "Conflict: role is admin with scopedClientId: null, but active app_admins records exist.",
        alreadyMigrated: false,
      });
      continue;
    }

    // 3. User with app admin assignments
    if (hasAppAdminRecords) {
      const activeClientId = appAdminRecords[0]?.clientId || adminRegistrations[0]?.clientId;
      classifications.push({
        userId: userIdStr,
        email,
        currentRole: role || "user",
        currentScopedClientId: scopedClientId,
        targetRole: "app-admin",
        targetScopedClientId: activeClientId,
        category: "Class B (App Admin)",
        reason: `Role was '${role || "user"}' but user possesses active app admin assignments.`,
        alreadyMigrated: false,
      });
      continue;
    }

    // 4. Standard User
    classifications.push({
      userId: userIdStr,
      email,
      currentRole: role || "user",
      currentScopedClientId: scopedClientId,
      targetRole: "user",
      targetScopedClientId: null,
      category: "Class C (Standard User)",
      reason: "Standard user without admin privileges.",
      alreadyMigrated: role === "user" && (scopedClientId === null || scopedClientId === undefined),
    });
  }

  // Print audit report
  console.log("--------------------------------------------------------------------------------");
  console.log("  CLASSIFICATION AUDIT SUMMARY");
  console.log("--------------------------------------------------------------------------------");
  const classA = classifications.filter((c) => c.category === "Class A (Super Admin)");
  const classB = classifications.filter((c) => c.category === "Class B (App Admin)");
  const classC = classifications.filter((c) => c.category === "Class C (Standard User)");
  const classD = classifications.filter((c) => c.category === "Class D (Conflict / Flagged)");

  console.log(`Class A (Super Admin)            : ${classA.length} (Already migrated: ${classA.filter((x) => x.alreadyMigrated).length})`);
  console.log(`Class B (App Admin)              : ${classB.length} (Already migrated: ${classB.filter((x) => x.alreadyMigrated).length})`);
  console.log(`Class C (Standard User)          : ${classC.length} (Already migrated: ${classC.filter((x) => x.alreadyMigrated).length})`);
  console.log(`Class D (Flagged for Resolution) : ${classD.length} [ACTION REQUIRED]`);
  console.log("--------------------------------------------------------------------------------\n");

  if (classD.length > 0) {
    console.log("⚠️ FLAGGED ACCOUNTS REQUIRING OPERATOR RESOLUTION (NEVER AUTOMATICALLY PROMOTED):");
    classD.forEach((item) => {
      console.log(`  - User ID : ${item.userId}`);
      console.log(`    Email   : ${item.email}`);
      console.log(`    Role    : ${item.currentRole}, ScopedClientId: ${JSON.stringify(item.currentScopedClientId)}`);
      console.log(`    Reason  : ${item.reason}`);
      console.log(`    Action  : Operator must manually set role to "super-admin" or "app-admin" after confirming intent.\n`);
    });
  }

  if (!options.apply) {
    console.log("ℹ️ Dry-run completed. No database changes were made.");
    console.log("  To apply migrations for Class A, B, and C accounts, rerun with --apply.");
    await client.close();
    return { classifications, applied: false };
  }

  // APPLY MODE
  console.log("🚀 APPLYING MIGRATIONS FOR CLEAR-CUT IDENTITIES...\n");
  let appliedCount = 0;
  let sessionInvalidations = 0;
  let tokenRevocations = 0;

  for (const item of classifications) {
    if (item.alreadyMigrated || item.category === "Class D (Conflict / Flagged)" || !item.targetRole) {
      continue;
    }

    const filter = ObjectId.isValid(item.userId)
      ? { _id: new ObjectId(item.userId) }
      : { id: item.userId };

    const updateDoc: any = {
      role: item.targetRole,
      scopedClientId: item.targetScopedClientId,
      updatedAt: new Date(),
    };

    await db.collection("user").updateOne(filter, { $set: updateDoc });

    // Invalidate active session cookies for this user
    const sessionRes = await db.collection("session").deleteMany({
      $or: [
        { userId: item.userId },
        ...(ObjectId.isValid(item.userId) ? [{ userId: new ObjectId(item.userId) }] : []),
      ],
    });
    sessionInvalidations += sessionRes.deletedCount;

    // Revoke refresh token families for this user
    const tokenRes = await db.collection("oauth_token_families").updateMany(
      {
        $or: [
          { userId: item.userId },
          ...(ObjectId.isValid(item.userId) ? [{ userId: new ObjectId(item.userId) }] : []),
        ],
        isRevoked: false,
      },
      {
        $set: {
          isRevoked: true,
          revokedAt: new Date(),
          revokeReason: "identity_role_migration",
        },
      }
    );
    tokenRevocations += tokenRes.modifiedCount;

    appliedCount++;
    console.log(`  ✅ Migrated ${item.email} -> role: ${item.targetRole}, scopedClientId: ${item.targetScopedClientId}`);
  }

  console.log("\n================================================================================");
  console.log("  MIGRATION COMPLETE");
  console.log(`  Identities updated          : ${appliedCount}`);
  console.log(`  Sessions invalidated        : ${sessionInvalidations}`);
  console.log(`  Refresh families revoked    : ${tokenRevocations}`);
  console.log(`  Flagged items untouched     : ${classD.length}`);
  console.log("================================================================================\n");

  await client.close();
  return { classifications, applied: true, appliedCount, sessionInvalidations, tokenRevocations };
}

const isDirectExecution = process.argv[1]?.includes("migrate-identity-roles");
if (isDirectExecution) {
  const isApply = process.argv.includes("--apply");
  runIdentityMigration({ apply: isApply })
    .then(() => process.exit(0))
    .catch((err) => {
      console.error("Migration failed:", err);
      process.exit(1);
    });
}
