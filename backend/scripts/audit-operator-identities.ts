import { MongoClient } from "mongodb";
import dotenv from "dotenv";

dotenv.config({ path: ".env" });

/**
 * Read-only Operator Identity & Role Audit Script
 *
 * Inspects all users and administrative assignments to verify
 * mutual exclusivity and strict tenant boundaries.
 * Changes nothing in the database.
 */
export function isSuperAdminDoc(user: any): boolean {
  if (!user) return false;
  if (user.role === "super-admin") {
    return user.scopedClientId === null || user.scopedClientId === undefined;
  }
  if (user.role === "admin" && user.scopedClientId === null) {
    return true;
  }
  return false;
}

export function isAppAdminDoc(user: any): boolean {
  if (!user) return false;
  if (isSuperAdminDoc(user)) return false;
  if (user.role === "app-admin") {
    if (typeof user.scopedClientId === "string") {
      return user.scopedClientId.trim().length > 0;
    }
    return true;
  }
  if (user.role === "admin" && typeof user.scopedClientId === "string" && user.scopedClientId.trim().length > 0) {
    return true;
  }
  return false;
}

export function evaluateIdentityAccount(u: any, allAssigned: string[]): string {
  const dbRole = u?.role || "user";
  const hasClientAssignments = allAssigned.length > 0;
  const hasScopeString = typeof u?.scopedClientId === "string" && u.scopedClientId.trim().length > 0;

  if (dbRole === "super-admin") {
    if (hasScopeString || hasClientAssignments) {
      const conflicts = [hasScopeString ? `scope=${u.scopedClientId}` : "", ...allAssigned].filter(Boolean);
      return `INVALID (Conflict: super-admin has client scope or assignments: ${conflicts.join(", ")})`;
    }
    return "VALID Super-Admin (Platform console only)";
  }

  if (dbRole === "app-admin") {
    if (u.scopedClientId === null && !hasClientAssignments) {
      return "INVALID (app-admin has no client scope or assigned applications)";
    }
    const targetScope = hasScopeString ? u.scopedClientId : allAssigned.join(", ");
    return `VALID App-Admin (Scoped to: ${targetScope})`;
  }

  if (dbRole === "admin") {
    if (u.scopedClientId === null) {
      if (hasClientAssignments) {
        return `INVALID (Conflict: legacy super-admin with explicit null scope has active app assignments: ${allAssigned.join(", ")})`;
      }
      return "VALID Legacy Super-Admin (Explicit null scope)";
    }
    if (hasScopeString) {
      return `VALID Legacy App-Admin (Scoped to: ${u.scopedClientId})`;
    }
    return "INVALID (Ambiguous legacy admin: missing or empty scope fails closed)";
  }

  if (hasClientAssignments || hasScopeString) {
    const details = [hasScopeString ? `scope=${u.scopedClientId}` : "", ...allAssigned].filter(Boolean);
    return `FLAGGED (Standard user has client scoping or registrations: ${details.join(", ")})`;
  }

  return "Standard User (No admin privileges)";
}

export async function auditIdentities(options?: { dbUri?: string; dbName?: string }) {
  console.log("================================================================");
  console.log("  SWYRA AUTH -- OPERATOR IDENTITIES & ROLES AUDIT (READ ONLY)");
  console.log("================================================================\n");

  const uri = options?.dbUri || process.env.MONGO_URI;
  if (!uri) {
    console.error("❌ Error: MONGO_URI is required to run identity audit.");
    return;
  }

  const client = new MongoClient(uri);
  await client.connect();
  const db = client.db(options?.dbName);

  try {
    const users = await db.collection("user").find({
      $or: [
        { role: { $in: ["super-admin", "admin", "app-admin"] } },
        { scopedClientId: { $exists: true, $ne: null } },
      ],
    }).toArray();

    const appAdmins = await db.collection("app_admins").find({}).toArray();
    const registrations = await db.collection("user_app_registrations").find({}).toArray();

    console.log(`Found ${users.length} administrative user record(s).\n`);

    for (const u of users) {
      const userId = (u.id || u._id)?.toString();
      const email = u.email || "N/A";
      const dbRole = u.role || "user";
      const dbScope = u.scopedClientId ?? "(null/unscoped)";

      const assignedApps = appAdmins
        .filter((a) => a.userId === userId || a.userId?.toString() === userId)
        .map((a) => a.clientId);

      const regApps = registrations
        .filter((r) => r.userId === userId || r.userId?.toString() === userId)
        .map((r) => r.clientId);

      const allAssigned = Array.from(new Set([...assignedApps, ...regApps]));
      const evaluation = evaluateIdentityAccount(u, allAssigned);

      console.log(`User: ${email} (ID: ${userId})`);
      console.log(`  Role in DB:          ${dbRole}`);
      console.log(`  Scope in DB:         ${dbScope}`);
      console.log(`  Active Memberships:  ${allAssigned.length > 0 ? allAssigned.join(", ") : "none"}`);
      console.log(`  Account Status:      disabled=${Boolean(u.disabled)}, banned=${Boolean(u.banned)}, active=${u.isActive !== false}`);
      console.log(`  Policy Evaluation:   ${evaluation}`);
      console.log("----------------------------------------------------------------");
    }

    console.log("\nAudit complete. No database records were modified.\n");
  } finally {
    await client.close();
  }
}

if (process.argv[1]?.endsWith("audit-operator-identities.ts")) {
  auditIdentities().catch((err) => {
    console.error("Audit failed:", err);
    process.exit(1);
  });
}
