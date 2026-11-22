import { ObjectId } from "mongodb";
import { isSuperAdmin } from "./admin-roles";

export async function checkUserIsClientAdmin(
  database: any,
  userDoc: any,
  userIdStr: string,
  clientId: string
): Promise<boolean> {
  if (!database || !clientId || typeof clientId !== "string") return false;
  const cleanClientId = clientId.trim();
  if (!cleanClientId || cleanClientId.startsWith("$")) return false;

  const resolvedUserId = (typeof userIdStr === "string" ? userIdStr : (userDoc?.id || userDoc?._id)?.toString()) || "";
  if (!resolvedUserId || resolvedUserId.startsWith("$")) return false;

  let user = userDoc;
  if (!user && database) {
    const userQueries: any[] = [{ id: resolvedUserId }];
    if (ObjectId.isValid(resolvedUserId) && resolvedUserId.length === 24) {
      try {
        userQueries.push({ _id: new ObjectId(resolvedUserId) });
      } catch {}
    }
    user = await database.collection("user").findOne({ $or: userQueries });
  }

  // USER-REQUIRED POLICY: Super admins must never receive consumer app-admin privileges
  if (user && isSuperAdmin(user)) return false;

  const userConditions: any[] = [{ userId: resolvedUserId }];
  if (ObjectId.isValid(resolvedUserId) && resolvedUserId.length === 24) {
    try {
      userConditions.push({ userId: new ObjectId(resolvedUserId) });
    } catch {}
  }

  // Concurrent authoritative check across both app_admins and user_app_registrations
  const [adminRecords, regRecords] = await Promise.all([
    database.collection("app_admins").find({
      clientId: cleanClientId,
      $or: userConditions,
    }).toArray(),
    database.collection("user_app_registrations").find({
      clientId: cleanClientId,
      $or: userConditions,
    }).toArray(),
  ]);

  // Explicit revocation, suspension, or disabling in either source strictly takes precedence
  const hasRevokedAdmin = adminRecords.some((a: any) =>
    a.isActive === false ||
    a.active === false ||
    a.disabled === true ||
    a.revoked === true ||
    ["inactive", "revoked", "suspended", "disabled"].includes(a.status)
  );

  const hasRevokedReg = regRecords.some((r: any) =>
    r.isActive === false ||
    r.active === false ||
    r.disabled === true ||
    r.revoked === true ||
    ["inactive", "revoked", "suspended", "disabled"].includes(r.status) ||
    (r.appRole && r.appRole !== "admin")
  );

  if (hasRevokedAdmin || hasRevokedReg) {
    return false;
  }

  const hasActiveAdmin = adminRecords.some((a: any) =>
    a.isActive !== false &&
    a.active !== false &&
    !a.disabled &&
    !a.revoked &&
    !["inactive", "revoked", "suspended", "disabled"].includes(a.status)
  );

  const hasActiveReg = regRecords.some((r: any) =>
    r.appRole === "admin" &&
    r.isActive !== false &&
    r.active !== false &&
    !r.disabled &&
    !r.revoked &&
    !["inactive", "revoked", "suspended", "disabled"].includes(r.status)
  );

  if (hasActiveAdmin || hasActiveReg) {
    return true;
  }

  // Fail closed: runtime email matching without migration is strictly removed.
  // scopedClientId alone, legacy roles without assignment records,
  // or email matching a different user ID can NEVER grant admin privileges
  return false;
}
