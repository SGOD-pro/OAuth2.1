import { ObjectId } from "mongodb";

/**
 * Check whether a user is registered for an application in user_app_registrations.
 * Uses authenticated server-side userId and canonical client ID.
 */
export async function checkUserAppRegistration(
  db: any,
  userId: string,
  canonicalClientId: string,
): Promise<boolean> {
  if (!userId || !canonicalClientId) return false;
  if (typeof userId !== "string" || typeof canonicalClientId !== "string") return false;
  const cleanUserId = userId.trim();
  const cleanClientId = canonicalClientId.trim();
  if (!cleanUserId || !cleanClientId || cleanUserId.startsWith("$") || cleanClientId.startsWith("$")) {
    return false;
  }

  const userConditions: any[] = [
    { userId: cleanUserId },
  ];
  if (ObjectId.isValid(cleanUserId) && cleanUserId.length === 24) {
    try {
      userConditions.push({ userId: new ObjectId(cleanUserId) });
    } catch {}
  }

  const reg = await db.collection("user_app_registrations").findOne({
    clientId: cleanClientId,
    $or: userConditions,
    status: { $nin: ["inactive", "revoked", "suspended", "disabled"] },
    revoked: { $ne: true },
    disabled: { $ne: true },
    isActive: { $ne: false },
    active: { $ne: false },
  });

  return Boolean(reg);
}

/**
 * Authoritative check for user access to an application.
 *
 * Rules:
 * 1. Super Admin has NO bypass or membership in consumer applications.
 * 2. Explicit revocation/suspension/deactivation in EITHER user_app_registrations
 *    OR app_admins strictly and immediately denies access.
 * 3. Active registration in user_app_registrations grants access.
 * 4. Active administrator record in app_admins grants access.
 * 5. A removed, revoked, or non-existent assignment CANNOT regain access
 *    through user.scopedClientId or cached claims.
 */
export async function checkUserHasAppAccess(
  db: any,
  userOrId: any,
  canonicalClientId: string,
): Promise<boolean> {
  if (!db || !userOrId || !canonicalClientId) return false;
  const cleanClientId = typeof canonicalClientId === "string" ? canonicalClientId.trim() : "";
  if (!cleanClientId || cleanClientId.startsWith("$")) return false;

  const userDoc = typeof userOrId === "object" ? userOrId : null;
  const userIdStr = (
    typeof userOrId === "string"
      ? userOrId
      : (userDoc?.id || userDoc?._id || userDoc?.userId)?.toString()
  ) || "";
  const cleanUserId = userIdStr.trim();
  if (!cleanUserId || cleanUserId.startsWith("$")) return false;

  let user = userDoc;
  if (!user && db) {
    const userQueries: any[] = [{ id: cleanUserId }];
    if (ObjectId.isValid(cleanUserId) && cleanUserId.length === 24) {
      try {
        userQueries.push({ _id: new ObjectId(cleanUserId) });
      } catch {}
    }
    user = await db.collection("user").findOne({ $or: userQueries });
  }

  // USER-REQUIRED POLICY: Super Admin has NO bypass or membership in consumer applications
  if (user) {
    if (user.role === "super-admin" && (user.scopedClientId === null || user.scopedClientId === undefined)) return false;
    if (user.role === "admin" && user.scopedClientId === null) return false;
  }

  const userConditions: any[] = [{ userId: cleanUserId }];
  if (ObjectId.isValid(cleanUserId) && cleanUserId.length === 24) {
    try {
      userConditions.push({ userId: new ObjectId(cleanUserId) });
    } catch {}
  }

  // Authoritative concurrent check across both user_app_registrations and app_admins
  const [regRecords, adminRecords] = await Promise.all([
    db.collection("user_app_registrations").find({
      clientId: cleanClientId,
      $or: userConditions,
    }).toArray(),
    db.collection("app_admins").find({
      clientId: cleanClientId,
      $or: userConditions,
    }).toArray(),
  ]);

  // Explicit revocation, suspension, or disabling in either source strictly takes precedence
  const hasRevokedReg = regRecords.some((r: any) =>
    r.isActive === false ||
    r.active === false ||
    r.disabled === true ||
    r.revoked === true ||
    ["inactive", "revoked", "suspended", "disabled"].includes(r.status)
  );

  const hasRevokedAdmin = adminRecords.some((a: any) =>
    a.isActive === false ||
    a.active === false ||
    a.disabled === true ||
    a.revoked === true ||
    ["inactive", "revoked", "suspended", "disabled"].includes(a.status)
  );

  if (hasRevokedReg || hasRevokedAdmin) {
    return false;
  }

  const hasActiveReg = regRecords.some((r: any) =>
    r.isActive !== false &&
    r.active !== false &&
    !r.disabled &&
    !r.revoked &&
    !["inactive", "revoked", "suspended", "disabled"].includes(r.status)
  );

  const hasActiveAdmin = adminRecords.some((a: any) =>
    a.isActive !== false &&
    a.active !== false &&
    !a.disabled &&
    !a.revoked &&
    !["inactive", "revoked", "suspended", "disabled"].includes(a.status)
  );

  if (hasActiveReg || hasActiveAdmin) {
    return true;
  }

  // Fail closed: runtime email matching without migration is strictly removed.
  // Removed or non-existent assignment: scopedClientId alone NEVER grants access
  return false;
}

/**
 * Validates post-issuance token access for private applications at UserInfo and Introspection.
 * For explicit private applications, active assignment is strictly required.
 * For legacy clients without explicit policy, denies super admins and revoked members.
 */
export async function checkPrivateAppTokenAccess(
  db: any,
  userOrId: any,
  clientDoc: any
): Promise<boolean> {
  if (!clientDoc) return true;
  const isPrivate = clientDoc.accessPolicy === "private" || (clientDoc.accessPolicy !== "open" && clientDoc.isPublic === false);
  if (!isPrivate) return true;

  const canonicalClientId = clientDoc.clientId || clientDoc.client_id;
  if (!canonicalClientId) return false;

  // Explicit private policy strictly requires active assignment
  if (clientDoc.isExplicit === true) {
    return checkUserHasAppAccess(db, userOrId, canonicalClientId);
  }

  const userDoc = typeof userOrId === "object" ? userOrId : null;
  const userIdStr = (
    typeof userOrId === "string"
      ? userOrId
      : (userDoc?.id || userDoc?._id || userDoc?.userId)?.toString()
  ) || "";
  const cleanUserId = userIdStr.trim();

  let user = userDoc;
  if (!user && db && cleanUserId) {
    const userQueries: any[] = [{ id: cleanUserId }];
    if (ObjectId.isValid(cleanUserId) && cleanUserId.length === 24) {
      try { userQueries.push({ _id: new ObjectId(cleanUserId) }); } catch {}
    }
    user = await db.collection("user").findOne({ $or: userQueries });
  }

  if (user && user.role === "super-admin" && !user.scopedClientId) {
    return false;
  }

  // Deny if explicit revoked registration or admin assignment exists
  const userConditions: any[] = [{ userId: cleanUserId }];
  if (ObjectId.isValid(cleanUserId) && cleanUserId.length === 24) {
    try { userConditions.push({ userId: new ObjectId(cleanUserId) }); } catch {}
  }

  const [regRecords, adminRecords] = await Promise.all([
    db.collection("user_app_registrations").find({ clientId: canonicalClientId, $or: userConditions }).toArray(),
    db.collection("app_admins").find({ clientId: canonicalClientId, $or: userConditions }).toArray(),
  ]);

  const hasRevoked = regRecords.some((r: any) =>
    r.isActive === false || r.active === false || r.disabled === true || r.revoked === true ||
    ["inactive", "revoked", "suspended", "disabled"].includes(r.status)
  ) || adminRecords.some((a: any) =>
    a.isActive === false || a.active === false || a.disabled === true || a.revoked === true ||
    ["inactive", "revoked", "suspended", "disabled"].includes(a.status)
  );

  return !hasRevoked;
}
