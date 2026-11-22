import { ObjectId } from "mongodb";
import { getDb } from "../db/mongo";
import {
  getTrustedClientIp,
  resolveOAuthClient,
  toApprovedDisplayLabel,
  isEmailShaped,
  validateSafePrimitiveString,
  escapeRegex,
} from "../utils/security";
import { recordAdminAudit } from "../db/state";

export async function handleGetAppUsers(c: any): Promise<Response> {
  const rawClientId = c.req.param("clientId");
  const queryUserId = c.req.query("userId");
  try {
    const database = await getDb();
    let client: any;
    try {
      client = await resolveOAuthClient(database, rawClientId);
    } catch (err: any) {
      console.error("[ADMIN_LIST_APP_USERS] DB error resolving client:", err);
      return c.json({ error: "Failed to resolve client due to database error" }, 500);
    }
    if (!client) {
      return c.json({ error: "Application not found" }, 404);
    }
    const canonicalClientId = client.clientId;

    const query: Record<string, any> = { clientId: canonicalClientId };
    if (queryUserId !== undefined) {
      const validUserId = validateSafePrimitiveString(queryUserId, "userId");
      if (!validUserId) {
        return c.json({ error: "Invalid userId parameter", code: "ERR_INVALID_INPUT" }, 400);
      }
      query.userId = validUserId;
    }
    const regs = await database
      .collection("user_app_registrations")
      .find(query)
      .sort({ registeredAt: -1 })
      .toArray();

    const userIds = regs.map((r: any) => r.userId);
    const validObjectIds: ObjectId[] = [];
    for (const id of userIds) {
      try {
        if (ObjectId.isValid(id)) validObjectIds.push(new ObjectId(id));
      } catch {}
    }
    const users = await database
      .collection("user")
      .find({
        $or: [
          { id: { $in: userIds } },
          { _id: { $in: validObjectIds } },
        ],
      })
      .toArray();

    const userMap = new Map<string, any>();
    users.forEach((u: any) => {
      userMap.set(String(u.id || u._id), u);
      userMap.set(String(u._id), u);
    });

    const enriched = regs.map((r: any) => {
      const u = userMap.get(String(r.userId));
      return {
        registrationId: r._id.toString(),
        userId: r.userId,
        displayLabel: toApprovedDisplayLabel(u?.email, u?.name),
        name: isEmailShaped(u?.name) ? toApprovedDisplayLabel(u?.name) : (u?.name || "User"),
        registeredAt: r.registeredAt ? r.registeredAt.toISOString() : null,
      };
    });

    return c.json({ users: enriched });
  } catch (err: any) {
    console.error("[ADMIN_LIST_APP_USERS] Error:", err);
    return c.json({ error: "Failed to load assigned users" }, 500);
  }
}

export async function handlePostAppUsers(c: any): Promise<Response> {
  const rawClientId = c.req.param("clientId");
  const body = await c.req.json().catch(() => ({}));
  const email = typeof body.email === "string" ? body.email.toLowerCase().trim() : "";
  const sessionUser = c.get("user") as any;

  if (!email || !email.includes("@")) {
    return c.json({ error: "Valid user email is required" }, 400);
  }

  try {
    const database = await getDb();
    let client: any;
    try {
      client = await resolveOAuthClient(database, rawClientId);
    } catch (err: any) {
      console.error("[ADMIN_ASSIGN_APP_USER] DB error resolving client:", err);
      return c.json({ error: "Failed to resolve client due to database error" }, 500);
    }
    if (!client) return c.json({ error: "Application not found" }, 404);

    const canonicalClientId = client.clientId;

    const user = await database.collection("user").findOne({ email });
    if (!user) {
      return c.json({ error: "No user found with this email address" }, 404);
    }

    const userId = String(user.id || user._id);

    const existing = await database.collection("user_app_registrations").findOne({
      clientId: canonicalClientId,
      userId,
    });
    if (existing) {
      return c.json({ error: "User is already assigned to this application" }, 409);
    }

    const now = new Date();
    await database.collection("user_app_registrations").insertOne({
      clientId: canonicalClientId,
      userId,
      registeredAt: now,
      assignedBy: sessionUser?.email || "admin",
    });

    await recordAdminAudit({
      actorUserId: sessionUser?.id,
      actorEmail: sessionUser?.email,
      actorScope: sessionUser?.scopedClientId || "super_admin",
      action: "user_assigned_to_app",
      targetClientId: canonicalClientId,
      targetUserId: userId,
      details: { email },
      ipAddress: getTrustedClientIp(c),
      timestamp: now,
    });

    return c.json({
      success: true,
      message: "User successfully authorized for this application",
      user: {
        userId,
        email: user.email,
        name: user.name || user.email.split("@")[0],
        registeredAt: now.toISOString(),
      },
    }, 201);
  } catch (err: any) {
    console.error("[ADMIN_ASSIGN_APP_USER] Error:", err);
    return c.json({ error: err?.message || "Failed to assign user" }, 500);
  }
}

export async function handleDeleteAppUser(c: any): Promise<Response> {
  const rawClientId = c.req.param("clientId");
  const userId = c.req.param("userId");
  const sessionUser = c.get("user") as any;

  try {
    const database = await getDb();
    let clientDoc: any;
    try {
      clientDoc = await resolveOAuthClient(database, rawClientId);
    } catch (err: any) {
      console.error("[ADMIN_REMOVE_APP_USER] DB error resolving client:", err);
      return c.json({ error: "Failed to resolve client due to database error" }, 500);
    }

    if (!clientDoc) {
      return c.json({ error: "Client not found" }, 404);
    }

    const canonicalClientId = clientDoc.clientId;

    const [regResult, tokenResult, refreshResult, consentResult, codeResult] = await Promise.all([
      database.collection("user_app_registrations").deleteMany({
        clientId: canonicalClientId,
        $or: [{ userId }, { userId: String(userId) }],
      }),
      database.collection("oauthAccessToken").deleteMany({ clientId: canonicalClientId, userId: { $in: [userId, String(userId)] } }),
      database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalClientId, userId: { $in: [userId, String(userId)] } }),
      database.collection("oauthConsent").deleteMany({ clientId: canonicalClientId, userId: { $in: [userId, String(userId)] } }),
      database.collection("oauthAuthorizationCode").deleteMany({ clientId: canonicalClientId, userId: { $in: [userId, String(userId)] } }),
      database.collection("oauth_token_families").updateMany(
        { clientId: canonicalClientId, userId: { $in: [userId, String(userId)] } },
        { $set: { status: "revoked", revokedAt: new Date() } }
      ),
      database.collection("verification").deleteMany({
        $or: [
          { value: { $regex: `"userId":"${escapeRegex(userId)}".*"client_id":"${escapeRegex(canonicalClientId)}"` } },
          { value: { $regex: `"client_id":"${escapeRegex(canonicalClientId)}".*"userId":"${escapeRegex(userId)}"` } },
        ]
      }).catch(() => {}),
    ]);

    const totalRemoved =
      regResult.deletedCount +
      tokenResult.deletedCount +
      refreshResult.deletedCount +
      consentResult.deletedCount +
      codeResult.deletedCount;

    if (totalRemoved === 0) {
      return c.json({ error: "Assignment not found" }, 404);
    }

    await recordAdminAudit({
      actorUserId: sessionUser?.id,
      actorEmail: sessionUser?.email,
      actorScope: sessionUser?.scopedClientId || "super_admin",
      action: "user_removed_from_app",
      targetClientId: canonicalClientId,
      targetUserId: userId,
      ipAddress: getTrustedClientIp(c),
      timestamp: new Date(),
    });

    return c.json({ success: true, message: "User access removed from application" });
  } catch (err: any) {
    console.error("[ADMIN_REMOVE_APP_USER] Error:", err);
    return c.json({ error: err?.message || "Failed to remove user" }, 500);
  }
}
