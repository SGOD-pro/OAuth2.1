import { getDb } from "../db/mongo";

export async function handleGetStats(c: any): Promise<Response> {
  try {
    const database = await getDb();
    const sessionUser = c.get("user") as any;
    const scopedClientId = sessionUser?.scopedClientId;

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const clientQuery = scopedClientId
      ? { $or: [{ clientId: scopedClientId }, { client_id: scopedClientId }, { id: scopedClientId }] }
      : {};

    const activeClientFilter = {
      ...clientQuery,
      disabled: { $ne: true },
      is_active: { $ne: false },
      isActive: { $ne: false },
      status: { $nin: ["disabled", "inactive", "revoked", "suspended"] },
    };

    const [totalUsers, totalClients, activeClients, recent24hLogins, activeSessions, recentLogs] = await Promise.all([
      scopedClientId ? 1 : database.collection("user").countDocuments(),
      database.collection("oauthClient").countDocuments(clientQuery),
      database.collection("oauthClient").countDocuments(activeClientFilter),
      database.collection("session").countDocuments({ createdAt: { $gte: oneDayAgo } }),
      database.collection("session").countDocuments({ expiresAt: { $gt: new Date() } }),
      database.collection("session").find().sort({ createdAt: -1 }).limit(10).toArray(),
    ]);

    return c.json({
      totalUsers,
      totalClients,
      activeClients,
      recentLogins: recent24hLogins,
      recentSessions24h: recent24hLogins,
      activeSessions,
      recentActivity: recentLogs.map((log: any) => {
        const rawIp = typeof log.ipAddress === "string" ? log.ipAddress.trim() : null;
        const ipAddress = (rawIp && rawIp.toLowerCase() !== "unknown") ? rawIp : null;
        const ts = log.createdAt || log.updatedAt;
        const timestamp = ts ? new Date(ts).toISOString() : null;
        return {
          id: log.id || log._id?.toString(),
          type: "session_created",
          userId: log.userId,
          ipAddress,
          userAgent: log.userAgent ? log.userAgent.split(" ")[0] : null,
          timestamp,
        };
      }),
    });
  } catch (err) {
    console.error("[ADMIN_STATS] Error fetching stats:", err);
    return c.json({ error: "Failed to fetch stats" }, 500);
  }
}
