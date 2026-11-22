import { ObjectId } from "mongodb";
import { toApprovedDisplayLabel } from "../utils/security";
import { AggregatedLogsParams, AggregatedLogsResult, NormalizedLogEntry } from "./admin-logs-types";
import { buildLogsFilters, buildLogsPipeline } from "./admin-logs-pipeline";

export async function getAggregatedLogs(
  database: any,
  params: AggregatedLogsParams
): Promise<AggregatedLogsResult> {
  const { page, limit } = params;
  const filterContext = buildLogsFilters(params);
  const { authFilter, auditFilter, unmappedSessionPipeline } = filterContext;

  const [authCount, auditCount, sessionCountDocs] = await Promise.all([
    database.collection("auth_events").countDocuments(authFilter),
    database.collection("admin_audit").countDocuments(auditFilter),
    database.collection("session").aggregate([
      ...unmappedSessionPipeline,
      { $count: "total" },
    ]).toArray(),
  ]);

  const sessionCount = (sessionCountDocs && sessionCountDocs[0]?.total) || 0;
  const totalCount = authCount + auditCount + sessionCount;
  const totalPages = Math.ceil(totalCount / limit) || 1;

  if (totalCount === 0) {
    return {
      entries: [],
      totalCount: 0,
      page,
      limit,
      totalPages: 1,
    };
  }

  const pipeline = buildLogsPipeline(filterContext, page, limit);
  const docs = await database.collection("auth_events").aggregate(pipeline).toArray();

  const paginated: NormalizedLogEntry[] = docs.map((doc: any) => {
    const rawIp = typeof doc.ipAddress === "string" ? doc.ipAddress.trim() : null;
    const ipAddress = (rawIp && rawIp.toLowerCase() !== "unknown") ? rawIp : null;
    const ts = doc.timestamp;
    const createdAt = ts ? new Date(ts).toISOString() : null;

    let appName: string | null = null;
    if (doc.source === "admin_audit") {
      appName = "Platform Console";
    } else if (doc.source === "session") {
      appName = "Unknown application";
    } else {
      appName = doc.clientName || doc.clientId || (doc.clientId === null ? "Platform Console" : null);
    }

    return {
      userId: doc.userId ? String(doc.userId) : (doc.targetIdentifier || "unknown"),
      userEmail: doc.targetIdentifier || (doc.userId ? String(doc.userId) : null),
      action: doc.eventType || "auth_event",
      outcome: doc.outcome || null,
      ipAddress,
      createdAt,
      appName,
      applicationName: appName,
      clientId: doc.clientId || null,
      reason: doc.reason || null,
      details: doc.details || null,
    };
  });

  // Single batch user resolution for any unpopulated emails
  const unresolvedUserIds = new Set<string>();
  paginated.forEach((entry) => {
    if (entry.userId && (!entry.userEmail || entry.userEmail === entry.userId || entry.userEmail === "unknown")) {
      unresolvedUserIds.add(entry.userId);
    }
  });

  if (unresolvedUserIds.size > 0) {
    const stringIds = Array.from(unresolvedUserIds);
    const objectIds = stringIds
      .filter((id) => ObjectId.isValid(id))
      .map((id) => {
        try {
          return new ObjectId(id);
        } catch {
          return null;
        }
      })
      .filter((id): id is ObjectId => id !== null);

    const userDocs = await database
      .collection("user")
      .find(
        {
          $or: [
            ...(objectIds.length > 0 ? [{ _id: { $in: objectIds } }] : []),
            { id: { $in: stringIds } },
          ],
        },
        { projection: { email: 1, id: 1 } }
      )
      .toArray();

    const emailMap = new Map<string, string>();
    userDocs.forEach((u: any) => {
      if (u.email) {
        emailMap.set(String(u._id), u.email);
        if (u.id) emailMap.set(String(u.id), u.email);
      }
    });

    paginated.forEach((entry) => {
      if (entry.userId && (!entry.userEmail || entry.userEmail === entry.userId || entry.userEmail === "unknown")) {
        const found = emailMap.get(entry.userId);
        if (found) {
          entry.userEmail = toApprovedDisplayLabel(found);
        }
      } else if (entry.userEmail && entry.userEmail.includes("@")) {
        entry.userEmail = toApprovedDisplayLabel(entry.userEmail);
      }
    });
  }

  return {
    entries: paginated,
    totalCount,
    page,
    limit,
    totalPages,
  };
}
