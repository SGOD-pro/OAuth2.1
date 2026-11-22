import { AggregatedLogsParams } from "./admin-logs-types";

export interface LogFilterContext {
  authFilter: any;
  auditFilter: any;
  sessionFilter: any;
  unmappedSessionPipeline: any[];
}

export function buildLogsFilters(params: AggregatedLogsParams): LogFilterContext {
  const { outcome: rawOutcome, action, clientId, from, to, search } = params;
  const outcome = rawOutcome === "failed" ? "failure" : rawOutcome;

  // Build filters for auth_events
  const authFilter: any = {};
  if (outcome) {
    authFilter.outcome = outcome;
  }
  if (action) {
    authFilter.eventType = action;
  }
  if (clientId) {
    authFilter.clientId = clientId;
  }
  if (from || to) {
    authFilter.timestamp = {};
    if (from) authFilter.timestamp.$gte = from;
    if (to) authFilter.timestamp.$lte = to;
  }

  // Build filters for admin_audit
  const auditFilter: any = {};
  if (outcome) {
    if (outcome === "success") {
      // admin_audit entries are successful administrative actions
    } else {
      auditFilter._id = { $exists: false };
    }
  }
  if (action) {
    auditFilter.action = action;
  }
  if (clientId) {
    auditFilter.targetClientId = clientId;
  }
  if (from || to) {
    auditFilter.timestamp = {};
    if (from) auditFilter.timestamp.$gte = from;
    if (to) auditFilter.timestamp.$lte = to;
  }

  // Build filters for session
  const sessionFilter: any = {};
  if (outcome) {
    if (outcome === "unknown") {
      // Historical sessions honestly lack explicit outcome flags
    } else {
      sessionFilter._id = { $exists: false };
    }
  }
  if (action) {
    if (action === "user_sign_in" || action === "sign_in") {
      // session matches sign in
    } else {
      sessionFilter._id = { $exists: false };
    }
  }
  if (clientId) {
    sessionFilter._id = { $exists: false };
  }
  if (from || to) {
    sessionFilter.createdAt = {};
    if (from) sessionFilter.createdAt.$gte = from;
    if (to) sessionFilter.createdAt.$lte = to;
  }

  // Search filter across searchable fields
  if (search && search.trim()) {
    const escaped = search.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(escaped, "i");
    authFilter.$or = [
      { targetIdentifier: regex },
      { userId: regex },
      { ipAddress: regex },
      { clientId: regex },
      { clientName: regex },
      { eventType: regex },
      { reason: regex },
    ];
    if (!auditFilter._id) {
      auditFilter.$or = [
        { actorEmail: regex },
        { actorUserId: regex },
        { action: regex },
        { targetClientId: regex },
        { ipAddress: regex },
      ];
    }
    if (!sessionFilter._id) {
      sessionFilter.$or = [
        { userId: regex },
        { ipAddress: regex },
      ];
    }
  }

  // Deduplicate active sessions already tracked in auth_events with correlation identifiers
  // Un-correlated historical sessions are filtered using database-side lookup without unbounded memory consumption
  const unmappedSessionPipeline: any[] = [
    { $match: sessionFilter },
    {
      $lookup: {
        from: "auth_events",
        let: { sidStr: { $toString: "$_id" }, sidId: { $ifNull: ["$id", ""] } },
        pipeline: [
          {
            $match: {
              $expr: {
                $or: [
                  { $eq: ["$sessionId", "$$sidStr"] },
                  { $eq: ["$sessionId", "$$sidId"] },
                ],
              },
            },
          },
          { $project: { _id: 1 } },
          { $limit: 1 },
        ],
        as: "matchedAuth",
      },
    },
    { $match: { matchedAuth: { $size: 0 } } },
  ];

  return {
    authFilter,
    auditFilter,
    sessionFilter,
    unmappedSessionPipeline,
  };
}

export function buildLogsPipeline(
  filterContext: LogFilterContext,
  page: number,
  limit: number
): any[] {
  const { authFilter, auditFilter, unmappedSessionPipeline } = filterContext;

  return [
    { $match: authFilter },
    {
      $project: {
        _id: 1,
        userId: 1,
        targetIdentifier: 1,
        eventType: 1,
        outcome: 1,
        ipAddress: 1,
        timestamp: 1,
        clientId: 1,
        clientName: 1,
        reason: 1,
        details: 1,
        source: { $literal: "auth_events" },
      },
    },
    {
      $unionWith: {
        coll: "admin_audit",
        pipeline: [
          { $match: auditFilter },
          {
            $project: {
              _id: 1,
              userId: "$actorUserId",
              targetIdentifier: "$actorEmail",
              eventType: "$action",
              outcome: { $ifNull: ["$outcome", "success"] },
              ipAddress: 1,
              timestamp: { $ifNull: ["$timestamp", "$createdAt"] },
              clientId: "$targetClientId",
              clientName: { $literal: "Platform Console" },
              reason: { $literal: null },
              details: 1,
              source: { $literal: "admin_audit" },
            },
          },
        ],
      },
    },
    {
      $unionWith: {
        coll: "session",
        pipeline: [
          ...unmappedSessionPipeline,
          {
            $project: {
              _id: 1,
              userId: 1,
              targetIdentifier: { $literal: null },
              eventType: { $literal: "user_sign_in" },
              outcome: { $literal: "unknown" },
              ipAddress: 1,
              timestamp: { $ifNull: ["$createdAt", "$updatedAt"] },
              clientId: { $literal: null },
              clientName: { $literal: "Unknown application" },
              reason: { $literal: null },
              details: { $literal: null },
              source: { $literal: "session" },
            },
          },
        ],
      },
    },
    { $sort: { timestamp: -1, _id: -1 } },
    { $skip: (page - 1) * limit },
    { $limit: limit },
  ];
}
