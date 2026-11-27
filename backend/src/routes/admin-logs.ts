import { getDb } from "../db/mongo";
import { AccountKeyAccessError } from "../identity/account-key-provider";
import { ProtectedFieldError } from "../identity/protected-envelope";
import { getAggregatedLogs, type AdminLogsDeps } from "./admin-logs-service";

export interface AdminLogsRouteDeps extends AdminLogsDeps {
  getDb?: () => Promise<any>;
}

function parseLogsParams(c: any) {
  const rawPage = parseInt(c.req.query("page") || "1", 10);
  const rawLimit = parseInt(c.req.query("limit") || "50", 10);
  const page = isNaN(rawPage) || rawPage < 1 ? 1 : rawPage;
  const limit = isNaN(rawLimit) || rawLimit < 1 ? 50 : Math.min(rawLimit, 100);
  const outcome = c.req.query("outcome") || null;
  const action = c.req.query("action") || c.req.query("eventType") || null;
  const clientId = c.req.query("clientId") || null;
  const fromStr = c.req.query("from");
  const toStr = c.req.query("to");
  const from = fromStr ? new Date(fromStr) : null;
  const to = toStr ? new Date(toStr) : null;
  return {
    page,
    limit,
    outcome,
    action,
    clientId,
    from: from && !isNaN(from.getTime()) ? from : null,
    to: to && !isNaN(to.getTime()) ? to : null,
    search: c.req.query("search") || null,
  };
}

function mapProtectedLogsError(c: any, err: unknown): Response | null {
  if (err instanceof AccountKeyAccessError) {
    return c.json({ error: err.code, error_description: err.message }, err.code === "provider_outage" ? 503 : 403);
  }
  if (err instanceof ProtectedFieldError) {
    return c.json({ error: err.code, error_description: err.message }, err.code === "profile_not_found" ? 404 : 500);
  }
  return null;
}

export function createGetLogsHandler(deps: AdminLogsRouteDeps = {}) {
  return async (c: any): Promise<Response> => {
    try {
      const database = await (deps.getDb ?? getDb)();
      const result = await getAggregatedLogs(database, parseLogsParams(c), deps);
      c.header("X-Total-Count", String(result.totalCount));
      c.header("X-Page", String(result.page));
      c.header("X-Limit", String(result.limit));
      c.header("X-Total-Pages", String(result.totalPages));
      return c.json(result.entries);
    } catch (err) {
      const mapped = mapProtectedLogsError(c, err);
      if (mapped) return mapped;
      console.error("[ADMIN_LOGS] Error fetching logs:", err);
      return c.json({ error: "Failed to fetch audit logs", code: "ERR_DATABASE_ERROR" }, 500);
    }
  };
}

export function createGetV2LogsHandler(deps: AdminLogsRouteDeps = {}) {
  return async (c: any): Promise<Response> => {
    try {
      const database = await (deps.getDb ?? getDb)();
      const result = await getAggregatedLogs(database, parseLogsParams(c), deps);
      return c.json({
        logs: result.entries,
        pagination: {
          totalCount: result.totalCount,
          page: result.page,
          limit: result.limit,
          totalPages: result.totalPages,
        },
      });
    } catch (err) {
      const mapped = mapProtectedLogsError(c, err);
      if (mapped) return mapped;
      console.error("[ADMIN_LOGS_V2] Error fetching logs:", err);
      return c.json({ error: "Failed to fetch audit logs" }, 500);
    }
  };
}

export const handleGetLogs = createGetLogsHandler();
export const handleGetV2Logs = createGetV2LogsHandler();
