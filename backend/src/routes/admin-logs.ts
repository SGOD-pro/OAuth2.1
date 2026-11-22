import { getDb } from "../db/mongo";
import { getAggregatedLogs } from "./admin-logs-service";

export async function handleGetLogs(c: any): Promise<Response> {
  try {
    const database = await getDb();
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
    const validFrom = from && !isNaN(from.getTime()) ? from : null;
    const validTo = to && !isNaN(to.getTime()) ? to : null;
    const search = c.req.query("search") || null;

    const result = await getAggregatedLogs(database, {
      page,
      limit,
      outcome,
      action,
      clientId,
      from: validFrom,
      to: validTo,
      search,
    });

    c.header("X-Total-Count", String(result.totalCount));
    c.header("X-Page", String(result.page));
    c.header("X-Limit", String(result.limit));
    c.header("X-Total-Pages", String(result.totalPages));

    return c.json(result.entries);
  } catch (err) {
    console.error("[ADMIN_LOGS] Error fetching logs:", err);
    return c.json({ error: "Failed to fetch audit logs", code: "ERR_DATABASE_ERROR" }, 500);
  }
}

export async function handleGetV2Logs(c: any): Promise<Response> {
  try {
    const database = await getDb();
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
    const validFrom = from && !isNaN(from.getTime()) ? from : null;
    const validTo = to && !isNaN(to.getTime()) ? to : null;
    const search = c.req.query("search") || null;

    const result = await getAggregatedLogs(database, {
      page,
      limit,
      outcome,
      action,
      clientId,
      from: validFrom,
      to: validTo,
      search,
    });

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
    console.error("[ADMIN_LOGS_V2] Error fetching logs:", err);
    return c.json({ error: "Failed to fetch audit logs" }, 500);
  }
}
