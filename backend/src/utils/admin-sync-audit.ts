import { Db } from "mongodb";

export async function recordSyncAudit(
  database: Db,
  entry: {
    action: string;
    targetClientId: string;
    targetUserId: string;
    details?: Record<string, unknown>;
    timestamp?: Date;
  }
): Promise<void> {
  try {
    await database.collection("admin_audit").insertOne({
      ...entry,
      timestamp: entry.timestamp || new Date(),
    });
  } catch (err: any) {
    console.warn("[ADMIN_SYNC_AUDIT] Failed to record admin audit entry:", err?.message || err);
  }
}
