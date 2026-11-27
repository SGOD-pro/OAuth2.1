import { pathToFileURL } from "node:url";
import { config } from "../config";
import { closeDb, getDb } from "../db/mongo";
import { reconcilePendingLedgerDeletions } from "../identity/deletion";
import { processNextDeletionCleanupJob, type DeletionCleanupDeps } from "../identity/deletion-cleanup";

export async function runDeletionReconcilePass(
  databaseArg?: any,
  maxBatch = 20,
  cleanupDeps: DeletionCleanupDeps = {}
): Promise<{ reconciledCount: number; cleanedCount: number }> {
  const database = databaseArg || (await getDb());
  const { reconciledCount } = await reconcilePendingLedgerDeletions(database, { maxBatch });
  let cleanedCount = 0;
  for (let i = 0; i < maxBatch; i++) {
    const didWork = await processNextDeletionCleanupJob(database, cleanupDeps);
    if (!didWork) break;
    cleanedCount += 1;
  }
  return { reconciledCount, cleanedCount };
}

export function startDeletionReconcileWorker(options: {
  intervalMs?: number;
  maxBatch?: number;
  getDbFn?: () => Promise<any>;
  onError?: (err: unknown) => void;
} = {}) {
  const intervalMs = Math.max(100, options.intervalMs ?? config.identity.deletionReconcileIntervalMs);
  const maxBatch = options.maxBatch ?? 20;
  let stopped = false;
  let inFlight: Promise<{ reconciledCount: number }> | null = null;

  const triggerNow = async (): Promise<{ reconciledCount: number }> => {
    if (stopped) return { reconciledCount: 0 };
    if (inFlight) {
      await inFlight;
      return { reconciledCount: 0 };
    }
    inFlight = (async () => {
      const database = await (options.getDbFn ?? getDb)();
      return reconcilePendingLedgerDeletions(database, { maxBatch });
    })();
    try {
      return await inFlight;
    } finally {
      inFlight = null;
    }
  };

  const runSafe = () => {
    void triggerNow().catch((err) => {
      if (options.onError) options.onError(err);
      else console.error("[DELETION_WORKER] Reconciliation pass failed:", (err as any)?.message || err);
    });
  };

  const timer = setInterval(runSafe, intervalMs);
  if (typeof timer.unref === "function") timer.unref();
  queueMicrotask(runSafe);

  return {
    triggerNow,
    stop() {
      stopped = true;
      clearInterval(timer);
    },
  };
}

const isDirectExecution = Boolean(
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href
);

if (isDirectExecution) {
  const runOnce = process.argv.includes("--once");
  if (runOnce) {
    runDeletionReconcilePass()
      .then(async (res) => {
        console.log(`[DELETION_WORKER] Reconciled ${res.reconciledCount} pending ledger deletions`);
        await closeDb();
        process.exit(0);
      })
      .catch(async (err) => {
        console.error("[DELETION_WORKER] Fatal error:", err);
        await closeDb().catch(() => {});
        process.exit(1);
      });
  } else {
    const worker = startDeletionReconcileWorker();
    const shutdown = async () => {
      worker.stop();
      await closeDb().catch(() => {});
      process.exit(0);
    };
    process.on("SIGINT", () => void shutdown());
    process.on("SIGTERM", () => void shutdown());
  }
}
