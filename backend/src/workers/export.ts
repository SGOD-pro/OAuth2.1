import { getDb } from "../db/mongo";
import { processNextExportJob, type ExportJobDeps } from "../identity/export-jobs";

export async function runExportWorkerPass(
  databaseArg?: any,
  maxJobs = 10,
  deps: ExportJobDeps = {}
): Promise<number> {
  const database = databaseArg || (await getDb());
  let count = 0;
  for (let i = 0; i < maxJobs; i++) {
    const processed = await processNextExportJob(database, deps);
    if (!processed) break;
    count++;
  }
  return count;
}

export function startExportWorker(options: { intervalMs?: number; maxJobs?: number; deps?: ExportJobDeps } = {}) {
  const intervalMs = Math.max(500, options.intervalMs ?? 5000);
  let stopped = false;
  let inFlight = false;

  const runSafe = () => {
    if (stopped || inFlight) return;
    inFlight = true;
    void runExportWorkerPass(undefined, options.maxJobs ?? 10, options.deps ?? {})
      .catch((err) => console.error("[EXPORT_WORKER] Pass failed:", (err as any)?.message || err))
      .finally(() => { inFlight = false; });
  };

  const timer = setInterval(runSafe, intervalMs);
  if (typeof timer.unref === "function") timer.unref();
  return {
    stop() {
      stopped = true;
      clearInterval(timer);
    },
  };
}
