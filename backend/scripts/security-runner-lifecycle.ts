import { ChildProcess } from "node:child_process";
import { MongoClient } from "mongodb";

/**
 * Check if any process in the target process group is alive on POSIX platforms.
 */
export function isProcessGroupAlive(targetPid: number): boolean {
  if (process.platform === "win32") {
    return false;
  }
  try {
    process.kill(-targetPid, 0);
    return true;
  } catch (err: any) {
    return err.code === "EPERM";
  }
}

/**
 * Terminate a process group with bounded graceful period then SIGKILL.
 * Handles the case where the leader exits while descendants ignore SIGTERM.
 */
export async function terminateProcessGroup(
  pid: number | undefined,
  child: ChildProcess | null,
  gracePeriodMs = 2000
): Promise<void> {
  if (!pid) return;

  const sendSignal = (signal: NodeJS.Signals) => {
    try {
      if (process.platform !== "win32") {
        process.kill(-pid, signal);
      } else if (child) {
        child.kill(signal);
      }
    } catch {}
  };

  // If process or group is already dead, nothing to do
  if (process.platform !== "win32" && !isProcessGroupAlive(pid)) {
    return;
  }

  sendSignal("SIGTERM");

  // Wait up to grace period while group or child remains active
  const startTime = Date.now();
  while (Date.now() - startTime < gracePeriodMs) {
    if (process.platform !== "win32") {
      if (!isProcessGroupAlive(pid)) {
        return;
      }
    } else if (child && (child.exitCode !== null || child.signalCode !== null)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  // Force kill if processes still remain in group
  sendSignal("SIGKILL");

  const killStartTime = Date.now();
  while (Date.now() - killStartTime < 2000) {
    if (process.platform !== "win32") {
      if (!isProcessGroupAlive(pid)) {
        return;
      }
    } else if (child && (child.exitCode !== null || child.signalCode !== null)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  if (process.platform !== "win32" && isProcessGroupAlive(pid)) {
    console.error(`[PROCESS_CLEANUP_FAILURE] Process group -${pid} survived SIGKILL escalation`);
  }
}

/**
 * Safely drop a database with bounded operation deadline and reliable client close.
 */
export async function dropDatabaseBounded(
  uri: string,
  dbName: string,
  deadlineMs = 5000
): Promise<void> {
  const cleanupClient = new MongoClient(uri, {
    serverSelectionTimeoutMS: deadlineMs,
    connectTimeoutMS: deadlineMs,
  });

  try {
    await cleanupClient.connect();
    await Promise.race([
      cleanupClient.db(dbName).dropDatabase({ maxTimeMS: deadlineMs }),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error(`Database drop timed out after ${deadlineMs}ms`)),
          deadlineMs
        )
      ),
    ]);
  } catch (err: any) {
    console.error(`[DATABASE_CLEANUP_FAILURE] Cleanup failed for ${dbName}: ${err?.message || err}`);
    throw err;
  } finally {
    await cleanupClient.close().catch((closeErr: any) => {
      console.error(`[DATABASE_CLEANUP_CLOSE_ERROR] Failed closing client for ${dbName}: ${closeErr?.message || closeErr}`);
    });
  }
}

/**
 * Coordinated cleanup awaiting process termination before database removal.
 */
export async function coordinateSuiteCleanup(options: {
  child: ChildProcess | null;
  uri: string | null;
  dbName: string | null;
  gracePeriodMs?: number;
  deadlineMs?: number;
}): Promise<void> {
  const { child, uri, dbName, gracePeriodMs = 2000, deadlineMs = 5000 } = options;

  if (child) {
    await terminateProcessGroup(child.pid, child, gracePeriodMs);
  }

  if (uri && dbName) {
    try {
      await dropDatabaseBounded(uri, dbName, deadlineMs);
    } catch (err: any) {
      console.error(`[SUITE_CLEANUP_ERROR] Coordinated database removal failed for ${dbName}: ${err?.message || err}`);
    }
  }
}
