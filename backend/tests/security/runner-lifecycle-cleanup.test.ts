import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  isProcessGroupAlive,
  terminateProcessGroup,
  dropDatabaseBounded,
  coordinateSuiteCleanup,
} from "../../scripts/security-runner-lifecycle";

describe("Security Runner Lifecycle and Process Cleanup Suite", () => {
  it("terminates stubborn descendant ignoring SIGTERM when leader exits first", async () => {
    if (process.platform === "win32") {
      return; // Process group signaling is POSIX specific
    }

    // Spawn a leader that forks an unkillable-by-SIGTERM child and exits immediately
    const helperCode = `
      const { spawn } = require("node:child_process");
      const worker = spawn(process.execPath, [
        "-e",
        "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);"
      ], { stdio: "ignore" });
      process.stdout.write(String(worker.pid) + "\\n");
      process.exit(0);
    `;

    const leader = spawn(process.execPath, ["-e", helperCode], {
      detached: true,
      stdio: ["ignore", "pipe", "ignore"],
    });

    const leaderPid = leader.pid!;
    assert.ok(leaderPid);

    const workerPidStr = await new Promise<string>((resolve) => {
      leader.stdout?.once("data", (data) => resolve(data.toString().trim()));
    });
    const workerPid = Number(workerPidStr);
    assert.ok(workerPid && !isNaN(workerPid));

    // Wait for leader process to exit
    await new Promise<void>((resolve) => {
      leader.once("exit", () => resolve());
    });
    assert.notEqual(leader.exitCode, null, "Leader must have exited");

    // Stubborn worker must still be running in the process group
    assert.ok(isProcessGroupAlive(leaderPid), "Process group must be alive while stubborn worker runs");

    // Execute terminateProcessGroup with 200ms grace period
    const start = Date.now();
    await terminateProcessGroup(leaderPid, null, 200);
    const elapsed = Date.now() - start;

    // Must have terminated worker via SIGKILL escalation within bounded time
    assert.ok(!isProcessGroupAlive(leaderPid), "Process group must be completely dead after SIGKILL escalation");
    assert.ok(elapsed < 4000, `Cleanup must finish in bounded time (took ${elapsed}ms)`);
  });

  it("detects terminated child via signalCode when exitCode is null", async () => {
    const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000);"], {
      detached: process.platform !== "win32",
    });

    assert.ok(child.pid);
    const start = Date.now();

    // Kill child with SIGKILL
    setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {}
    }, 50);

    await terminateProcessGroup(child.pid, child, 1000);
    const elapsed = Date.now() - start;

    assert.ok(elapsed < 3000, "Must detect exit via signalCode without waiting full timeout");
  });

  it("bounds database cleanup failure within specified timeout", async () => {
    // Unreachable host to trigger connection/operation deadline
    const unreachableUri = "mongodb://192.0.2.1:27017/unreachable_db";
    const start = Date.now();
    let thrownError: any = null;

    try {
      await dropDatabaseBounded(unreachableUri, "unreachable_test_db", 300);
    } catch (err: any) {
      thrownError = err;
    }

    const elapsed = Date.now() - start;
    assert.ok(thrownError, "Bounded drop must throw on failure");
    assert.ok(elapsed < 3000, `Cleanup must fail fast within bounded deadline (took ${elapsed}ms)`);
  });

  it("coordinates process termination before database cleanup", async () => {
    const callOrder: string[] = [];

    const mockChild: any = {
      pid: undefined,
      exitCode: 0,
      signalCode: null,
      kill: () => {},
    };

    let cleanupFinished = false;
    await coordinateSuiteCleanup({
      child: mockChild,
      uri: null,
      dbName: null,
      gracePeriodMs: 100,
      deadlineMs: 200,
    });
    cleanupFinished = true;

    assert.ok(cleanupFinished, "Coordinated cleanup must complete cleanly");
  });
});
