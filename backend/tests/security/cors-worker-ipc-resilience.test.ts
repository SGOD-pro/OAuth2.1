import "../fixtures/test-env-isolation";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { fork, spawn, ChildProcess } from "node:child_process";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import {
  sendToWorker,
  terminateWorkerGracefully,
} from "../fixtures/cors-worker-client";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const suite = await setupSuiteDatabase("cors_ipc_resilience");
const mongoUri = suite.uri;
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
const workerPath = path.resolve(__dirname, "../fixtures/cors-multi-process-worker.ts");

function spawnWorker(): ChildProcess {
  return fork(workerPath, [], {
    execPath: process.execPath,
    execArgv: process.execArgv,
    env: {
      ...process.env,
      MONGO_URI: mongoUri,
      NODE_ENV: "test",
    },
    stdio: ["ignore", "inherit", "inherit", "ipc"],
  });
}

function isChildAlive(child: ChildProcess): boolean {
  if (child.exitCode !== null) return false;
  if (!child.pid) return false;
  try {
    process.kill(child.pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function runTest(name: string, fn: () => Promise<void>) {
  process.stdout.write(`  ✔ ${name} ... `);
  const start = Date.now();
  try {
    await fn();
    console.log(`PASSED (${Date.now() - start}ms)`);
  } catch (err: any) {
    console.log(`FAILED (${Date.now() - start}ms)`);
    console.error(err);
    throw err;
  }
}

console.log("\n================================================================");
console.log("  CORS WORKER IPC RESILIENCE AND LIFECYCLE TESTS");
console.log("================================================================\n");

// TEST 1: Worker crash during in-flight IPC
await runTest("Worker crash during IPC request is bounded and rejects with exit info", async () => {
  const child = spawnWorker();
  const start = Date.now();
  let caughtError: Error | null = null;

  try {
    await sendToWorker(child, { type: "INIT" }, { expectedType: "INIT_OK", timeoutMs: 3000 });
    await sendToWorker(child, { type: "TRIGGER_CRASH" }, { stage: "crash_trigger", timeoutMs: 3000 });
  } catch (err: any) {
    caughtError = err;
  } finally {
    await terminateWorkerGracefully(child, 1000);
  }

  const elapsed = Date.now() - start;
  assert.ok(caughtError !== null, "Must catch worker crash error");
  assert.match(caughtError!.message, /Worker exited during stage "crash_trigger"|Worker disconnected during stage "crash_trigger"/);
  assert.ok(elapsed < 2000, `Must settle quickly on exit, took ${elapsed}ms`);
  assert.equal(isChildAlive(child), false, "Worker PID must not be alive");
});

// TEST 2: Worker disconnect during in-flight IPC
await runTest("Worker disconnect during IPC request is bounded and rejects with disconnect info", async () => {
  const child = spawnWorker();
  const start = Date.now();
  let caughtError: Error | null = null;

  try {
    await sendToWorker(child, { type: "INIT" }, { expectedType: "INIT_OK", timeoutMs: 3000 });
    await sendToWorker(child, { type: "TRIGGER_DISCONNECT" }, { stage: "disconnect_trigger", timeoutMs: 3000 });
  } catch (err: any) {
    caughtError = err;
  } finally {
    await terminateWorkerGracefully(child, 1000);
  }

  const elapsed = Date.now() - start;
  assert.ok(caughtError !== null, "Must catch worker disconnect error");
  assert.match(caughtError!.message, /Worker disconnected during stage "disconnect_trigger"|Worker exited/);
  assert.ok(elapsed < 2000, `Must settle quickly on disconnect, took ${elapsed}ms`);
  assert.equal(isChildAlive(child), false, "Worker PID must not be alive");
});

// TEST 3: Missing worker reply triggers bounded timeout
await runTest("Missing worker reply triggers bounded timeout with stage attribution", async () => {
  const child = spawnWorker();
  const start = Date.now();
  let caughtError: Error | null = null;

  try {
    await sendToWorker(child, { type: "INIT" }, { expectedType: "INIT_OK", timeoutMs: 3000 });
    await sendToWorker(child, { type: "IGNORE_MESSAGE" }, { stage: "silent_worker_stage", timeoutMs: 1200 });
  } catch (err: any) {
    caughtError = err;
  } finally {
    await terminateWorkerGracefully(child, 1000);
  }

  const elapsed = Date.now() - start;
  assert.ok(caughtError !== null, "Must catch timeout error");
  assert.match(caughtError!.message, /Worker request timed out after 1200ms during stage "silent_worker_stage"/);
  assert.ok(elapsed >= 1150 && elapsed < 2500, `Elapsed ${elapsed}ms must match bounded timeout`);
  assert.equal(isChildAlive(child), false, "Worker PID must not be alive");
});

// TEST 4: Send on terminated worker fails immediately without hanging
await runTest("Sending to terminated child rejects immediately without hang", async () => {
  const child = spawnWorker();
  await terminateWorkerGracefully(child, 1000);
  let caughtError: Error | null = null;

  try {
    await sendToWorker(child, { type: "START_CHECK" }, { stage: "dead_child_send", timeoutMs: 1000 });
  } catch (err: any) {
    caughtError = err;
  }

  assert.ok(caughtError !== null, "Must reject send on dead worker");
  assert.equal(isChildAlive(child), false, "Worker PID must not be alive");
});

// TEST 5: Graceful termination leaves zero surviving owned workers
await runTest("Graceful worker termination leaves zero surviving child processes", async () => {
  const child = spawnWorker();
  await sendToWorker(child, { type: "INIT" }, { expectedType: "INIT_OK", timeoutMs: 3000 });
  const pid = child.pid!;
  assert.equal(isChildAlive(child), true, "Worker process should initially be alive");

  await terminateWorkerGracefully(child, 2000);
  assert.equal(isChildAlive(child), false, "Worker process must be dead after graceful termination");
  assert.notEqual(child.exitCode, null, "Child exitCode must be populated");
});

await suite.cleanup();

console.log("\n================================================================");
console.log("  ALL CORS WORKER IPC RESILIENCE TESTS PASSED");
console.log("================================================================\n");
