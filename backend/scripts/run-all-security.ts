import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, "..");
dotenv.config({ path: path.resolve(backendDir, ".env") });
delete process.env.MONGO_URI;

import { isolateTestEnvironment, REDIS_ALIAS_ENV_VARS } from "../tests/fixtures/test-env-isolation";
isolateTestEnvironment();

import { startSharedMongo, stopSharedMongo, getSuiteUri, isHarnessRunning } from "../tests/fixtures/test-docker-mongo";
import { MongoClient } from "mongodb";
import crypto from "node:crypto";
import { spawn, ChildProcess } from "node:child_process";

let harnessInitiallyRunning = false;
let currentChild: ChildProcess | null = null;
let currentSuiteDbName: string | null = null;
let currentSuiteUri: string | null = null;
let isShuttingDown = false;

async function terminateProcessTree(child: ChildProcess, gracePeriodMs = 3000): Promise<void> {
  const pid = child.pid;
  if (!pid || child.exitCode !== null) return;

  const killGroup = (signal: NodeJS.Signals) => {
    try {
      if (process.platform !== "win32") {
        process.kill(-pid, signal);
      } else {
        child.kill(signal);
      }
    } catch {}
  };

  killGroup("SIGTERM");

  const exited = await new Promise<boolean>((resolve) => {
    if (child.exitCode !== null) return resolve(true);
    const timer = setTimeout(() => resolve(false), gracePeriodMs);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve(true);
    });
  });

  if (!exited && child.exitCode === null) {
    killGroup("SIGKILL");
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null) return resolve();
      const killTimer = setTimeout(resolve, 2000);
      child.once("exit", () => {
        clearTimeout(killTimer);
        resolve();
      });
    });
  }
}

async function dropDatabaseSafely(uri: string, dbName: string): Promise<void> {
  const cleanupClient = new MongoClient(uri, {
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 5000,
  });
  try {
    await cleanupClient.connect();
    await cleanupClient.db(dbName).dropDatabase();
  } catch (err: any) {
    console.warn(`Database cleanup failed for ${dbName}: ${err?.message || err}`);
  } finally {
    await cleanupClient.close().catch(() => {});
  }
}

async function handleSignal(signal: NodeJS.Signals) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`\nReceived ${signal}. Cleaning up owned test resources...`);

  if (currentChild) {
    await terminateProcessTree(currentChild, 2000);
    currentChild = null;
  }
  if (currentSuiteUri && currentSuiteDbName) {
    await dropDatabaseSafely(currentSuiteUri, currentSuiteDbName);
    currentSuiteUri = null;
    currentSuiteDbName = null;
  }
  if (!harnessInitiallyRunning) {
    stopSharedMongo();
  }
  process.exit(signal === "SIGINT" ? 130 : 143);
}

process.on("SIGINT", () => {
  handleSignal("SIGINT").catch(() => process.exit(130));
});
process.on("SIGTERM", () => {
  handleSignal("SIGTERM").catch(() => process.exit(143));
});

const suiteTimeoutsMs: Record<string, number> = {
  "tests/security/cors-cache-correctness.test.ts": 120000,
  "tests/security/final-adversarial-gate.ts": 90000,
  "tests/security/full-production-adversarial-suite.ts": 90000,
  "tests/security/oauth-security-hardening.test.ts": 90000,
  "tests/security/client-policy-enforcement.test.ts": 60000,
  "tests/security/pkce-enforcement.test.ts": 60000,
};

const defaultTimeoutMs = 60000;

const securityTestFiles = [
  "tests/security/p0-engine-transactions.test.ts",
  "tests/security/p0-engine-sessions.test.ts",
  "tests/security/test-client-mode-transition.ts",
  "tests/security/cross-client-refresh-matrix.ts",
  "tests/security/full-production-adversarial-suite.ts",
  "tests/security/final-adversarial-gate.ts",
  "tests/security/direct-backend-access-suite.ts",
  "tests/security/session-hijacking-suite.ts",
  "tests/security/oauth-transaction-suite.ts",
  "tests/security/credential-compromise-suite.ts",
  "tests/security/cross-tenant-matrix.ts",
  "tests/security/production-vs-development-suite.ts",
  "tests/security/deployed-consumer-suite.ts",
  "tests/security/aws-dashboard-integration-suite.ts",
  "tests/security/test-app-management-auth.ts",
  "tests/security/adversarial-role-tampering.test.ts",
  "tests/security/account-switch-e2e.test.ts",
  "tests/security/consumer-mfa-continuation.test.ts",
  "tests/security/private-app-login-isolation.test.ts",
  "tests/security/nosql-injection-boundary.test.ts",
  "tests/security/e2e-oidc-interop.test.ts",
  "tests/security/cors-cache-correctness.test.ts",
  "tests/security/cors-worker-ipc-resilience.test.ts",
  "tests/security/redis-test-isolation.test.ts",
  "tests/security/membership-lifecycle.test.ts",
  "tests/security/oauth-security-hardening.test.ts",
  "tests/security/dashboard-stats-accuracy.test.ts",
  "tests/security/auth-event-telemetry.test.ts",
  "tests/security/auth-deduplication-and-attribution.test.ts",
  "tests/security/client-policy-compatibility.test.ts",
  "tests/security/pkce-enforcement.test.ts",
  "tests/security/session-expiry-and-isolation.test.ts",
];

console.log("================================================================");
console.log("  SWYRA AUTH -- REPRODUCIBLE ALL-SECURITY TEST HARNESS");
console.log("================================================================\n");

harnessInitiallyRunning = await isHarnessRunning();
const { port } = await startSharedMongo();
console.log(`Disposable test MongoDB harness running on 127.0.0.1:${port}\n`);

let failedCount = 0;
let passedCount = 0;
const results: { file: string; passed: boolean; durationMs: number; error?: string }[] = [];

for (const testFile of securityTestFiles) {
  console.log(`\n>>> RUNNING: ${testFile}`);
  const startTime = Date.now();
  const timeoutMs = suiteTimeoutsMs[testFile] || defaultTimeoutMs;

  const cleanName = path.basename(testFile, ".ts").replace(/[^a-z0-9_]/g, "_").slice(0, 24);
  const suiteDbName = `test_sec_${cleanName}_${crypto.randomBytes(4).toString("hex")}`;
  const suiteUri = getSuiteUri(suiteDbName, port);

  currentSuiteDbName = suiteDbName;
  currentSuiteUri = suiteUri;

  const childEnv = { ...process.env };
  for (const v of REDIS_ALIAS_ENV_VARS) {
    delete childEnv[v];
  }
  for (const k of Object.keys(childEnv)) {
    if (k.includes("REDIS") && !k.startsWith("TEST_REDIS")) {
      delete childEnv[k];
    }
  }

  let timeoutFired = false;

  const exitCode = await new Promise<number>((resolve) => {
    const extraFlags = process.env.NODE_TEST_FLAGS ? process.env.NODE_TEST_FLAGS.trim().split(/\s+/) : [];
    const child = spawn(
      process.execPath,
      [...extraFlags, "--import", "tsx", testFile],
      {
        cwd: backendDir,
        env: {
          ...childEnv,
          NODE_ENV: "test",
          MONGO_URI: suiteUri,
        },
        stdio: "inherit",
        detached: process.platform !== "win32",
      }
    );

    currentChild = child;

    const timer = setTimeout(async () => {
      timeoutFired = true;
      console.error(`\n[TIMEOUT] ${testFile} exceeded ${timeoutMs}ms timeout. Terminating process tree.`);
      await terminateProcessTree(child, 3000);
      resolve(1);
    }, timeoutMs);

    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve(code ?? 1);
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      console.error(`Failed to spawn ${testFile}:`, err);
      resolve(1);
    });
  });

  if (currentChild) {
    await terminateProcessTree(currentChild, 1000);
    currentChild = null;
  }

  await dropDatabaseSafely(suiteUri, suiteDbName);
  currentSuiteDbName = null;
  currentSuiteUri = null;

  const durationMs = Date.now() - startTime;
  if (exitCode === 0 && !timeoutFired) {
    passedCount++;
    results.push({ file: testFile, passed: true, durationMs });
    console.log(`>>> PASSED: ${testFile} (${durationMs}ms)`);
  } else {
    failedCount++;
    const errMsg = timeoutFired ? "timeout exceeded" : `exit code ${exitCode}`;
    results.push({ file: testFile, passed: false, durationMs, error: errMsg });
    console.error(`>>> FAILED: ${testFile} (${errMsg})`);
  }
}

if (!harnessInitiallyRunning) {
  stopSharedMongo();
}

console.log("\n================================================================");
console.log("  SECURITY TEST SUITE EXECUTION SUMMARY");
console.log("================================================================");
for (const r of results) {
  const status = r.passed ? "[PASS]" : "[FAIL]";
  const errDetail = r.error ? ` (${r.error})` : "";
  console.log(`  ${status} ${r.file} (${r.durationMs}ms)${errDetail}`);
}
console.log(`\nTotal: ${results.length} | Passed: ${passedCount} | Failed: ${failedCount}`);
console.log("================================================================\n");

process.exit(failedCount === 0 ? 0 : 1);
