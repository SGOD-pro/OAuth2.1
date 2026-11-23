import { isolateTestEnvironment, REDIS_ALIAS_ENV_VARS } from "../tests/fixtures/test-env-isolation";
isolateTestEnvironment();

import { startSharedMongo, stopSharedMongo, getSuiteUri, isHarnessRunning } from "../tests/fixtures/test-docker-mongo";
import { MongoClient } from "mongodb";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, "..");

let wasRunning = false;

process.on("SIGINT", () => {
  if (!wasRunning) {
    stopSharedMongo();
  }
  process.exit(130);
});
process.on("SIGTERM", () => {
  if (!wasRunning) {
    stopSharedMongo();
  }
  process.exit(143);
});

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
  "tests/security/redis-test-isolation.test.ts",
  "tests/security/membership-lifecycle.test.ts",
  "tests/security/oauth-security-hardening.test.ts",
  "tests/security/dashboard-stats-accuracy.test.ts",
  "tests/security/auth-event-telemetry.test.ts",
  "tests/security/auth-deduplication-and-attribution.test.ts",
  "tests/security/session-expiry-and-isolation.test.ts",
];

console.log("================================================================");
console.log("  SWYRA AUTH -- REPRODUCIBLE ALL-SECURITY TEST HARNESS");
console.log("================================================================\n");

wasRunning = await isHarnessRunning();
const { port } = await startSharedMongo();
console.log(`Disposable test MongoDB harness running on 127.0.0.1:${port}\n`);

let failedCount = 0;
let passedCount = 0;
const results: { file: string; passed: boolean; durationMs: number }[] = [];

for (const testFile of securityTestFiles) {
  console.log(`\n>>> RUNNING: ${testFile}`);
  const startTime = Date.now();

  const cleanName = path.basename(testFile, ".ts").replace(/[^a-z0-9_]/g, "_").slice(0, 24);
  const suiteDbName = `test_sec_${cleanName}_${crypto.randomBytes(4).toString("hex")}`;
  const suiteUri = getSuiteUri(suiteDbName, port);

  const childEnv = { ...process.env };
  for (const v of REDIS_ALIAS_ENV_VARS) {
    delete childEnv[v];
  }
  for (const k of Object.keys(childEnv)) {
    if (k.includes("REDIS") && !k.startsWith("TEST_REDIS")) {
      delete childEnv[k];
    }
  }

  const exitCode = await new Promise<number>((resolve) => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", testFile],
      {
        cwd: backendDir,
        env: {
          ...childEnv,
          NODE_ENV: "test",
          MONGO_URI: suiteUri,
        },
        stdio: "inherit",
      }
    );

    child.on("exit", (code) => resolve(code ?? 1));
    child.on("error", (err) => {
      console.error(`Failed to spawn ${testFile}:`, err);
      resolve(1);
    });
  });

  try {
    const cleanupClient = new MongoClient(suiteUri);
    await cleanupClient.connect();
    await cleanupClient.db(suiteDbName).dropDatabase();
    await cleanupClient.close();
  } catch {}

  const durationMs = Date.now() - startTime;
  if (exitCode === 0) {
    passedCount++;
    results.push({ file: testFile, passed: true, durationMs });
    console.log(`>>> PASSED: ${testFile} (${durationMs}ms)`);
  } else {
    failedCount++;
    results.push({ file: testFile, passed: false, durationMs });
    console.error(`>>> FAILED: ${testFile} (exit code ${exitCode})`);
  }
}

if (!wasRunning) {
  stopSharedMongo();
}

console.log("\n================================================================");
console.log("  SECURITY TEST SUITE EXECUTION SUMMARY");
console.log("================================================================");
for (const r of results) {
  console.log(`  ${r.passed ? "[PASS]" : "[FAIL]"} ${r.file} (${r.durationMs}ms)`);
}
console.log(`\nTotal: ${results.length} | Passed: ${passedCount} | Failed: ${failedCount}`);
console.log("================================================================\n");

process.exit(failedCount === 0 ? 0 : 1);
