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
import crypto from "node:crypto";
import { spawn, ChildProcess } from "node:child_process";
import { coordinateSuiteCleanup } from "./security-runner-lifecycle";

let harnessInitiallyRunning = false;
let currentChild: ChildProcess | null = null;
let currentSuiteDbName: string | null = null;
let currentSuiteUri: string | null = null;
let isShuttingDown = false;

async function handleSignal(signal: NodeJS.Signals) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`\nReceived ${signal}. Cleaning up owned test resources...`);

  await coordinateSuiteCleanup({
    child: currentChild,
    uri: currentSuiteUri,
    dbName: currentSuiteDbName,
    gracePeriodMs: 2000,
    deadlineMs: 5000,
  });
  currentChild = null;
  currentSuiteUri = null;
  currentSuiteDbName = null;

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
  "tests/security/membership-lifecycle.test.ts": 90000,
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
  "tests/security/auth-before-mutation-repro.test.ts",
  "tests/security/client-secret-post-auth.test.ts",
  "tests/security/open-app-membership-bypass.test.ts",
  "tests/security/private-app-policy-enforcement.test.ts",
  "tests/security/runner-lifecycle-cleanup.test.ts",
  "tests/security/session-expiry-and-isolation.test.ts",
  "tests/security/private-token-access.test.ts",
  "tests/security/open-app-bypass-flows.test.ts",
  "tests/security/userinfo-introspect-auth.test.ts",
  "tests/security/introspect-controlled-failures.test.ts",
  "tests/security/p1c-admin-policy-api.test.ts",
  "tests/security/p1c-credential-transition.test.ts",
  "tests/security/p2a-intents-and-otp.test.ts",
  "tests/security/p2a-outbox-worker-and-callbacks.test.ts",
  "tests/security/p2b-account-completion.test.ts",
  "tests/security/p2b-provisioning-bypasses.test.ts",
  "tests/security/p3-browser-session-registry.test.ts",
  "tests/security/p3-session-adapter-isolation.test.ts",
  "tests/security/p3-chooser-transaction-selection.test.ts",
  "tests/security/p3-chooser-session-binding.test.ts",
  "tests/security/p3-continuation-session-binding.test.ts",
  "tests/security/p3-owner-dashboard-contexts.test.ts",
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
  childEnv.NODE_ENV = "test";
  childEnv.BETTER_AUTH_URL = "http://localhost:3000";
  childEnv.FRONTEND_URL = "http://localhost:5174";
  childEnv.BETTER_AUTH_SECRET = "ci_better_auth_secret_minimum_32_characters_long_key";
  childEnv.INTERNAL_GATEWAY_SECRET = "ci_internal_gateway_secret_minimum_32_characters_key";
  childEnv.TRUSTED_PROXY_CIDRS = "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32";
  childEnv.GOOGLE_CLIENT_ID = "test-google-id";
  childEnv.GOOGLE_CLIENT_SECRET = "test-google-secret";

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
      try {
        await coordinateSuiteCleanup({
          child,
          uri: suiteUri,
          dbName: suiteDbName,
          gracePeriodMs: 3000,
          deadlineMs: 5000,
        });
      } catch (err: any) {
        cleanupError = err;
      }
      currentChild = null;
      currentSuiteDbName = null;
      currentSuiteUri = null;
      resolve(1);
    }, timeoutMs);

    child.on("exit", (code, signal) => {
      clearTimeout(timer);
      const effectiveCode = code !== null ? code : (signal ? 1 : 0);
      resolve(effectiveCode);
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      console.error(`Failed to spawn ${testFile}:`, err);
      resolve(1);
    });
  });

  let cleanupError: Error | null = null;
  if (currentChild || currentSuiteDbName) {
    try {
      await coordinateSuiteCleanup({
        child: currentChild,
        uri: currentSuiteUri,
        dbName: currentSuiteDbName,
        gracePeriodMs: 1000,
        deadlineMs: 5000,
      });
    } catch (err: any) {
      cleanupError = err;
    }
    currentChild = null;
    currentSuiteDbName = null;
    currentSuiteUri = null;
  }

  const durationMs = Date.now() - startTime;
  if (exitCode === 0 && !timeoutFired && !cleanupError) {
    passedCount++;
    results.push({ file: testFile, passed: true, durationMs });
    console.log(`>>> PASSED: ${testFile} (${durationMs}ms)`);
  } else {
    failedCount++;
    const errMsg = timeoutFired
      ? "timeout exceeded"
      : cleanupError
      ? `cleanup failed: ${cleanupError.message || cleanupError}`
      : `exit code ${exitCode}`;
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
