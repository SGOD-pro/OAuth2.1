import { isolateTestEnvironment, REDIS_ALIAS_ENV_VARS } from "../tests/fixtures/test-env-isolation";
isolateTestEnvironment();

import { MongoMemoryServer } from "mongodb-memory-server";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, "..");

const securityTestFiles = [
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
  "tests/security/membership-lifecycle.test.ts",
];

console.log("================================================================");
console.log("  SWYRA AUTH -- REPRODUCIBLE ALL-SECURITY TEST HARNESS");
console.log("================================================================\n");

const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();
console.log(`Disposable in-memory MongoDB started at: ${mongoUri}\n`);

let failedCount = 0;
let passedCount = 0;
const results: { file: string; passed: boolean; durationMs: number }[] = [];

for (const testFile of securityTestFiles) {
  console.log(`\n>>> RUNNING: ${testFile}`);
  const startTime = Date.now();

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
      [path.join(backendDir, "node_modules/tsx/dist/cli.mjs"), testFile],
      {
        cwd: backendDir,
        env: {
          ...childEnv,
          NODE_ENV: "test",
          MONGO_URI: mongoUri,
          BETTER_AUTH_SECRET: "a".repeat(32),
          BETTER_AUTH_URL: "http://127.0.0.1:3000",
          FRONTEND_URL: "http://127.0.0.1:5174",
          INTERNAL_GATEWAY_SECRET: "g".repeat(32),
          GOOGLE_CLIENT_ID: "test-google-id",
          GOOGLE_CLIENT_SECRET: "test-google-secret",
          TRUSTED_PROXY_CIDRS: "127.0.0.1/32,10.0.0.0/8",
          AUTH_PUBLIC_SIGNUP_ENABLED: "true",
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

await mongod.stop();

console.log("\n================================================================");
console.log("  SECURITY TEST SUITE EXECUTION SUMMARY");
console.log("================================================================");
for (const r of results) {
  console.log(`  ${r.passed ? "[PASS]" : "[FAIL]"} ${r.file} (${r.durationMs}ms)`);
}
console.log(`\nTotal: ${results.length} | Passed: ${passedCount} | Failed: ${failedCount}`);
console.log("================================================================\n");

process.exit(failedCount === 0 ? 0 : 1);
