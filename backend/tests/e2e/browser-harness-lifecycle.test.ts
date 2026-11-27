import assert from "node:assert/strict";
import path from "node:path";
import { spawn } from "node:child_process";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness, killProcessGroupAndConfirm } from "../fixtures/browser-harness";

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite1 = await setupSuiteDatabase("harness_conc_1");
const suite2 = await setupSuiteDatabase("harness_conc_2");

let h1: Awaited<ReturnType<typeof startIdpAndFrontendHarness>> | null = null;
let h2: Awaited<ReturnType<typeof startIdpAndFrontendHarness>> | null = null;

try {
  // 1. Concurrent harness starts use distinct live IdP listeners with matching issuer URLs
  [h1, h2] = await Promise.all([
    startIdpAndFrontendHarness({
      backendDir,
      frontendDir,
      mongoUri: suite1.uri,
      gatewaySecret: "g".repeat(32),
      betterAuthSecret: "a".repeat(32),
    }),
    startIdpAndFrontendHarness({
      backendDir,
      frontendDir,
      mongoUri: suite2.uri,
      gatewaySecret: "g".repeat(32),
      betterAuthSecret: "b".repeat(32),
    }),
  ]);

  assert.notEqual(h1.idpUrl, h2.idpUrl, "Concurrent IdP listeners must use distinct ports");
  assert.notEqual(h1.frontendUrl, h2.frontendUrl, "Concurrent frontend listeners must use distinct ports");

  const [disc1, disc2] = await Promise.all([
    fetch(`${h1.idpUrl}/.well-known/openid-configuration`).then((r) => r.json()),
    fetch(`${h2.idpUrl}/.well-known/openid-configuration`).then((r) => r.json()),
  ]);
  assert.equal(disc1.issuer, h1.idpUrl);
  assert.equal(disc2.issuer, h2.idpUrl);

  // 2. Forced cleanup when a descendant ignores SIGTERM and parent exits early
  const parent = spawn(
    process.execPath,
    [
      "-e",
      `const { spawn } = require("node:child_process");
       spawn(process.execPath, ["-e", "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);"], { stdio: "ignore" });
       setTimeout(() => process.exit(0), 50);`,
    ],
    { detached: true, stdio: "ignore" }
  );
  const pid = parent.pid!;
  await new Promise<void>((resolve) => parent.once("exit", () => resolve()));
  await killProcessGroupAndConfirm(pid, 200, 1000);

  let esrch = false;
  try {
    process.kill(-pid, 0);
  } catch (err: any) {
    esrch = err?.code === "ESRCH";
  }
  assert.equal(esrch, true, "Process group must be gone (ESRCH) after killProcessGroupAndConfirm");

  console.log("[PASS] Browser harness concurrent listeners & descendant cleanup passed");
} finally {
  await h1?.cleanup().catch(() => {});
  await h2?.cleanup().catch(() => {});
  await suite1.cleanup().catch(() => {});
  await suite2.cleanup().catch(() => {});
}
