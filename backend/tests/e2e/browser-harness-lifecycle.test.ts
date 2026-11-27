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
let teardownError: unknown = null;

try {
  // 1. Concurrent harness starts tracked independently via Promise.allSettled
  const [res1, res2] = await Promise.allSettled([
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
  if (res1.status === "fulfilled") h1 = res1.value;
  if (res2.status === "fulfilled") h2 = res2.value;
  if (res1.status === "rejected") throw res1.reason;
  if (res2.status === "rejected") throw res2.reason;

  assert.notEqual(h1!.idpUrl, h2!.idpUrl, "Concurrent IdP listeners must use distinct ports");
  assert.notEqual(h1!.frontendUrl, h2!.frontendUrl, "Concurrent frontend listeners must use distinct ports");

  const [disc1, disc2] = await Promise.all([
    fetch(`${h1!.idpUrl}/.well-known/openid-configuration`).then((r) => r.json()),
    fetch(`${h2!.idpUrl}/.well-known/openid-configuration`).then((r) => r.json()),
  ]);
  assert.equal(disc1.issuer, h1!.idpUrl);
  assert.equal(disc2.issuer, h2!.idpUrl);

  // 2. Deterministic partial-startup regression (invalid BETTER_AUTH_SECRET causes early IdP exit)
  await assert.rejects(
    () =>
      startIdpAndFrontendHarness({
        backendDir,
        frontendDir,
        mongoUri: suite1.uri,
        gatewaySecret: "g".repeat(32),
        betterAuthSecret: "short",
      }),
    /Startup failed at stage "idp_spawn"/
  );

  // 3. Forced cleanup when a descendant installs SIGTERM handler, signals readiness, and parent exits
  const parent = spawn(
    process.execPath,
    [
      "-e",
      `const { spawn } = require("node:child_process");
       const desc = spawn(
         process.execPath,
         ["-e", "process.on('SIGTERM', () => {}); process.send?.({ type: 'descendant-ready' }); setInterval(() => {}, 1000);"],
         { stdio: ["ignore", "ignore", "ignore", "ipc"] }
       );
       desc.on("message", (msg) => {
         if (msg?.type === "descendant-ready") {
           process.send?.({ type: "descendant-ready" });
           process.exit(0);
         }
       });`,
    ],
    { detached: true, stdio: ["ignore", "ignore", "ignore", "ipc"] }
  );
  const pid = parent.pid!;
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Timeout waiting for descendant-ready")), 5000);
    parent.on("message", (msg: any) => {
      if (msg?.type === "descendant-ready") {
        clearTimeout(timer);
        resolve();
      }
    });
  });
  await new Promise<void>((resolve) => parent.once("exit", () => resolve()));

  // Assert the group is still alive after parent exits
  process.kill(-pid, 0);

  await killProcessGroupAndConfirm(pid, 200, 1000);

  let esrch = false;
  try {
    process.kill(-pid, 0);
  } catch (err: any) {
    esrch = err?.code === "ESRCH";
  }
  assert.equal(esrch, true, "Process group must be gone (ESRCH) after killProcessGroupAndConfirm");

  console.log("[PASS] Browser harness concurrent listeners, partial-startup & descendant cleanup passed");
} finally {
  if (h1) {
    await h1.cleanup().catch((err) => { teardownError = teardownError || err; });
  }
  await suite1.cleanup().catch((err) => { teardownError = teardownError || err; });
  if (h2) {
    await h2.cleanup().catch((err) => { teardownError = teardownError || err; });
  }
  await suite2.cleanup().catch((err) => { teardownError = teardownError || err; });
  if (teardownError) {
    throw teardownError;
  }
}
