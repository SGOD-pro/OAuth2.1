import assert from "node:assert/strict";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness, killProcessGroupAndConfirm } from "../fixtures/browser-harness";

type CleanupResult = { hasError: false } | { hasError: true; error: unknown };

async function cleanupSuiteWithHarness(
  harness: { cleanup: () => Promise<void> } | null,
  suite: { cleanup: () => Promise<void> }
): Promise<CleanupResult> {
  let firstError: CleanupResult = { hasError: false };
  if (harness) {
    try {
      await harness.cleanup();
    } catch (err) {
      firstError = { hasError: true, error: err };
    }
  }
  try {
    await suite.cleanup();
  } catch (err) {
    if (!firstError.hasError) {
      firstError = { hasError: true, error: err };
    }
  }
  return firstError;
}

async function probeTcpClosed(port: number): Promise<string> {
  return new Promise<string>((resolve) => {
    const sock = net.createConnection({ port, host: "127.0.0.1" }, () => {
      sock.destroy();
      resolve("CONNECTED");
    });
    sock.on("error", (err: any) => {
      sock.destroy();
      resolve(err?.code || "ERROR");
    });
    sock.setTimeout(1000, () => {
      sock.destroy();
      resolve("TIMEOUT");
    });
  });
}

function isProcessGroupGone(pid: number): boolean {
  try {
    process.kill(-pid, 0);
    return false;
  } catch (err: any) {
    if (err?.code === "ESRCH") return true;
    throw err;
  }
}

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite1 = await setupSuiteDatabase("harness_conc_1");
const suite2 = await setupSuiteDatabase("harness_conc_2");

let h1: Awaited<ReturnType<typeof startIdpAndFrontendHarness>> | null = null;
let h2: Awaited<ReturnType<typeof startIdpAndFrontendHarness>> | null = null;

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

  // 2. Deterministic partial-startup regression with direct resource release assertions
  let allocated: { frontendPort: number; idpPid: number } | null = null;
  await assert.rejects(
    () =>
      startIdpAndFrontendHarness({
        backendDir,
        frontendDir,
        mongoUri: suite1.uri,
        gatewaySecret: "g".repeat(32),
        betterAuthSecret: "short",
        onResourcesAllocated: (info) => {
          allocated = info;
        },
      }),
    /Startup failed at stage "idp_spawn"/
  );
  assert.ok(allocated && allocated.frontendPort > 0 && allocated.idpPid > 0, "Resources must have been allocated before failure");

  assert.equal(
    await probeTcpClosed(allocated!.frontendPort),
    "ECONNREFUSED",
    "Frontend listener must be closed after partial-startup failure"
  );
  assert.equal(isProcessGroupGone(allocated!.idpPid), true, "IdP process group must be gone (ESRCH) after partial-startup failure");

  // 2b. Deterministic partial-startup regression where IdP process group stays alive on failure
  let survivingAllocated: { frontendPort: number; idpPid: number } | null = null;
  let simulatedFailureThrew = false;
  try {
    await assert.rejects(
      () =>
        startIdpAndFrontendHarness({
          backendDir,
          frontendDir,
          mongoUri: suite1.uri,
          gatewaySecret: "g".repeat(32),
          betterAuthSecret: "a".repeat(32),
          idpArgs: [
            "-e",
            "process.send?.({ type: 'error', message: 'simulated_idp_failure' }); setInterval(() => {}, 1000);",
          ],
          onResourcesAllocated: (info) => {
            survivingAllocated = info;
          },
        }),
      /Startup failed at stage "idp_spawn": simulated_idp_failure/
    );
    assert.ok(
      survivingAllocated && survivingAllocated.frontendPort > 0 && survivingAllocated.idpPid > 0,
      "Resources must have been allocated before simulated failure"
    );
    assert.equal(
      await probeTcpClosed(survivingAllocated!.frontendPort),
      "ECONNREFUSED",
      "Frontend listener must be closed after simulated IdP failure"
    );
    assert.equal(
      isProcessGroupGone(survivingAllocated!.idpPid),
      true,
      "Surviving IdP process group must be killed (ESRCH) by startup failure cleanup"
    );
  } catch (err) {
    simulatedFailureThrew = true;
    throw err;
  } finally {
    const pidToCheck = (survivingAllocated as { frontendPort: number; idpPid: number } | null)?.idpPid;
    if (pidToCheck && !isProcessGroupGone(pidToCheck)) {
      try {
        await killProcessGroupAndConfirm(pidToCheck, 200, 1000);
        assert.equal(
          isProcessGroupGone(pidToCheck),
          true,
          "Fallback cleanup must remove surviving IdP process group (ESRCH)"
        );
      } catch (fallbackErr) {
        if (!simulatedFailureThrew) {
          throw fallbackErr;
        }
      }
    }
  }

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

  process.kill(-pid, 0);
  await killProcessGroupAndConfirm(pid, 200, 1000);

  assert.equal(isProcessGroupGone(pid), true, "Process group must be gone (ESRCH) after killProcessGroupAndConfirm");

  // 4. Per-suite teardown contract: harness failure still attempts its own DB drop, peer still cleans up, first error surfaces (including undefined)
  let s1Dropped = false;
  let h2Cleaned = false;
  let s2Cleaned = false;
  const teardownRes1 = await cleanupSuiteWithHarness(
    { cleanup: async () => { throw new Error("harness_1_teardown_boom"); } },
    { cleanup: async () => { s1Dropped = true; } }
  );
  const teardownRes2 = await cleanupSuiteWithHarness(
    { cleanup: async () => { h2Cleaned = true; } },
    { cleanup: async () => { s2Cleaned = true; } }
  );
  assert.equal(s1Dropped, true, "Suite 1 DB cleanup must still run after harness 1 teardown fails");
  assert.equal(h2Cleaned, true, "Peer harness 2 must still clean up");
  assert.equal(s2Cleaned, true, "Peer suite 2 DB must still clean up");
  assert.equal(teardownRes1.hasError, true);
  assert.match(String((teardownRes1.error as Error)?.message), /harness_1_teardown_boom/);
  assert.equal(teardownRes2.hasError, false);

  const undefRes = await cleanupSuiteWithHarness(
    { cleanup: async () => Promise.reject(undefined) },
    { cleanup: async () => {} }
  );
  assert.equal(undefRes.hasError, true, "Rejection with undefined must still be recorded as a teardown failure");

  console.log("[PASS] Browser harness concurrent listeners, partial-startup, teardown-order & descendant cleanup passed");
} finally {
  const res1 = await cleanupSuiteWithHarness(h1, suite1);
  const res2 = await cleanupSuiteWithHarness(h2, suite2);
  if (res1.hasError) {
    throw res1.error;
  }
  if (res2.hasError) {
    throw res2.error;
  }
}
