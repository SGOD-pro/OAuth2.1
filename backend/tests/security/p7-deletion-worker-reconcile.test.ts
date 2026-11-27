import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

function runWorkerProcess(args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const backendDir = path.resolve(import.meta.dirname, "../..");
    const tsxBin = path.join(backendDir, "node_modules/.bin/tsx");
    const child = spawn(tsxBin, ["src/workers/deletion.ts", ...args], {
      cwd: backendDir,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d.toString(); });
    child.stderr.on("data", (d) => { stderr += d.toString(); });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("P7.2 Automatic Deletion Reconciliation Worker", { timeout: 60_000 }, () => {
  let app: any;
  let db: any;
  let origin: string;
  let gatewaySecret: string;
  let suiteCtx: Awaited<ReturnType<typeof setupSuiteDatabase>> | undefined;

  before(async () => {
    process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
    process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
    process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
    process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
    process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
    isolateTestEnvironment();
    process.env.NODE_ENV = "test";
    process.env.ALLOW_PUBLIC_SIGNUP = "true";
    process.env.REQUIRE_EMAIL_VERIFICATION = "false";
    process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
    gatewaySecret = process.env.INTERNAL_GATEWAY_SECRET;
    origin = process.env.FRONTEND_URL;

    suiteCtx = await setupSuiteDatabase("p7_deletion_worker");
    const { getDb } = await import("../../src/db/mongo");
    db = await getDb();
    const { default: appInstance } = await import("../../src/app");
    app = appInstance;
  });

  after(async () => {
    const { closeDb } = await import("../../src/db/mongo");
    await closeDb();
    await suiteCtx?.cleanup();
  });

  function headers(extra: Record<string, string> = {}) {
    return {
      "Content-Type": "application/json",
      Origin: origin,
      "x-gateway-secret": gatewaySecret,
      "x-csrf-token": "any",
      "x-forwarded-for": "198.51.100.101, 10.0.0.1",
      ...extra,
    };
  }

  function extractCookie(res: Response, name: string): string {
    const raw = (res.headers as any).getSetCookie
      ? (res.headers as any).getSetCookie()
      : [res.headers.get("set-cookie") || ""];
    for (const item of raw) {
      for (const part of String(item).split(/,(?=\s*[^;]+=[^;]+)/)) {
        const kv = part.trim().split(";")[0].trim();
        if (kv.startsWith(`${name}=`)) return kv;
      }
    }
    return "";
  }

  it("restarts standalone deletion worker entrypoint to complete Step B without owner session and handles overlapping runs", async () => {
    const emailA = `p72_wrk_a_${Date.now()}@example.com`;
    const pass = "P72!Worker#Pass123";
    const { getBrowserSessionCookieName } = await import("../../src/identity/browser-session-registry");
    const { createDeletionHandlers } = await import("../../src/routes/identity-deletion");
    const { startDeletionReconcileWorker } = await import("../../src/workers/deletion");
    const cookieName = getBrowserSessionCookieName();

    await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass, name: "Worker Alpha" }),
    });
    await db.collection("user").updateOne({ email: emailA }, { $set: { emailVerified: true, username: "wrk_alpha" } });
    const inA = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass }),
    });
    const proofA = extractCookie(inA, cookieName);
    const userA = await db.collection("user").findOne({ email: emailA });
    const regSet = await db.collection("browser_session_sets").findOne({ "entries.userId": String(userA._id) });
    const entryA = regSet.entries.find((e: any) => e.userId === String(userA._id));

    const ctxARes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: headers({ Cookie: proofA }),
      body: JSON.stringify({ entryId: entryA.entryId, purpose: "owner_dashboard" }),
    });
    const ctxA = (await ctxARes.json()).contextHandle;

    // Persist Step A and force Step B to fail
    const failingApp = new Hono();
    const handlers = createDeletionHandlers({
      getDb: async () => db,
      startSession: () => ({
        async withTransaction() {
          throw new Error("Forced Step B failure");
        },
        async endSession() {},
      }),
    });
    failingApp.post("/api/identity/me/deletion", handlers.requestDeletion);

    const failRes = await failingApp.request("/api/identity/me/deletion", {
      method: "POST",
      headers: headers({ Cookie: proofA, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ confirm: true }),
    });
    assert.equal(failRes.status, 503);
    assert.equal(extractCookie(failRes, "swyra_deletion_receipt"), "");

    // Ledger denial is active before worker runs
    const meBefore = await app.request("/api/identity/me", {
      method: "GET",
      headers: headers({ Cookie: proofA, "X-Identity-Context": ctxA }),
    });
    assert.equal(meBefore.status, 401);

    // Run normal worker entrypoint in a fresh child process (no owner session, no shared memory)
    const workerRun = await runWorkerProcess(["--once"], { ...process.env, MONGO_URI: suiteCtx!.uri });
    assert.equal(workerRun.code, 0, `Worker failed: ${workerRun.stderr}`);

    const userAfter = await db.collection("user").findOne({ _id: userA._id });
    assert.ok(["deleting", "key_destruction_pending", "purged"].includes(userAfter.status));
    assert.equal(userAfter.disabled, true);
    assert.equal(userAfter.tokenVersion, (userA.tokenVersion ?? 1) + 1);

    const ledgerA = await db.collection("deletion_ledger").findOne({ userId: String(userA._id) });
    const jobsA = await db.collection("deletion_jobs").find({ userId: String(userA._id) }).toArray();
    assert.equal(jobsA.length, 1);
    assert.equal(jobsA[0].operationId, ledgerA.operationId);

    // Second user with pending ledger denial: test overlapping periodic worker runs
    const idC = new ObjectId();
    await db.collection("user").insertOne({
      _id: idC,
      email: `p72_wrk_c_${Date.now()}@example.com`,
      emailVerified: true,
      name: "Worker Charlie",
      username: `wrk_c_${Date.now()}`,
      tokenVersion: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await db.collection("deletion_ledger").insertOne({
      userId: String(idC),
      operationId: `del_overlap_${Date.now()}`,
      denialVersion: 1,
      status: "deleting",
      committedAt: new Date(),
    });

    const worker = startDeletionReconcileWorker({
      intervalMs: 60_000,
      getDbFn: async () => db,
    });
    try {
      const [r1, r2] = await Promise.all([worker.triggerNow(), worker.triggerNow()]);
      assert.equal(r1.reconciledCount + r2.reconciledCount, 1);
    } finally {
      worker.stop();
    }

    const userC = await db.collection("user").findOne({ _id: idC });
    assert.ok(["deleting", "key_destruction_pending", "purged"].includes(userC.status));
    assert.equal(userC.tokenVersion, 2);
    assert.equal(await db.collection("deletion_jobs").countDocuments({ userId: String(idC) }), 1);

    // Ledger denial remains effective throughout and after recovery
    const signInA = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass }),
    });
    assert.equal(signInA.status, 401);
  });
});
