import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P7.2 Deletion Acceptance, Account Denial, and Revocation", { timeout: 60_000 }, () => {
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

    suiteCtx = await setupSuiteDatabase("p7_deletion_acceptance");
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
      "x-forwarded-for": "198.51.100.98, 10.0.0.1",
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

  it("enforces recent auth, denies/revokes A while keeping B active, blocks old exports, and serves PII-free status receipt", async () => {
    const emailA = `p72_a_${Date.now()}@example.com`;
    const emailB = `p72_b_${Date.now()}@example.com`;
    const pass = "P72!Delete#Pass123";
    const { getBrowserSessionCookieName } = await import("../../src/identity/browser-session-registry");
    const { runExportWorkerPass } = await import("../../src/workers/export");
    const cookieName = getBrowserSessionCookieName();

    await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass, name: "Delete Alpha" }),
    });
    await db.collection("user").updateOne({ email: emailA }, { $set: { emailVerified: true, username: "del_alpha" } });
    const inA = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass }),
    });
    const proof = extractCookie(inA, cookieName);

    await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailB, password: pass, name: "Keep Beta" }),
    });
    await db.collection("user").updateOne({ email: emailB }, { $set: { emailVerified: true, username: "keep_beta" } });
    const inB = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers({ Cookie: proof }),
      body: JSON.stringify({ email: emailB, password: pass }),
    });
    const proofAB = extractCookie(inB, cookieName) || proof;

    const userA = await db.collection("user").findOne({ email: emailA });
    const userB = await db.collection("user").findOne({ email: emailB });
    const regSet = await db.collection("browser_session_sets").findOne({ "entries.userId": String(userA._id) });
    const entryA = regSet.entries.find((e: any) => e.userId === String(userA._id));
    const entryB = regSet.entries.find((e: any) => e.userId === String(userB._id));

    const ctxARes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: headers({ Cookie: proofAB }),
      body: JSON.stringify({ entryId: entryA.entryId, purpose: "owner_dashboard" }),
    });
    const ctxA = (await ctxARes.json()).contextHandle;

    const ctxBRes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: headers({ Cookie: proofAB }),
      body: JSON.stringify({ entryId: entryB.entryId, purpose: "owner_dashboard" }),
    });
    const ctxB = (await ctxBRes.json()).contextHandle;

    // Create and complete an export for A before deletion
    const expRes = await app.request("/api/identity/me/export", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA, "Idempotency-Key": "pre-del-exp" }),
      body: JSON.stringify({}),
    });
    assert.equal(expRes.status, 202);
    const { jobId: oldExportId } = await expRes.json();
    assert.equal(await runExportWorkerPass(db), 1);

    // Seed an active token family and access token for A
    await db.collection("oauth_token_families").insertOne({
      familyId: `fam_del_${Date.now()}`,
      userId: String(userA._id),
      clientId: "client_1",
      activeTokenHash: "hash_a",
      status: "active",
      createdAt: new Date(),
    });

    // Confirmation required
    const noConfirm = await app.request("/api/identity/me/deletion", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
      body: JSON.stringify({}),
    });
    assert.equal(noConfirm.status, 400);

    // Execute deletion acceptance for A
    const delRes = await app.request("/api/identity/me/deletion", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA, "Idempotency-Key": "del-op-1" }),
      body: JSON.stringify({ confirm: true }),
    });
    assert.equal(delRes.status, 202);
    const delBody = await delRes.json();
    assert.ok(delBody.operationId);
    assert.equal(delBody.status, "deleting");
    assert.equal(JSON.stringify(delBody).includes(emailA), false);
    assert.equal(JSON.stringify(delBody).includes("del_alpha"), false);

    const receiptCookie = extractCookie(delRes, "swyra_deletion_receipt");
    assert.ok(receiptCookie, "Deletion receipt cookie must be set");

    // A's session, context, token family, and old export are immediately denied/revoked
    const afterMe = await app.request("/api/identity/me", {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(afterMe.status, 401);

    const afterSignIn = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass }),
    });
    assert.equal(afterSignIn.status, 401);

    const famAfter = await db.collection("oauth_token_families").findOne({ userId: String(userA._id) });
    assert.equal(famAfter.status, "revoked");

    const oldExpAfter = await db.collection("export_jobs").findOne({ jobId: oldExportId });
    assert.equal(oldExpAfter.status, "suppressed");
    assert.equal(oldExpAfter.encryptedArtifact, undefined);

    // Status receipt works without owner session and exposes no PII
    const statusRes = await app.request("/api/identity/deletion/status", {
      method: "GET",
      headers: headers({ Cookie: receiptCookie }),
    });
    assert.equal(statusRes.status, 200);
    const statusBody = await statusRes.json();
    assert.equal(statusBody.operationId, delBody.operationId);
    assert.equal(statusBody.status, "deleting");
    assert.equal(JSON.stringify(statusBody).includes(emailA), false);
    assert.equal(JSON.stringify(statusBody).includes(String(userA._id)), false);

    // Missing receipt cookie fails closed (401)
    const noReceipt = await app.request("/api/identity/deletion/status", {
      method: "GET",
      headers: headers(),
    });
    assert.equal(noReceipt.status, 401);

    // Account B in the same browser stays active
    const bMe = await app.request("/api/identity/me", {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxB }),
    });
    assert.equal(bMe.status, 200);
    const bBody = await bMe.json();
    assert.equal(bBody.email, emailB);
  });

  it("blocks racing export worker and issuance fence after deletion commits, and converges on partial failure retry", async () => {
    const { createDeletionHandlers } = await import("../../src/routes/identity-deletion");
    const { MongoDeletionLedgerStore } = await import("../../src/identity/deletion");
    const { enqueueOwnerExportJob, processNextExportJob } = await import("../../src/identity/export-jobs");
    const { commitUserIssuanceLinearization } = await import("../../src/routes/auth-client-fence");

    const userId = new ObjectId();
    await db.collection("user").insertOne({
      _id: userId,
      email: `race_${Date.now()}@example.com`,
      emailVerified: true,
      name: "Race User",
      username: `race_${Date.now()}`,
      tokenVersion: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // 1. Partial failure: ledger outage -> returns 503, no 202, no deletion_jobs record
    const failingLedger = {
      async recordDeletionDenial() {
        throw new Error("Ledger unavailable");
      },
      async isDenied() {
        return false;
      },
    };
    const testApp = new Hono();
    const failHandlers = createDeletionHandlers({
      getDb: async () => db,
      resolveOwner: async () => ({ ok: true, userId: String(userId), sessionId: "sess-1" }),
      requireRecentAuth: async () => ({ ok: true }),
      ledgerStore: failingLedger,
    });
    testApp.post("/deletion", failHandlers.requestDeletion);

    const failRes = await testApp.request("/deletion", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    });
    assert.equal(failRes.status, 503);
    assert.equal(await db.collection("deletion_jobs").countDocuments({ userId: String(userId) }), 0);

    // 2. Partial failure: ledger succeeds, DB transaction fails -> returns 503; retry converges on same operationId
    const { client } = await import("../../src/db/mongo");
    const realLedger = new MongoDeletionLedgerStore(db);
    let failTx = true;
    const txHandlers = createDeletionHandlers({
      getDb: async () => db,
      startSession: () =>
        failTx
          ? {
              async withTransaction() {
                throw new Error("Simulated DB tx failure");
              },
              async endSession() {},
            }
          : client.startSession(),
      resolveOwner: async () => ({ ok: true, userId: String(userId), sessionId: "sess-1" }),
      requireRecentAuth: async () => ({ ok: true }),
      ledgerStore: realLedger,
    });
    const retryApp = new Hono();
    retryApp.post("/deletion", txHandlers.requestDeletion);

    const partialRes = await retryApp.request("/deletion", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    });
    assert.equal(partialRes.status, 503);
    const ledgerEntry = await db.collection("deletion_ledger").findOne({ userId: String(userId) });
    assert.ok(ledgerEntry, "Ledger entry must exist after Step A");

    failTx = false;
    const [retry1, retry2] = await Promise.all([
      retryApp.request("/deletion", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ confirm: true }),
      }),
      retryApp.request("/deletion", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ confirm: true }),
      }),
    ]);
    assert.equal(retry1.status, 202);
    assert.equal(retry2.status, 202);
    const b1 = await retry1.json();
    const b2 = await retry2.json();
    assert.equal(b1.operationId, ledgerEntry.operationId);
    assert.equal(b2.operationId, ledgerEntry.operationId);
    assert.equal(await db.collection("deletion_jobs").countDocuments({ userId: String(userId) }), 1);

    // 3. Issuance fence loses against committed deletion
    const fenceOk = await commitUserIssuanceLinearization(db, String(userId), 1);
    assert.equal(fenceOk, false);

    // 4. Export worker racing deletion cannot publish usable artifact
    const expJob = await enqueueOwnerExportJob(db, String(userId), { idempotencyKey: `race-exp-${Date.now()}` });
    await processNextExportJob(db);
    const expDoc = await db.collection("export_jobs").findOne({ jobId: expJob.jobId });
    assert.notEqual(expDoc.status, "completed");
    assert.equal(expDoc.encryptedArtifact, undefined);
  });
});
