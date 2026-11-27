import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import { MongoProfileCollection, writeProtectedProfile } from "../../src/identity/protected-profile-store";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P7.1 Durable Owner Export Jobs", { timeout: 60_000 }, () => {
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

    suiteCtx = await setupSuiteDatabase("p7_owner_export_jobs");
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
      "x-forwarded-for": "198.51.100.97, 10.0.0.1",
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
        if (kv.includes(`${name}=`)) return kv;
      }
    }
    return "";
  }

  it("binds export creation, status, and download to owner, enforces recent auth & idempotency, and blocks second browser account", async () => {
    const emailA = `p7_a_${Date.now()}@example.com`;
    const emailB = `p7_b_${Date.now()}@example.com`;
    const pass = "P71!Export#Pass123";
    const { getBrowserSessionCookieName } = await import("../../src/identity/browser-session-registry");
    const { runExportWorkerPass } = await import("../../src/workers/export");
    const cookieName = getBrowserSessionCookieName();

    await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass, name: "Export Alpha" }),
    });
    await db.collection("user").updateOne(
      { email: emailA },
      { $set: { emailVerified: true, username: "export_alpha", password: "secret_hash_value" } }
    );
    const inA = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass }),
    });
    const proof = extractCookie(inA, cookieName);

    await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailB, password: pass, name: "Export Beta" }),
    });
    await db.collection("user").updateOne(
      { email: emailB },
      { $set: { emailVerified: true, username: "export_beta" } }
    );
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

    // 1. Idempotent creation
    const create1 = await app.request("/api/identity/me/export", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA, "Idempotency-Key": "idem-p7-1" }),
      body: JSON.stringify({}),
    });
    assert.equal(create1.status, 202);
    const body1 = await create1.json();
    assert.ok(body1.jobId);
    assert.equal(body1.status, "queued");

    const create2 = await app.request("/api/identity/me/export", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA, "Idempotency-Key": "idem-p7-1" }),
      body: JSON.stringify({}),
    });
    assert.equal(create2.status, 202);
    const body2 = await create2.json();
    assert.equal(body2.jobId, body1.jobId);
    assert.equal(await db.collection("export_jobs").countDocuments({ ownerUserId: String(userA._id) }), 1);

    // 2. Download before completion fails closed (409)
    const earlyDl = await app.request(`/api/identity/me/export/${body1.jobId}/download`, {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(earlyDl.status, 409);

    // 3. Second account B in same browser cannot view status or download A's job
    const bStatus = await app.request(`/api/identity/me/export/${body1.jobId}`, {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxB }),
    });
    assert.equal(bStatus.status, 404);

    const bDl = await app.request(`/api/identity/me/export/${body1.jobId}/download`, {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxB }),
    });
    assert.equal(bDl.status, 404);

    // 4. Worker processes job
    const processed = await runExportWorkerPass(db);
    assert.equal(processed, 1);

    const statusA = await app.request(`/api/identity/me/export/${body1.jobId}`, {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(statusA.status, 200);
    const statusBody = await statusA.json();
    assert.equal(statusBody.status, "completed");
    assert.equal(statusBody.downloadAvailable, true);
    assert.ok(statusBody.downloadExpiresAt);

    // 5. Owner A downloads complete artifact; B still denied
    const dlA = await app.request(`/api/identity/me/export/${body1.jobId}/download`, {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(dlA.status, 200);
    assert.equal(dlA.headers.get("cache-control"), "no-store");
    const payload = await dlA.json();
    assert.equal(payload.ownerUserId, String(userA._id));
    assert.equal(payload.profile.email, emailA);
    assert.equal(JSON.stringify(payload).includes("secret_hash_value"), false);
    assert.equal(JSON.stringify(payload).includes(emailB), false);

    const bDlAfter = await app.request(`/api/identity/me/export/${body1.jobId}/download`, {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxB }),
    });
    assert.equal(bDlAfter.status, 404);

    // 6. Expired download window fails closed (410)
    await db.collection("export_jobs").updateOne(
      { jobId: body1.jobId },
      { $set: { downloadExpiresAt: new Date(Date.now() - 1000) } }
    );
    const expiredDl = await app.request(`/api/identity/me/export/${body1.jobId}/download`, {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(expiredDl.status, 410);

    // 7. Stale auth (old createdAt/mfaVerifiedAt, even with fresh updatedAt) is rejected on POST
    await db.collection("session").updateOne(
      { _id: new ObjectId(entryA.sessionId) },
      { $set: { createdAt: new Date(Date.now() - 10 * 60_000), updatedAt: new Date() }, $unset: { mfaVerifiedAt: "" } }
    );
    const staleCreate = await app.request("/api/identity/me/export", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA, "Idempotency-Key": "idem-p7-stale" }),
      body: JSON.stringify({}),
    });
    assert.equal(staleCreate.status, 403);
  });

  it("handles concurrent workers and lease recovery after partial failure without duplicate or stale publish", async () => {
    const { enqueueOwnerExportJob, processNextExportJob } = await import("../../src/identity/export-jobs");
    const userId = new ObjectId();
    await db.collection("user").insertOne({
      _id: userId,
      email: `conc_${Date.now()}@example.com`,
      emailVerified: true,
      name: "Concurrent User",
      username: `conc_${Date.now()}`,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const job = await enqueueOwnerExportJob(db, String(userId), { idempotencyKey: `conc-${Date.now()}` });

    // Concurrent workers race for the same job
    const [r1, r2] = await Promise.all([processNextExportJob(db), processNextExportJob(db)]);
    assert.equal(Number(r1) + Number(r2), 1);

    const finished = await db.collection("export_jobs").findOne({ jobId: job.jobId });
    assert.equal(finished.status, "completed");
    assert.equal(finished.fence, 1);

    // Crash recovery: simulate expired lease on an in-flight job
    const job2 = await enqueueOwnerExportJob(db, String(userId), { idempotencyKey: `recover-${Date.now()}` });
    await db.collection("export_jobs").updateOne(
      { jobId: job2.jobId },
      { $set: { status: "processing", leaseOwner: "crashed-worker", leaseExpiry: new Date(Date.now() - 5000), fence: 1 } }
    );
    const recovered = await processNextExportJob(db);
    assert.equal(recovered, true);
    const recoveredDoc = await db.collection("export_jobs").findOne({ jobId: job2.jobId });
    assert.equal(recoveredDoc.status, "completed");
    assert.equal(recoveredDoc.fence, 2);
  });

  it("fails closed on protected-read outage and key denial without falling back to legacy plaintext", async () => {
    const { enqueueOwnerExportJob, processNextExportJob } = await import("../../src/identity/export-jobs");
    const { createOwnerExportHandlers } = await import("../../src/routes/identity-export");

    const provider = new InMemoryAccountKeyProvider();
    const store = new MongoProfileCollection(db);
    const userId = new ObjectId();
    await db.collection("user").insertOne({
      _id: userId,
      email: "legacy_should_not_leak@example.com",
      emailVerified: true,
      name: "Legacy Name",
      username: `prot_${Date.now()}`,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    const sealed = await writeProtectedProfile({
      store,
      provider,
      accountId: String(userId),
      name: "Protected Name",
      email: "protected_real@example.com",
    });

    // Outage during worker execution -> transient requeue, no artifact, no legacy fallback
    const jobOutage = await enqueueOwnerExportJob(db, String(userId), { idempotencyKey: `outage-${Date.now()}` });
    provider.setOutage(true);
    await processNextExportJob(db, {
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "compat",
    });
    const afterOutage = await db.collection("export_jobs").findOne({ jobId: jobOutage.jobId });
    assert.equal(afterOutage.status, "queued");
    assert.equal(afterOutage.lastErrorCode, "provider_outage");
    assert.equal(afterOutage.encryptedArtifact, undefined);

    // Recover from outage -> completes with protected email
    await db.collection("export_jobs").updateOne({ jobId: jobOutage.jobId }, { $set: { nextAttemptAt: new Date(0) } });
    provider.setOutage(false);
    await processNextExportJob(db, {
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "compat",
    });
    const completed = await db.collection("export_jobs").findOne({ jobId: jobOutage.jobId });
    assert.equal(completed.status, "completed");

    // Key denial after completion blocks download with 403
    await provider.denyAccess(String(userId), completed.encryptedArtifact.envelope.keyRef, "account_deleted");
    await provider.denyAccess(String(userId), sealed.emailEnvelope.keyRef, "account_deleted");
    const testApp = new Hono();
    const handlers = createOwnerExportHandlers({
      getDb: async () => db,
      resolveOwner: async () => ({ ok: true, userId: String(userId), sessionId: "sess-test" }),
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "compat",
    });
    testApp.get("/export/:jobId/download", handlers.downloadExport);
    const deniedDl = await testApp.request(`/export/${jobOutage.jobId}/download`);
    assert.equal(deniedDl.status, 403);
    const deniedBody = await deniedDl.json();
    assert.equal(deniedBody.error, "key_denied");

    // Key denial before worker execution -> permanent failed, zero artifact, zero legacy fallback
    const jobDenied = await enqueueOwnerExportJob(db, String(userId), { idempotencyKey: `denied-${Date.now()}` });
    await processNextExportJob(db, {
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "compat",
    });
    const failedDoc = await db.collection("export_jobs").findOne({ jobId: jobDenied.jobId });
    assert.equal(failedDoc.status, "failed");
    assert.equal(failedDoc.errorCode, "key_denied");
    assert.equal(failedDoc.encryptedArtifact, undefined);
  });
});
