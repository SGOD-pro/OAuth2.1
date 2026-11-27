import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { ObjectId } from "mongodb";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P7.3 Deletion Cleanup & P7.4 Quarantine Restore Replay", { timeout: 60_000 }, () => {
  let db: any;
  let suiteCtx: Awaited<ReturnType<typeof setupSuiteDatabase>> | undefined;

  before(async () => {
    process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
    process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
    process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
    process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
    process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
    isolateTestEnvironment();
    process.env.NODE_ENV = "test";
    process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
    suiteCtx = await setupSuiteDatabase("p7_deletion_cleanup");
    const { getDb } = await import("../../src/db/mongo");
    db = await getDb();
  });

  after(async () => {
    const { closeDb } = await import("../../src/db/mongo");
    await closeDb();
    await suiteCtx?.cleanup();
  });

  it("transitions deleting -> key_destruction_pending -> purged, destroys keys, and prevents snapshot resurrection", async () => {
    const { InMemoryAccountKeyProvider } = await import("../../src/identity/account-key-provider");
    const { acceptOwnerDeletion } = await import("../../src/identity/deletion");
    const { processNextDeletionCleanupJob, restoreSnapshotInQuarantine } = await import("../../src/identity/deletion-cleanup");
    const { MongoProfileCollection, writeProtectedProfile } = await import("../../src/identity/protected-profile-store");
    const provider = new InMemoryAccountKeyProvider();
    const profileStore = new MongoProfileCollection(db);

    const idA = new ObjectId();
    const idB = new ObjectId();
    const snapUserA = {
      _id: idA,
      email: "cleanup_a@example.com",
      emailVerified: true,
      name: "Cleanup A",
      username: "cleanup_a",
      usernameNormalized: "cleanup_a",
      tokenVersion: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const snapUserB = {
      _id: idB,
      email: "survive_b@example.com",
      emailVerified: true,
      name: "Survive B",
      username: "survive_b",
      usernameNormalized: "survive_b",
      tokenVersion: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    await db.collection("user").insertMany([snapUserA, snapUserB]);
    const profA = await writeProtectedProfile({
      store: profileStore,
      provider,
      accountId: String(idA),
      name: "Cleanup A",
      email: "cleanup_a@example.com",
    });
    await db.collection("oauthConsent").insertOne({ userId: String(idA), clientId: "c1", scopes: ["openid"] });
    await db.collection("oauthConsent").insertOne({ userId: String(idB), clientId: "c1", scopes: ["openid"] });

    // Accept deletion for A
    await acceptOwnerDeletion({ database: db, userId: String(idA) });

    // Pass 1: deleting -> key_destruction_pending (purges profile, lookup, consents; schedules key destruction)
    const step1 = await processNextDeletionCleanupJob(db, { accountKeyProvider: provider });
    assert.equal(step1, true);
    const job1 = await db.collection("deletion_jobs").findOne({ userId: String(idA) });
    assert.equal(job1.state, "key_destruction_pending");
    assert.equal(await db.collection("identity_profiles").countDocuments({ userId: String(idA) }), 0);
    assert.equal(await db.collection("oauthConsent").countDocuments({ userId: String(idA) }), 0);
    assert.equal(await db.collection("oauthConsent").countDocuments({ userId: String(idB) }), 1);

    // Key is scheduled_destruction -> Pass 2 stays key_destruction_pending
    await processNextDeletionCleanupJob(db, { accountKeyProvider: provider });
    const jobWait = await db.collection("deletion_jobs").findOne({ userId: String(idA) });
    assert.equal(jobWait.state, "key_destruction_pending");

    // Provider completes final key destruction -> Pass 3 transitions to purged and scrubs user PII
    provider.completeDestructionForTest(String(idA), profA.nameEnvelope.keyRef);
    provider.completeDestructionForTest(String(idA), profA.emailEnvelope.keyRef);
    await processNextDeletionCleanupJob(db, { accountKeyProvider: provider });

    const jobPurged = await db.collection("deletion_jobs").findOne({ userId: String(idA) });
    assert.equal(jobPurged.state, "purged");
    const tombA = await db.collection("user").findOne({ _id: idA });
    assert.equal(tombA.status, "purged");
    assert.equal(tombA.email, undefined);
    assert.equal(tombA.username, undefined);

    // P7.4: Restore pre-deletion snapshot into quarantine -> A stays purged/denied, B survives intact
    await db.collection("user").deleteMany({});
    const restoreRes = await restoreSnapshotInQuarantine(db, [snapUserA, snapUserB]);
    assert.equal(restoreRes.quarantinedDeletedCount, 1);
    assert.equal(restoreRes.restoredActiveCount, 1);

    const afterRestoreA = await db.collection("user").findOne({ _id: idA });
    assert.equal(afterRestoreA.disabled, true);
    assert.equal(afterRestoreA.email, undefined);
    const afterRestoreB = await db.collection("user").findOne({ _id: idB });
    assert.equal(afterRestoreB.email, "survive_b@example.com");
  });
});
