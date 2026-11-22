process.env.NODE_ENV = "test";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.INTERNAL_GATEWAY_SECRET = "g".repeat(32);

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Worker } from "node:worker_threads";
import { MongoMemoryServer } from "mongodb-memory-server";
import { MongoClient, Db } from "mongodb";

describe("OAuth V2: Ownership-Safe Refresh Lease and Fencing Deterministic Suite", () => {
  let mongod: MongoMemoryServer;
  let mongoClient: MongoClient;
  let db: Db;
  let mongoUri: string;

  before(async () => {
    mongod = await MongoMemoryServer.create({ binary: { version: "7.0.24" } });
    mongoUri = mongod.getUri();
    process.env.MONGO_URI = mongoUri;
    mongoClient = new MongoClient(mongoUri);
    await mongoClient.connect();
    db = mongoClient.db();
  });

  after(async () => {
    try {
      const { closeDb } = await import("../../src/db/mongo");
      await closeDb();
    } catch {}
    await mongoClient?.close();
    await mongod?.stop();
  });

  function createWorker(clientId: string, incomingHash: string): Worker {
    const workerScript = `
      import { parentPort, workerData } from "node:worker_threads";
      import { MongoClient } from "mongodb";
      import { claimRotationRights } from "./src/routes/auth-token-claim";
      import { verifyAndRotateTokenFamily } from "./src/db/token-families";

      const { mongoUri, clientId, incomingHash } = workerData;
      const client = new MongoClient(mongoUri);
      await client.connect();
      const db = client.db();

      let leaseOwner;

      parentPort.on("message", async (msg) => {
        try {
          if (msg.action === "claim") {
            const mockC = { json: (body, status) => ({ body, status }) };
            const res = await claimRotationRights(mockC, db, clientId, {}, incomingHash);
            if (res.claimed) {
              leaseOwner = res.leaseOwner;
              parentPort.postMessage({ status: "claimed", leaseOwner });
            } else {
              parentPort.postMessage({ status: "claim_failed", response: res.response });
            }
          } else if (msg.action === "release") {
            const filter = { activeTokenHash: incomingHash, clientId, rotating: true };
            if (leaseOwner) filter.rotationOwner = leaseOwner;
            const updateRes = await db.collection("oauth_token_families").updateOne(
              filter,
              { $set: { rotating: false }, $unset: { rotationOwner: "" } }
            );
            parentPort.postMessage({ status: "released", modifiedCount: updateRes.modifiedCount });
          } else if (msg.action === "rotate") {
            const rotationResult = await verifyAndRotateTokenFamily(
              incomingHash,
              msg.newHash,
              msg.userId,
              msg.nowMs || Date.now(),
              clientId,
              1,
              leaseOwner
            );
            parentPort.postMessage({ status: "rotated", rotationResult });
          } else if (msg.action === "close") {
            await client.close();
            parentPort.postMessage({ status: "closed" });
          }
        } catch (err) {
          parentPort.postMessage({ status: "error", error: err.message });
        }
      });
    `;

    return new Worker(workerScript, {
      eval: true,
      execArgv: ["--import", "tsx"],
      env: { ...process.env, MONGO_URI: mongoUri },
      workerData: { mongoUri, clientId, incomingHash },
    });
  }

  function sendWorker(worker: Worker, msg: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const handler = (m: any) => {
        worker.off("message", handler);
        if (m.status === "error") reject(new Error(m.error));
        else resolve(m);
      };
      worker.on("message", handler);
      worker.postMessage(msg);
    });
  }

  it("proves ownership-safe refresh lease fencing under pause, expiration, and stale cleanup", async () => {
    const rawToken = "initial-refresh-token-test-fencing";
    const initialHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const clientId = "client-fencing-test";
    const userId = "user-fencing-1";

    await db.collection("oauth_token_families").insertOne({
      familyId: "fam-fence-1",
      clientId,
      userId,
      activeTokenHash: initialHash,
      consumedTokenHashes: [],
      status: "active",
      createdAt: new Date(),
      updatedAt: new Date(),
      tokenVersion: 1,
    });

    const workerA = createWorker(clientId, initialHash);
    const workerB = createWorker(clientId, initialHash);

    try {
      // 1. Worker A acquires rotation lease
      const claimA = await sendWorker(workerA, { action: "claim" });
      assert.equal(claimA.status, "claimed");
      const leaseOwnerA = claimA.leaseOwner;
      assert.ok(leaseOwnerA, "Worker A must receive unique leaseOwner fencing token");

      let fam = await db.collection("oauth_token_families").findOne({ activeTokenHash: initialHash });
      assert.equal(fam?.rotating, true);
      assert.equal(fam?.rotationOwner, leaseOwnerA);

      // 2. Pause Worker A and expire its lease in MongoDB (> 15 seconds)
      await db.collection("oauth_token_families").updateOne(
        { activeTokenHash: initialHash },
        { $set: { rotatingAt: new Date(Date.now() - 20000) } }
      );

      // 3. Worker B acquires the expired lease
      const claimB = await sendWorker(workerB, { action: "claim" });
      assert.equal(claimB.status, "claimed");
      const leaseOwnerB = claimB.leaseOwner;
      assert.ok(leaseOwnerB);
      assert.notEqual(leaseOwnerB, leaseOwnerA, "Worker B must receive a distinct leaseOwner");

      fam = await db.collection("oauth_token_families").findOne({ activeTokenHash: initialHash });
      assert.equal(fam?.rotating, true);
      assert.equal(fam?.rotationOwner, leaseOwnerB, "DB rotationOwner must be bound to Worker B");

      // 4. Resume Worker A to execute failure cleanup (simulating delayed catch/finally block)
      const releaseA = await sendWorker(workerA, { action: "release" });
      assert.equal(releaseA.status, "released");
      assert.equal(releaseA.modifiedCount, 0, "Worker A stale release must not modify document");

      fam = await db.collection("oauth_token_families").findOne({ activeTokenHash: initialHash });
      assert.equal(fam?.rotating, true, "Worker B lease must be retained");
      assert.equal(fam?.rotationOwner, leaseOwnerB, "Worker B must remain lease owner");

      // 5. Stale Worker A attempts to commit rotation
      const rotateA = await sendWorker(workerA, {
        action: "rotate",
        newHash: "stale-hash-a",
        userId,
      });
      assert.equal(rotateA.status, "rotated");
      assert.equal(rotateA.rotationResult.valid, false, "Stale Worker A rotation must be rejected");

      fam = await db.collection("oauth_token_families").findOne({ activeTokenHash: initialHash });
      assert.equal(fam?.activeTokenHash, initialHash, "Active token hash must remain initialHash");
      assert.equal(fam?.rotationOwner, leaseOwnerB, "Worker B lease must still be intact");

      // 6. Active Worker B commits rotation successfully
      const rotateB = await sendWorker(workerB, {
        action: "rotate",
        newHash: "valid-rotated-hash-b",
        userId,
      });
      assert.equal(rotateB.status, "rotated");
      assert.equal(rotateB.rotationResult.valid, true, "Worker B rotation must succeed");

      const updatedFam = await db.collection("oauth_token_families").findOne({ familyId: "fam-fence-1" });
      assert.equal(updatedFam?.activeTokenHash, "valid-rotated-hash-b");
      assert.ok(updatedFam?.consumedTokenHashes.includes(initialHash));
      assert.equal(updatedFam?.rotating, false);
      assert.equal(updatedFam?.rotationOwner, undefined, "rotationOwner must be unset upon rotation commit");

      // 7. Stale Worker A attempts replay of consumed token after grace window
      const replayA = await sendWorker(workerA, {
        action: "rotate",
        newHash: "replay-hash-a",
        userId,
        nowMs: Date.now() + 3000,
      });
      assert.equal(replayA.rotationResult.replayed, true, "Replaying initial token must trigger replay detection");

      const revokedFam = await db.collection("oauth_token_families").findOne({ familyId: "fam-fence-1" });
      assert.equal(revokedFam?.status, "revoked", "Family must be revoked after replay detection");
    } finally {
      await sendWorker(workerA, { action: "close" }).catch(() => {});
      await sendWorker(workerB, { action: "close" }).catch(() => {});
      await workerA.terminate();
      await workerB.terminate();
    }
  });

  it("proves handleRefreshTokenGrant releases lock on thrown error", async () => {
    const { handleRefreshTokenGrant } = await import("../../src/routes/auth-token-refresh");
    const rawToken = "error-refresh-token-direct";
    const initialHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const clientId = "client-error-direct";
    const userId = "user-error-1";

    await db.collection("user").insertOne({
      _id: userId as any,
      id: userId,
      email: "user-error@example.com",
    });

    await db.collection("oauth_token_families").insertOne({
      familyId: "fam-error-direct",
      clientId,
      userId,
      activeTokenHash: initialHash,
      consumedTokenHashes: [],
      status: "active",
      createdAt: new Date(),
      updatedAt: new Date(),
      tokenVersion: 1,
    });

    const mockC = { json: (body: any, status: number) => ({ body, status }) };
    const mockContext: any = {
      canonicalClientId: clientId,
      clientDoc: { isPublic: true },
      reqToForward: { notARequest: true },
    };

    await assert.rejects(async () => {
      await handleRefreshTokenGrant(mockC, mockContext, rawToken);
    });

    const fam = await db.collection("oauth_token_families").findOne({ activeTokenHash: initialHash });
    assert.equal(fam?.rotating, false, "Rotation lock must be released on thrown error");
    assert.equal(fam?.rotationOwner, undefined, "rotationOwner must be unset on thrown error");
  });
});
