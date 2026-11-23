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
import { MongoClient, Db } from "mongodb";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2: Ownership-Safe Refresh Lease and Fencing Deterministic Suite", () => {
  let suite: SuiteDatabaseContext;
  let mongoClient: MongoClient;
  let db: Db;
  let mongoUri: string;

  before(async () => {
    suite = await setupSuiteDatabase("refresh_lease_fencing");
    mongoUri = suite.uri;
    mongoClient = suite.client;
    db = mongoClient.db();
    const { getIdpSigningKey } = await import("../../src/routes/auth");
    await getIdpSigningKey();
  });

  after(async () => {
    try {
      const { closeDb } = await import("../../src/db/mongo");
      await closeDb();
    } catch {}
    if (suite) await suite.cleanup();
  });

  function createWorker(clientId: string, incomingHash: string, userId: string): Worker {
    const workerScript = `
      import { parentPort, workerData } from "node:worker_threads";
      import { MongoClient } from "mongodb";
      import { authProvider } from "./src/utils/auth";
      import { handleRefreshTokenGrant } from "./src/routes/auth-token-refresh";
      import { setTokenBarrierHookForTesting } from "./src/routes/auth-keys";
      import { verifyAndRotateTokenFamily } from "./src/db/token-families";

      const { mongoUri, clientId, incomingHash, userId } = workerData;
      const client = new MongoClient(mongoUri);
      await client.connect();
      const db = client.db();
      let leaseOwner;

      parentPort.on("message", async (msg) => {
        try {
          if (msg.action === "refresh") {
            setTokenBarrierHookForTesting(async (stage, owner) => {
              if (stage === "after_lease_claim") {
                leaseOwner = owner;
                parentPort.postMessage({ status: "claimed_and_paused", leaseOwner });
                await new Promise((resolve, reject) => {
                  const onResume = (m) => {
                    if (m.action === "resume") {
                      parentPort.off("message", onResume);
                      if (m.fail) reject(new Error("Worker controlled failure after claim"));
                      else resolve();
                    }
                  };
                  parentPort.on("message", onResume);
                });
              }
            });

            if (msg.mockSuccess) {
              authProvider.handler = async () => new Response(
                JSON.stringify({
                  access_token: "mock-access-token",
                  refresh_token: msg.newRefreshToken || "new-raw-refresh-b",
                  expires_in: 900,
                  token_type: "Bearer",
                }),
                { status: 200, headers: { "Content-Type": "application/json" } }
              );
            }

            const mockC = { json: (body, status) => ({ body, status }) };
            const mockContext = {
              canonicalClientId: clientId,
              clientDoc: { isPublic: true },
              reqToForward: { url: "http://localhost:3000" },
            };

            const res = await handleRefreshTokenGrant(mockC, mockContext, msg.refreshToken);
            parentPort.postMessage({ status: "finished", response: res, leaseOwner });
          } else if (msg.action === "stale_rotate") {
            const rot = await verifyAndRotateTokenFamily(
              incomingHash, msg.newHash, userId, Date.now(), clientId, 1, msg.leaseOwner
            );
            parentPort.postMessage({ status: "rotated", rotationResult: rot });
          } else if (msg.action === "close") {
            await client.close();
            parentPort.postMessage({ status: "closed" });
          }
        } catch (err) {
          parentPort.postMessage({ status: "error", error: err.message, leaseOwner });
        }
      });
    `;

    return new Worker(workerScript, {
      eval: true,
      execArgv: ["--import", "tsx"],
      env: { ...process.env, MONGO_URI: mongoUri },
      workerData: { mongoUri, clientId, incomingHash, userId },
    });
  }

  function waitForWorkerStatus(worker: Worker, expectedStatus: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const handler = (m: any) => {
        if (m.status === expectedStatus) { worker.off("message", handler); resolve(m); }
        else if (m.status === "error") { worker.off("message", handler); reject(new Error(m.error)); }
      };
      worker.on("message", handler);
    });
  }

  function sendWorker(worker: Worker, msg: any): Promise<any> {
    return new Promise((resolve) => {
      const handler = (m: any) => {
        if (m.status === "finished" || m.status === "rotated" || m.status === "closed" || m.status === "error") {
          worker.off("message", handler);
          resolve(m);
        }
      };
      worker.on("message", handler);
      worker.postMessage(msg);
    });
  }

  it("proves ownership-safe refresh lease fencing under production path pause, expiration, and stale cleanup", async () => {
    const rawToken = "initial-refresh-token-test-fencing";
    const initialHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const clientId = "client-fencing-test";
    const userId = "user-fencing-1";
    const newRefreshTokenB = "valid-rotated-token-b";
    const newHashB = crypto.createHash("sha256").update(newRefreshTokenB).digest("hex");

    await db.collection("user").insertOne({
      _id: userId as any,
      id: userId,
      email: "fence-user@example.com",
      role: "user",
      tokenVersion: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

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

    const workerA = createWorker(clientId, initialHash, userId);
    const workerB = createWorker(clientId, initialHash, userId);

    try {
      // 1. Worker A initiates production refresh and pauses after acquiring lease
      const promiseA = sendWorker(workerA, { action: "refresh", refreshToken: rawToken });
      const claimA = await waitForWorkerStatus(workerA, "claimed_and_paused");
      const leaseOwnerA = claimA.leaseOwner;
      assert.ok(leaseOwnerA, "Worker A must acquire unique leaseOwner fencing token");

      let fam = await db.collection("oauth_token_families").findOne({ activeTokenHash: initialHash });
      assert.equal(fam?.rotating, true);
      assert.equal(fam?.rotationOwner, leaseOwnerA);

      // 2. Expire Worker A's lease in MongoDB (> 15 seconds)
      await db.collection("oauth_token_families").updateOne(
        { activeTokenHash: initialHash },
        { $set: { rotatingAt: new Date(Date.now() - 20000) } }
      );

      // 3. Worker B initiates production refresh and claims replacement lease
      const promiseB = sendWorker(workerB, {
        action: "refresh", refreshToken: rawToken, mockSuccess: true, newRefreshToken: newRefreshTokenB,
      });
      const claimB = await waitForWorkerStatus(workerB, "claimed_and_paused");
      const leaseOwnerB = claimB.leaseOwner;
      assert.ok(leaseOwnerB);
      assert.notEqual(leaseOwnerB, leaseOwnerA, "Worker B must receive a distinct leaseOwner");

      fam = await db.collection("oauth_token_families").findOne({ activeTokenHash: initialHash });
      assert.equal(fam?.rotating, true);
      assert.equal(fam?.rotationOwner, leaseOwnerB, "DB rotationOwner must be bound to Worker B");

      // 4. Resume Worker A with controlled failure; production cleanup runs releaseRotationLock
      workerA.postMessage({ action: "resume", fail: true });
      const resA = await promiseA;
      assert.equal(resA.status, "error");
      assert.equal(resA.error, "Worker controlled failure after claim");

      // 5. Assert production cleanup with leaseOwnerA preserved Worker B's owner and lock
      fam = await db.collection("oauth_token_families").findOne({ activeTokenHash: initialHash });
      assert.equal(fam?.rotating, true, "Worker B lease must be retained");
      assert.equal(fam?.rotationOwner, leaseOwnerB, "Worker B must remain lease owner");

      // 6. Stale Worker A attempts to commit rotation with leaseOwnerA
      const rotateA = await sendWorker(workerA, {
        action: "stale_rotate", newHash: "stale-hash-a", leaseOwner: leaseOwnerA,
      });
      assert.equal(rotateA.rotationResult.valid, false, "Stale Worker A rotation must be rejected");

      // 7. Active Worker B completes rotation successfully via production handleRefreshTokenGrant
      workerB.postMessage({ action: "resume", fail: false });
      const resB = await promiseB;
      assert.equal(resB.status, "finished");
      assert.equal(resB.response.status, 200, "Worker B must complete refresh with 200 status");
      assert.ok(resB.response.body.access_token, "Worker B must receive minted RS256 access token");
      assert.equal(resB.response.body.refresh_token, newRefreshTokenB);

      const updatedFam = await db.collection("oauth_token_families").findOne({ familyId: "fam-fence-1" });
      assert.equal(updatedFam?.activeTokenHash, newHashB);
      assert.ok(updatedFam?.consumedTokenHashes.includes(initialHash), "initialHash must be in consumed list");
      assert.equal(updatedFam?.rotating, false);
      assert.equal(updatedFam?.rotationOwner, undefined, "rotationOwner must be unset upon rotation commit");

      // 8. Stale initial token replay triggers immediate family revocation
      const { verifyAndRotateTokenFamily } = await import("../../src/db/token-families");
      const replayCheck = await verifyAndRotateTokenFamily(
        initialHash, "dummy-replay-hash", userId, Date.now() + 5000, clientId
      );
      assert.equal(replayCheck.replayed, true, "Replaying initial token must trigger replay detection");

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
    const initialHashDirect = crypto.createHash("sha256").update(rawToken).digest("hex");
    const clientIdDirect = "client-error-direct";
    const userIdDirect = "user-error-1";

    await db.collection("user").insertOne({
      _id: userIdDirect as any, id: userIdDirect, email: "user-error@example.com",
    });

    await db.collection("oauth_token_families").insertOne({
      familyId: "fam-error-direct", clientId: clientIdDirect, userId: userIdDirect,
      activeTokenHash: initialHashDirect, consumedTokenHashes: [], status: "active",
      createdAt: new Date(), updatedAt: new Date(), tokenVersion: 1,
    });

    const mockC = { json: (body: any, status: number) => ({ body, status }) };
    const mockContext: any = {
      canonicalClientId: clientIdDirect, clientDoc: { isPublic: true },
      reqToForward: { notARequest: true },
    };

    await assert.rejects(async () => {
      await handleRefreshTokenGrant(mockC, mockContext, rawToken);
    });

    const fam = await db.collection("oauth_token_families").findOne({ activeTokenHash: initialHashDirect });
    assert.equal(fam?.rotating, false, "Rotation lock must be released on thrown error");
    assert.equal(fam?.rotationOwner, undefined, "rotationOwner must be unset on thrown error");
  });
});
