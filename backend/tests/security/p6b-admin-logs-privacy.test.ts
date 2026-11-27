import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import {
  InMemoryProfileCollection,
  MongoProfileCollection,
  writeProtectedProfile,
} from "../../src/identity/protected-profile-store";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

process.env.NODE_ENV = process.env.NODE_ENV || "test";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);

let suiteCtx: Awaited<ReturnType<typeof setupSuiteDatabase>> | undefined;
let db: any;
let adminLogsMod: any;

before(async () => {
  isolateTestEnvironment();
  process.env.NODE_ENV = "test";
  suiteCtx = await setupSuiteDatabase("p6b_admin_logs_privacy");
  const { getDb } = await import("../../src/db/mongo");
  db = await getDb();
  adminLogsMod = await import("../../src/routes/admin-logs");
});

after(async () => {
  const { closeDb } = await import("../../src/db/mongo");
  await closeDb();
  await suiteCtx?.cleanup();
});

describe("P6b Admin Audit & Logs Privacy", { timeout: 60_000 }, () => {
  it("resolves masked userEmail from protected profile when legacy user.email is removed, scopes before decrypting, and fails closed", async () => {
    const createGetLogsHandler = adminLogsMod.createGetLogsHandler;
    assert.equal(typeof createGetLogsHandler, "function", "createGetLogsHandler must be exported");

    const scopedUserId = new ObjectId().toHexString();
    const otherUserId = new ObjectId().toHexString();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const written = await writeProtectedProfile({
      store,
      provider,
      accountId: scopedUserId,
      name: "Scoped Admin User",
      email: "protected.logs@example.com",
    });
    await writeProtectedProfile({
      store,
      provider,
      accountId: otherUserId,
      name: "Other Client User",
      email: "other.logs@example.com",
    });

    const unwrapAccounts: string[] = [];
    const spyingProvider = {
      wrapDataKey: provider.wrapDataKey.bind(provider),
      denyAccess: provider.denyAccess.bind(provider),
      scheduleDestruction: provider.scheduleDestruction.bind(provider),
      getKeyState: provider.getKeyState.bind(provider),
      async unwrapDataKey(accountId: string, keyRef: string, wrappedKey: string) {
        unwrapAccounts.push(accountId);
        return provider.unwrapDataKey(accountId, keyRef, wrappedKey);
      },
    };

    const mockDb = {
      collection(name: string) {
        if (name === "auth_events") {
          return {
            async countDocuments(filter: any) {
              return filter.clientId === "client-a" ? 1 : 2;
            },
            aggregate(pipeline: any[]) {
              const matchStage = pipeline.find((s) => s.$match)?.$match || {};
              const rows = matchStage.clientId === "client-a"
                ? [{ _id: new ObjectId(), userId: scopedUserId, targetIdentifier: null, eventType: "sign_in", outcome: "success", clientId: "client-a", timestamp: new Date(), source: "auth_events" }]
                : [
                    { _id: new ObjectId(), userId: scopedUserId, targetIdentifier: null, eventType: "sign_in", outcome: "success", clientId: "client-a", timestamp: new Date(), source: "auth_events" },
                    { _id: new ObjectId(), userId: otherUserId, targetIdentifier: null, eventType: "sign_in", outcome: "success", clientId: "client-b", timestamp: new Date(), source: "auth_events" },
                  ];
              return { async toArray() { return rows; } };
            },
          };
        }
        if (name === "admin_audit") return { async countDocuments() { return 0; } };
        if (name === "session") return { aggregate() { return { async toArray() { return []; } }; } };
        if (name === "user") {
          return {
            find() {
              // Simulate legacy user.email removed while stale name remains
              return { async toArray() { return [{ _id: new ObjectId(scopedUserId), id: scopedUserId, name: "Stale Name" }]; } };
            },
          };
        }
        return { async findOne() { return null; } };
      },
    };

    const app = new Hono();
    app.get("/logs", createGetLogsHandler({
      getDb: async () => mockDb,
      protectedProfileStore: store,
      accountKeyProvider: spyingProvider,
      migrationMode: "strict",
    }));

    const res = await app.request("/logs?clientId=client-a");
    assert.equal(res.status, 200);
    const text = await res.text();
    assert.equal(text.includes("protected.logs@example.com"), false, "Full protected email must not appear in logs");
    assert.equal(text.includes("other.logs@example.com"), false);
    const rows = JSON.parse(text);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].userEmail, "pr***@example.com");
    assert.deepEqual(unwrapAccounts, [scopedUserId], "Only client-scoped user may be decrypted");

    // Key denial fails closed without disclosing legacy plaintext
    await provider.denyAccess(scopedUserId, written.emailEnvelope.keyRef, "owner_revoked");
    const deniedRes = await app.request("/logs?clientId=client-a");
    assert.equal(deniedRes.status, 403);
    const deniedText = await deniedRes.text();
    assert.equal(deniedText.includes("protected.logs@example.com"), false);
    assert.equal(deniedText.includes("Stale Name"), false);
  });

  it("reads protected log display labels from real Docker MongoDB after legacy user.email removal", async () => {
    const createGetV2LogsHandler = adminLogsMod.createGetV2LogsHandler;
    assert.equal(typeof createGetV2LogsHandler, "function", "createGetV2LogsHandler must be exported");

    const userId = new ObjectId().toHexString();
    const provider = new InMemoryAccountKeyProvider();
    const mongoStore = new MongoProfileCollection(db);
    await writeProtectedProfile({
      store: mongoStore,
      provider,
      accountId: userId,
      name: "Mongo Logs User",
      email: "mongo.logs@example.com",
    });

    await db.collection("user").insertOne({ _id: new ObjectId(userId), id: userId, name: "Mongo Logs User" });
    await db.collection("auth_events").insertOne({
      timestamp: new Date(),
      eventType: "oauth_token",
      outcome: "success",
      userId,
      targetIdentifier: null,
      clientId: "mongo-client-1",
    });

    const app = new Hono();
    app.get("/v2/logs", createGetV2LogsHandler({
      getDb: async () => db,
      protectedProfileStore: mongoStore,
      accountKeyProvider: provider,
      migrationMode: "strict",
    }));

    const res = await app.request("/v2/logs?clientId=mongo-client-1");
    assert.equal(res.status, 200);
    const text = await res.text();
    assert.equal(text.includes("mongo.logs@example.com"), false);
    const json = JSON.parse(text);
    assert.equal(json.logs.length, 1);
    assert.equal(json.logs[0].userEmail, "mo***@example.com");

    provider.setOutage(true);
    const outageRes = await app.request("/v2/logs?clientId=mongo-client-1");
    assert.equal(outageRes.status, 503);
  });
});
