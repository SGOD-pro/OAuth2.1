import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import { InMemoryProfileCollection, writeProtectedProfile } from "../../src/identity/protected-profile-store";

process.env.NODE_ENV = process.env.NODE_ENV || "test";
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/local_di_unused";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);

const adminUsersMod = await import("../../src/routes/admin-users");
const adminAppUsersMod = await import("../../src/routes/admin-app-users");

describe("P6b Admin Profile Reads (admin-users & admin-app-users)", () => {
  it("resolves protected profile values for scoped admin user reads, preserves masking, and fails closed on key denial/outage", async () => {
    const createGetUsersHandler = (adminUsersMod as any).createGetUsersHandler;
    assert.equal(typeof createGetUsersHandler, "function", "createGetUsersHandler must be exported");

    const targetId = new ObjectId().toHexString();
    const otherId = new ObjectId().toHexString();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const targetWritten = await writeProtectedProfile({
      store,
      provider,
      accountId: targetId,
      name: "protected.alice@example.com",
      email: "protected.alice@example.com",
    });
    await writeProtectedProfile({
      store,
      provider,
      accountId: otherId,
      name: "Other User",
      email: "other@example.com",
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

    const targetUser = {
      _id: new ObjectId(targetId),
      id: targetId,
      username: "alice_target",
      usernameNormalized: "alice_target",
      name: "Stale Legacy Name",
      email: "stale.legacy@example.com",
      role: "user",
      createdAt: new Date(),
    };

    const mockDb = {
      collection(name: string) {
        if (name === "user") {
          return {
            find(filter: any) {
              const items = filter.$or ? [targetUser] : [targetUser];
              return {
                sort() { return this; },
                skip() { return this; },
                limit() { return this; },
                async toArray() { return items; },
              };
            },
          };
        }
        return { async findOne() { return null; } };
      },
    };

    const app = new Hono();
    app.get("/users", createGetUsersHandler({
      getDb: async () => mockDb,
      protectedProfileStore: store,
      accountKeyProvider: spyingProvider,
      migrationMode: "strict",
    }));

    const res = await app.request("/users?q=alice_target");
    assert.equal(res.status, 200);
    const bodyText = await res.text();
    assert.equal(bodyText.includes("protected.alice@example.com"), false, "Full protected email must stay masked");
    assert.equal(bodyText.includes("stale.legacy@example.com"), false, "Stale legacy email must not appear");
    const rows = JSON.parse(bodyText);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].displayLabel, "pr***@example.com");
    assert.equal(rows[0].name, "pr***@example.com");
    assert.equal(unwrapAccounts.every((id) => id === targetId), true, "Must only decrypt scoped query results");

    // Key denial must fail closed without plaintext fallback
    await provider.denyAccess(targetId, targetWritten.nameEnvelope.keyRef, "owner_revoked");
    const deniedRes = await app.request("/users?q=alice_target");
    assert.equal(deniedRes.status, 403);
    const deniedText = await deniedRes.text();
    assert.equal(deniedText.includes("Stale Legacy Name"), false);
    assert.equal(deniedText.includes("stale.legacy@example.com"), false);
  });

  it("resolves protected profile values for scoped app-user reads and fails closed on provider outage", async () => {
    const createGetAppUsersHandler = (adminAppUsersMod as any).createGetAppUsersHandler;
    assert.equal(typeof createGetAppUsersHandler, "function", "createGetAppUsersHandler must be exported");

    const memberId = new ObjectId().toHexString();
    const outsiderId = new ObjectId().toHexString();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    await writeProtectedProfile({
      store,
      provider,
      accountId: memberId,
      name: "Protected Member",
      email: "member.protected@example.com",
    });
    await writeProtectedProfile({
      store,
      provider,
      accountId: outsiderId,
      name: "Outsider",
      email: "outsider@example.com",
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

    const memberDoc = {
      _id: new ObjectId(memberId),
      id: memberId,
      name: "Stale Member Name",
      email: "stale.member@example.com",
    };

    const mockDb = {
      collection(name: string) {
        if (name === "user_app_registrations") {
          return {
            find() {
              return {
                sort() { return this; },
                async toArray() {
                  return [{ _id: new ObjectId(), clientId: "app-1", userId: memberId, registeredAt: new Date() }];
                },
              };
            },
          };
        }
        if (name === "user") {
          return {
            find() {
              return { async toArray() { return [memberDoc]; } };
            },
          };
        }
        return { async findOne() { return null; } };
      },
    };

    const app = new Hono();
    app.get("/clients/:clientId/users", createGetAppUsersHandler({
      getDb: async () => mockDb,
      resolveClient: async () => ({ clientId: "app-1" }),
      protectedProfileStore: store,
      accountKeyProvider: spyingProvider,
      migrationMode: "strict",
    }));

    const res = await app.request("/clients/app-1/users");
    assert.equal(res.status, 200);
    const bodyText = await res.text();
    assert.equal(bodyText.includes("member.protected@example.com"), false, "Full protected email must remain omitted");
    assert.equal(bodyText.includes("Stale Member Name"), false, "Stale legacy name must be replaced");
    const json = JSON.parse(bodyText);
    assert.equal(json.users.length, 1);
    assert.equal(json.users[0].name, "Protected Member");
    assert.equal(json.users[0].displayLabel, "Protected Member");
    assert.deepEqual(unwrapAccounts, [memberId], "Only assigned app member may be decrypted");

    provider.setOutage(true);
    const outageRes = await app.request("/clients/app-1/users");
    assert.equal(outageRes.status, 503);
    const outageText = await outageRes.text();
    assert.equal(outageText.includes("Stale Member Name"), false);
    assert.equal(outageText.includes("stale.member@example.com"), false);
  });
});
