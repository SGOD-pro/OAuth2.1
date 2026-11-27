import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import { prepareOwnerExport } from "../../src/identity/owner-export";
import { InMemoryProfileCollection, writeProtectedProfile } from "../../src/identity/protected-profile-store";
import type { OwnerProfileRouteDeps } from "../../src/routes/identity-owner-portal";

process.env.NODE_ENV = process.env.NODE_ENV || "test";
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/local_di_unused";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);

const { createOwnerProfileHandlers } = await import("../../src/routes/identity-owner-portal");

function cloneDocs(docs: any[]): any[] {
  return docs.map((d) => ({ ...d }));
}

function createInMemoryMongo(initialUsers: any[]) {
  let users = cloneDocs(initialUsers);
  let lookups: any[] = [];

  const makeDb = (txState?: { users: any[]; lookups: any[] }) => {
    const getUsers = () => (txState ? txState.users : users);
    const getLookups = () => (txState ? txState.lookups : lookups);
    return {
      collection(name: string) {
        if (name === "user") {
          return {
            async findOne(query: any) {
              const list = getUsers();
              if (query._id && typeof query._id === "object" && "$ne" in query._id) {
                const neId = String(query._id.$ne);
                return (
                  list.find(
                    (u) =>
                      String(u._id) !== neId &&
                      ((query.$or || []).some((c: any) =>
                        (c.usernameNormalized && u.usernameNormalized === c.usernameNormalized) ||
                        (c.username && u.username === c.username)
                      ))
                  ) ?? null
                );
              }
              return list.find((u) => String(u._id) === String(query._id)) ?? null;
            },
            async updateOne(filter: any, update: any) {
              const list = getUsers();
              const target = list.find((u) => String(u._id) === String(filter._id));
              if (target && update.$set) Object.assign(target, update.$set);
            },
          };
        }
        if (name === "identity_lookup") {
          return {
            async findOne(query: any) {
              const list = getLookups();
              return (
                list.find(
                  (d) =>
                    d.kind === query.kind &&
                    d.keyedLookup === query.keyedLookup &&
                    String(d.userId) !== String(query.userId?.$ne)
                ) ?? null
              );
            },
            async updateOne(filter: any, update: any) {
              const list = getLookups();
              const idx = list.findIndex((d) => d.kind === filter.kind && d.userId === filter.userId);
              const next = { ...(idx >= 0 ? list[idx] : {}), ...(update.$set || {}) };
              if (idx >= 0) list[idx] = next;
              else list.push(next);
            },
          };
        }
        return {
          find() {
            return { sort() { return { limit() { return { async toArray() { return []; } }; } }; } };
          },
        };
      },
    };
  };

  let txSnapshot: { users: any[]; lookups: any[] } | null = null;
  const db = new Proxy(
    {},
    {
      get(_t, prop) {
        const active = makeDb(txSnapshot ?? undefined) as any;
        return active[prop];
      },
    }
  );

  const startSession = () => ({
    async withTransaction(fn: () => Promise<void>) {
      txSnapshot = { users: cloneDocs(users), lookups: cloneDocs(lookups) };
      try {
        await fn();
        users = txSnapshot.users;
        lookups = txSnapshot.lookups;
      } finally {
        txSnapshot = null;
      }
    },
    async endSession() {},
  });

  return { db, startSession, getUsers: () => users };
}

function createTestApp(depsForActor: (actorId: string) => OwnerProfileRouteDeps) {
  const app = new Hono();
  app.get("/me", (c) => createOwnerProfileHandlers(depsForActor(c.req.header("x-test-actor") || "")).getOwnerMe(c));
  app.patch("/me", (c) => createOwnerProfileHandlers(depsForActor(c.req.header("x-test-actor") || "")).patchOwnerMe(c));
  return app;
}

describe("P6b Owner Profile Route Integration (Local DI)", () => {
  it("updates protected profile via PATCH /me, reads via GET /me and prepareOwnerExport, and rejects email edits", async () => {
    const idA = new ObjectId();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const mongo = createInMemoryMongo([
      { _id: idA, name: "Initial Name", email: "alice@example.com", emailVerified: true, username: "alice_a" },
    ]);

    const app = createTestApp((actorId) => ({
      getDb: async () => mongo.db,
      startSession: mongo.startSession,
      resolveOwner: async () => ({ ok: true, userId: actorId, sessionId: "sess-1" }),
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "compat",
    }));

    const emailReject = await app.request("/me", {
      method: "PATCH",
      headers: { "content-type": "application/json", "x-test-actor": String(idA) },
      body: JSON.stringify({ email: "new@example.com" }),
    });
    assert.equal(emailReject.status, 400);

    const patchRes = await app.request("/me", {
      method: "PATCH",
      headers: { "content-type": "application/json", "x-test-actor": String(idA) },
      body: JSON.stringify({ name: "Alice Protected" }),
    });
    assert.equal(patchRes.status, 200);
    const patchBody = await patchRes.json();
    assert.equal(patchBody.name, "Alice Protected");

    const storedDoc = await store.findByUserId(String(idA));
    assert.ok(storedDoc);
    assert.equal(JSON.stringify(storedDoc).includes("Alice Protected"), false);

    const getRes = await app.request("/me", {
      method: "GET",
      headers: { "x-test-actor": String(idA) },
    });
    assert.equal(getRes.status, 200);
    assert.equal((await getRes.json()).name, "Alice Protected");

    const exported = await prepareOwnerExport(mongo.db, String(idA), {
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    });
    assert.equal(exported?.profile.name, "Alice Protected");
    assert.equal(exported?.profile.email, "alice@example.com");
  });

  it("isolates foreign-account requests and prevents cross-account profile access", async () => {
    const idA = new ObjectId();
    const idB = new ObjectId();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    await writeProtectedProfile({
      store,
      provider,
      accountId: String(idA),
      name: "Alice Secret",
      email: "alice@example.com",
    });

    const mongo = createInMemoryMongo([
      { _id: idA, name: "Alice", email: "alice@example.com", emailVerified: true, username: "alice_a" },
      { _id: idB, name: "Bob", email: "bob@example.com", emailVerified: true, username: "bob_b" },
    ]);

    const app = createTestApp((actorId) => ({
      getDb: async () => mongo.db,
      startSession: mongo.startSession,
      resolveOwner: async () =>
        actorId === String(idB)
          ? { ok: true, userId: String(idB), sessionId: "sess-b" }
          : { ok: false, response: new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }) },
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    }));

    const bobGet = await app.request("/me", { method: "GET", headers: { "x-test-actor": String(idB) } });
    assert.equal(bobGet.status, 404);
    const aliceDoc = await store.findByUserId(String(idA));
    assert.ok(aliceDoc);
  });

  it("rolls back on provider outage during PATCH, preserves previous state, and never falls back to plaintext on decrypt failure", async () => {
    const idA = new ObjectId();
    const idB = new ObjectId();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const initialDoc = await writeProtectedProfile({
      store,
      provider,
      accountId: String(idA),
      name: "Original Protected",
      email: "alice@example.com",
    });

    const mongo = createInMemoryMongo([
      { _id: idA, name: "Original Plaintext", email: "alice@example.com", emailVerified: true, username: "alice_a" },
      { _id: idB, name: "Bob", email: "bob@example.com", emailVerified: true, username: "bob_taken", usernameNormalized: "bob_taken" },
    ]);

    const app = createTestApp((actorId) => ({
      getDb: async () => mongo.db,
      startSession: mongo.startSession,
      resolveOwner: async () => ({ ok: true, userId: actorId, sessionId: "sess-a" }),
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "compat",
    }));

    // 1. Outage during PATCH rolls back user update and preserves previous protected doc
    provider.setOutage(true);
    const outagePatch = await app.request("/me", {
      method: "PATCH",
      headers: { "content-type": "application/json", "x-test-actor": String(idA) },
      body: JSON.stringify({ name: "Should Roll Back" }),
    });
    assert.equal(outagePatch.status, 503);
    assert.equal(mongo.getUsers()[0].name, "Original Plaintext");
    assert.deepEqual(await store.findByUserId(String(idA)), initialDoc);
    provider.setOutage(false);

    // 2. Duplicate username (409) rolls back both user and protected profile
    const dupPatch = await app.request("/me", {
      method: "PATCH",
      headers: { "content-type": "application/json", "x-test-actor": String(idA) },
      body: JSON.stringify({ name: "Should Not Commit", username: "bob_taken" }),
    });
    assert.equal(dupPatch.status, 409);
    assert.equal(mongo.getUsers()[0].name, "Original Plaintext");
    assert.deepEqual(await store.findByUserId(String(idA)), initialDoc);

    // 3. Key denial on GET /me fails closed without falling back to user plaintext
    await provider.denyAccess(String(idA), initialDoc.nameEnvelope.keyRef, "owner_revoked");
    const deniedGet = await app.request("/me", {
      method: "GET",
      headers: { "x-test-actor": String(idA) },
    });
    assert.equal(deniedGet.status, 403);
    assert.equal(JSON.stringify(await deniedGet.json()).includes("Original Plaintext"), false);
  });

  it("reads legacy plaintext profile in compat mode and fails closed in strict mode", async () => {
    const idLegacy = new ObjectId();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const mongo = createInMemoryMongo([
      { _id: idLegacy, name: "Legacy Display", email: "legacy@example.com", emailVerified: true, username: "legacy_u" },
    ]);

    const compatApp = createTestApp((actorId) => ({
      getDb: async () => mongo.db,
      startSession: mongo.startSession,
      resolveOwner: async () => ({ ok: true, userId: actorId, sessionId: "sess-l" }),
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "compat",
    }));
    const strictApp = createTestApp((actorId) => ({
      getDb: async () => mongo.db,
      startSession: mongo.startSession,
      resolveOwner: async () => ({ ok: true, userId: actorId, sessionId: "sess-l" }),
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    }));

    const compatRes = await compatApp.request("/me", { method: "GET", headers: { "x-test-actor": String(idLegacy) } });
    assert.equal(compatRes.status, 200);
    assert.equal((await compatRes.json()).name, "Legacy Display");

    const strictRes = await strictApp.request("/me", { method: "GET", headers: { "x-test-actor": String(idLegacy) } });
    assert.equal(strictRes.status, 404);
  });
});
