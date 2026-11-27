import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import { prepareOwnerExport } from "../../src/identity/owner-export";
import { InMemoryProfileCollection, writeProtectedProfile } from "../../src/identity/protected-profile-store";

process.env.NODE_ENV = process.env.NODE_ENV || "test";
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/local_di_unused";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);

const { computeEmailLookup } = await import("../../src/identity/registration-crypto");
const { createOwnerProfileHandlers } = await import("../../src/routes/identity-owner-portal");
const { createEmailChangeHandlers } = await import("../../src/routes/identity-email-change");

function cloneDocs(docs: any[]): any[] {
  return docs.map((d) => ({ ...d }));
}

function createTransactionalMongo(initialUsers: any[], initialLookups: any[] = []) {
  let state = {
    users: cloneDocs(initialUsers),
    lookups: cloneDocs(initialLookups),
    requests: [] as any[],
  };
  let txState: typeof state | null = null;
  let activeSessionToken: unknown = null;
  const recordedSessions: Array<{ op: string; col: string; session: unknown }> = [];

  const active = () => txState ?? state;
  const checkSession = (op: string, col: string, opts?: any) => {
    if (txState && opts?.session !== activeSessionToken) {
      throw new Error(`Missing or mismatched transaction session on ${col}.${op}`);
    }
    if (txState) recordedSessions.push({ op, col, session: opts?.session });
  };

  const db = {
    collection(name: string) {
      if (name === "user") {
        return {
          async findOne(query: any, opts?: any) {
            checkSession("findOne", name, opts);
            const list = active().users;
            if (query._id && typeof query._id === "object" && "$ne" in query._id) {
              return list.find((u) => String(u._id) !== String(query._id.$ne) && u.email === query.email) ?? null;
            }
            if (query.email && !query._id) {
              return list.find((u) => u.email === query.email) ?? null;
            }
            return (
              list.find(
                (u) => String(u._id) === String(query._id) && (query.email === undefined || u.email === query.email)
              ) ?? null
            );
          },
          async updateOne(filter: any, update: any, opts?: any) {
            checkSession("updateOne", name, opts);
            const target = active().users.find(
              (u) => String(u._id) === String(filter._id) && (filter.email === undefined || u.email === filter.email)
            );
            if (!target) return { matchedCount: 0 };
            if (update.$set) Object.assign(target, update.$set);
            if (update.$inc) {
              for (const [k, v] of Object.entries(update.$inc)) {
                target[k] = (typeof target[k] === "number" ? target[k] : 0) + Number(v);
              }
            }
            return { matchedCount: 1 };
          },
        };
      }
      if (name === "identity_lookup") {
        return {
          async findOne(query: any, opts?: any) {
            checkSession("findOne", name, opts);
            return (
              active().lookups.find(
                (d) =>
                  d.kind === query.kind &&
                  d.keyedLookup === query.keyedLookup &&
                  String(d.userId) !== String(query.userId?.$ne)
              ) ?? null
            );
          },
          async updateOne(filter: any, update: any, opts?: any) {
            checkSession("updateOne", name, opts);
            const list = active().lookups;
            const idx = list.findIndex((d) => d.kind === filter.kind && d.userId === filter.userId);
            const next = { ...(idx >= 0 ? list[idx] : {}), ...(update.$set || {}) };
            if (idx >= 0) list[idx] = next;
            else list.push(next);
          },
        };
      }
      if (name === "email_change_requests") {
        return {
          async updateMany(filter: any, update: any, opts?: any) {
            checkSession("updateMany", name, opts);
            for (const r of active().requests) {
              if (r.userId === filter.userId && r.consumedAt === null && update.$set) Object.assign(r, update.$set);
            }
          },
          async insertOne(doc: any, opts?: any) {
            checkSession("insertOne", name, opts);
            active().requests.push({ ...doc });
          },
          async findOneAndUpdate(filter: any, update: any, opts?: any) {
            checkSession("findOneAndUpdate", name, opts);
            const req = active().requests.find(
              (r) => r.tokenDigest === filter.tokenDigest && r.userId === filter.userId && r.consumedAt === null
            );
            if (!req) return null;
            if (update.$set) Object.assign(req, update.$set);
            return { ...req };
          },
        };
      }
      return {
        async deleteMany(_f: any, opts?: any) { checkSession("deleteMany", name, opts); },
        async updateMany(_f: any, _u: any, opts?: any) { checkSession("updateMany", name, opts); },
        find() { return { sort() { return { limit() { return { async toArray() { return []; } }; } }; } }; },
      };
    },
  };

  const startSession = () => {
    const sessionObj = {
      async withTransaction(fn: () => Promise<void>) {
        txState = {
          users: cloneDocs(state.users),
          lookups: cloneDocs(state.lookups),
          requests: cloneDocs(state.requests),
        };
        activeSessionToken = sessionObj;
        try {
          await fn();
          state = txState;
        } finally {
          txState = null;
          activeSessionToken = null;
        }
      },
      async endSession() {},
    };
    return sessionObj;
  };

  return {
    db,
    startSession,
    getState: () => state,
    getRecordedSessions: () => recordedSessions,
    getSessionToken: () => activeSessionToken,
  };
}

describe("P6b Verified Email Change Route Integration (Local DI)", () => {
  it("updates protected email and identity_lookup in same session while preserving display name, and reflects in GET /me and export", async () => {
    const idA = new ObjectId();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    await writeProtectedProfile({
      store,
      provider,
      accountId: String(idA),
      name: "Alice Protected",
      email: "alice.old@example.com",
    });

    const mongo = createTransactionalMongo(
      [{ _id: idA, name: "Legacy Old Name", email: "alice.old@example.com", emailVerified: true, tokenVersion: 1 }],
      [{ kind: "email", userId: String(idA), keyVersion: 1, keyedLookup: computeEmailLookup("alice.old@example.com") }]
    );

    const profileHandlers = createOwnerProfileHandlers({
      getDb: async () => mongo.db,
      startSession: mongo.startSession,
      resolveOwner: async () => ({ ok: true, userId: String(idA), sessionId: "sess-a" }),
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "compat",
    });
    const emailHandlers = createEmailChangeHandlers({
      getDb: async () => mongo.db,
      startSession: mongo.startSession,
      resolveOwner: async () => ({ ok: true, userId: String(idA), sessionId: "sess-a", contextId: "ctx-a" }),
      verifyPassword: async () => true,
      protectedProfileStore: store,
      accountKeyProvider: provider,
    });

    const app = new Hono();
    app.get("/me", profileHandlers.getOwnerMe);
    app.patch("/me", profileHandlers.patchOwnerMe);
    app.post("/email-change/request", emailHandlers.requestEmailChange);
    app.post("/email-change/confirm", emailHandlers.confirmEmailChange);

    let capturedToken = "";
    const reqRes = await app.request("/email-change/request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ newEmail: "alice.new@example.com", password: "ValidPassword123!" }),
    });
    assert.equal(reqRes.status, 200);
    // Test mail sink captured token in memory
    const { getTestMailSinkMessages } = await import("../../src/identity/mail-service");
    const mail = getTestMailSinkMessages().findLast((m) => m.to === "alice.new@example.com");
    assert.ok(mail);
    const tokenMatch = mail.text.match(/token:\s*([^\s)]+)/);
    assert.ok(tokenMatch);
    capturedToken = tokenMatch[1];

    // Concurrent display-name update BEFORE confirm must be preserved after email-change confirm
    const namePatch = await app.request("/me", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Alice Concurrent Name" }),
    });
    assert.equal(namePatch.status, 200);

    mongo.getRecordedSessions().length = 0;
    const confirmRes = await app.request("/email-change/confirm", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: capturedToken }),
    });
    assert.equal(confirmRes.status, 200);

    // Every write in the confirm transaction used the same session
    const txOps = mongo.getRecordedSessions();
    assert.ok(txOps.length >= 4);
    const uniqueSessions = new Set(txOps.map((o) => o.session));
    assert.equal(uniqueSessions.size, 1);

    // GET /me and prepareOwnerExport return new protected email while preserving display name
    const meRes = await app.request("/me", { method: "GET" });
    assert.equal(meRes.status, 200);
    const meBody = await meRes.json();
    assert.equal(meBody.email, "alice.new@example.com");
    assert.equal(meBody.name, "Alice Concurrent Name");

    const exported = await prepareOwnerExport(mongo.db, String(idA), {
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    });
    assert.equal(exported?.profile.email, "alice.new@example.com");
    assert.equal(exported?.profile.name, "Alice Concurrent Name");

    // Verify lookup updated and no plaintext email in protected doc
    const lookup = mongo.getState().lookups.find((l) => l.kind === "email" && l.userId === String(idA));
    assert.equal(lookup?.keyedLookup, computeEmailLookup("alice.new@example.com"));
    const storedDoc = await store.findByUserId(String(idA));
    assert.equal(JSON.stringify(storedDoc).includes("alice.new@example.com"), false);
  });

  it("rolls back on duplicate email and key-provider outage, leaving profile, user, lookup, and proof consistent", async () => {
    const idA = new ObjectId();
    const idB = new ObjectId();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const initialDoc = await writeProtectedProfile({
      store,
      provider,
      accountId: String(idA),
      name: "Alice Protected",
      email: "alice.old@example.com",
    });

    const mongo = createTransactionalMongo(
      [
        { _id: idA, name: "Alice Protected", email: "alice.old@example.com", emailVerified: true, tokenVersion: 1 },
        { _id: idB, name: "Bob", email: "taken@example.com", emailVerified: true, tokenVersion: 1 },
      ],
      [
        { kind: "email", userId: String(idA), keyVersion: 1, keyedLookup: computeEmailLookup("alice.old@example.com") },
        { kind: "email", userId: String(idB), keyVersion: 1, keyedLookup: computeEmailLookup("taken@example.com") },
      ]
    );

    const emailHandlers = createEmailChangeHandlers({
      getDb: async () => mongo.db,
      startSession: mongo.startSession,
      resolveOwner: async () => ({ ok: true, userId: String(idA), sessionId: "sess-a", contextId: "ctx-a" }),
      verifyPassword: async () => true,
      protectedProfileStore: store,
      accountKeyProvider: provider,
    });
    const app = new Hono();
    app.post("/email-change/request", emailHandlers.requestEmailChange);
    app.post("/email-change/confirm", emailHandlers.confirmEmailChange);

    // 1. Request change to future-colliding email (simulate race where B claims it before confirm)
    await app.request("/email-change/request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ newEmail: "race@example.com", password: "ValidPassword123!" }),
    });
    const { getTestMailSinkMessages } = await import("../../src/identity/mail-service");
    const mail1 = getTestMailSinkMessages().findLast((m) => m.to === "race@example.com")!;
    const tok1 = mail1.text.match(/token:\s*([^\s)]+)/)![1];

    // B claims race@example.com in identity_lookup
    mongo.getState().lookups.push({
      kind: "email",
      userId: String(idB),
      keyVersion: 1,
      keyedLookup: computeEmailLookup("race@example.com"),
    });

    const dupConfirm = await app.request("/email-change/confirm", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: tok1 }),
    });
    assert.equal(dupConfirm.status, 409);
    assert.equal(mongo.getState().requests[0].consumedAt, null, "Proof must remain unconsumed on rollback");
    assert.equal(mongo.getState().users[0].email, "alice.old@example.com");
    assert.deepEqual(await store.findByUserId(String(idA)), initialDoc);

    // 2. Request change to valid email, then trigger key-provider outage on confirm
    await app.request("/email-change/request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ newEmail: "alice.outage@example.com", password: "ValidPassword123!" }),
    });
    const mail2 = getTestMailSinkMessages().findLast((m) => m.to === "alice.outage@example.com")!;
    const tok2 = mail2.text.match(/token:\s*([^\s)]+)/)![1];

    provider.setOutage(true);
    const outageConfirm = await app.request("/email-change/confirm", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: tok2 }),
    });
    assert.equal(outageConfirm.status, 503);
    assert.equal(mongo.getState().requests.find((r) => r.newEmail === "alice.outage@example.com")?.consumedAt, null);
    assert.equal(mongo.getState().users[0].email, "alice.old@example.com");
    assert.equal(
      mongo.getState().lookups.find((l) => l.userId === String(idA))?.keyedLookup,
      computeEmailLookup("alice.old@example.com")
    );
    assert.deepEqual(await store.findByUserId(String(idA)), initialDoc);
  });

  it("preserves verified-email flow when protected storage is disabled", async () => {
    const idA = new ObjectId();
    const mongo = createTransactionalMongo([
      { _id: idA, name: "Plaintext User", email: "plain.old@example.com", emailVerified: true, tokenVersion: 1 },
    ]);
    const emailHandlers = createEmailChangeHandlers({
      getDb: async () => mongo.db,
      startSession: mongo.startSession,
      resolveOwner: async () => ({ ok: true, userId: String(idA), sessionId: "sess-a", contextId: "ctx-a" }),
      verifyPassword: async () => true,
    });
    const app = new Hono();
    app.post("/email-change/request", emailHandlers.requestEmailChange);
    app.post("/email-change/confirm", emailHandlers.confirmEmailChange);

    await app.request("/email-change/request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ newEmail: "plain.new@example.com", password: "ValidPassword123!" }),
    });
    const { getTestMailSinkMessages } = await import("../../src/identity/mail-service");
    const mail = getTestMailSinkMessages().findLast((m) => m.to === "plain.new@example.com")!;
    const tok = mail.text.match(/token:\s*([^\s)]+)/)![1];

    const res = await app.request("/email-change/confirm", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: tok }),
    });
    assert.equal(res.status, 200);
    assert.equal(mongo.getState().users[0].email, "plain.new@example.com");
  });
});
