import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import { prepareOwnerExport } from "../../src/identity/owner-export";
import { InMemoryProfileCollection } from "../../src/identity/protected-profile-store";

process.env.NODE_ENV = process.env.NODE_ENV || "test";
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/local_di_unused";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
process.env.IDENTITY_REGISTRATION_MODE = "verified";

const { computeBrowserBindingHash, computeEmailLookup, digestToken, encryptContactEmail } = await import(
  "../../src/identity/registration-crypto"
);
const { completeVerifiedRegistration } = await import("../../src/identity/registration-complete");
const { createOwnerProfileHandlers } = await import("../../src/routes/identity-owner-portal");

function cloneDocs(docs: any[]): any[] {
  return docs.map((d) => ({ ...d }));
}

function createRegistrationFixture(opts?: {
  existingEmail?: string;
  existingUsernameLookup?: string;
  initialSessions?: any[];
  failSessionDelete?: boolean;
}) {
  let state = {
    users: opts?.existingEmail
      ? [{ _id: new ObjectId(), email: opts.existingEmail, name: "Existing", emailVerified: true }]
      : ([] as any[]),
    accounts: [] as any[],
    intents: [] as any[],
    lookups: opts?.existingUsernameLookup
      ? [{ kind: "username", keyVersion: 1, keyedLookup: opts.existingUsernameLookup, userId: "existing-u" }]
      : ([] as any[]),
    profiles: [] as any[],
    events: [] as any[],
    outbox: [] as any[],
    sessions: opts?.initialSessions ? cloneDocs(opts.initialSessions) : ([] as any[]),
  };
  let txState: typeof state | null = null;
  const active = () => txState ?? state;

  const matchesWhere = (doc: any, where: Array<{ field: string; value: any }>) =>
    where.every((w) => doc[w.field] === w.value);

  const modelList = (model: string): any[] => {
    if (model === "user") return active().users;
    if (model === "account") return active().accounts;
    if (model === "registration_intents") return active().intents;
    if (model === "identity_lookup") return active().lookups;
    if (model === "identity_profiles") return active().profiles;
    if (model === "auth_events") return active().events;
    if (model === "identity_outbox") return active().outbox;
    return [];
  };

  const database: any = {
    async createCollection() {},
    collection(name: string) {
      return {
        async createIndex() {},
        async dropIndex() {},
        async deleteOne(query: any) {
          if (name === "session") {
            if (opts?.failSessionDelete) {
              throw new Error("session_delete_db_failure");
            }
            const idx = state.sessions.findIndex((s) => s.token === query.token);
            if (idx >= 0) state.sessions.splice(idx, 1);
          }
        },
        async findOne(query: any) {
          const list = modelList(name);
          return (
            list.find((d) =>
              Object.entries(query).every(([k, v]) => (k === "_id" ? String(d._id) === String(v) : d[k] === v))
            ) ?? null
          );
        },
        find() {
          return { sort() { return { limit() { return { async toArray() { return []; } }; } }; } };
        },
      };
    },
  };

  const txEngine: any = {
    engine: {
      $context: Promise.resolve({
        password: { hash: async (pw: string) => `hashed:${pw}` },
      }),
    },
    boundary: {
      async run(_eng: any, fn: (scope: any) => Promise<void>) {
        txState = {
          users: cloneDocs(state.users),
          accounts: cloneDocs(state.accounts),
          intents: cloneDocs(state.intents),
          lookups: cloneDocs(state.lookups),
          profiles: cloneDocs(state.profiles),
          events: cloneDocs(state.events),
          outbox: cloneDocs(state.outbox),
          sessions: cloneDocs(state.sessions),
        };
        const adapter = {
          async findOne({ model, where }: any) {
            return modelList(model).find((d) => matchesWhere(d, where)) ?? null;
          },
          async create({ model, data }: any) {
            const doc = { ...data, _id: new ObjectId() };
            modelList(model).push(doc);
            return doc;
          },
          async update({ model, where, update }: any) {
            const target = modelList(model).find((d) => matchesWhere(d, where));
            if (!target) return null;
            Object.assign(target, update);
            return target;
          },
        };
        const internalAdapter = {
          async createUser(data: any) {
            const oid = new ObjectId();
            const doc = { ...data, _id: oid, id: String(oid) };
            modelList("user").push(doc);
            return doc;
          },
          async linkAccount(data: any) {
            const doc = { ...data, _id: new ObjectId() };
            modelList("account").push(doc);
            return doc;
          },
        };
        try {
          await fn({ adapter, internalAdapter });
          state = txState;
        } finally {
          txState = null;
        }
      },
    },
  };

  const seedVerifiedIntent = (email: string) => {
    const rawBrowser = "browser-cookie-val-1";
    const rawProof = "proof-token-val-1";
    const intentId = "intent-1";
    const emailLookup = computeEmailLookup(email);
    state.intents.push({
      intentId,
      browserBindingHash: computeBrowserBindingHash(rawBrowser),
      proofDigest: digestToken(rawProof, "proof"),
      status: "verified",
      emailLookup,
      encryptedEmail: encryptContactEmail(email, { intentId, emailLookup }),
      termsVersion: "v1",
      expiresAt: new Date(Date.now() + 600_000),
      proofExpiresAt: new Date(Date.now() + 600_000),
    });
    return { rawBrowser, rawProof };
  };

  const signInEmail = async ({ email }: { email: string; password: string }) => {
    state.sessions.push({ email, createdAt: new Date() });
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  };

  return { database, txEngine, signInEmail, seedVerifiedIntent, getState: () => state };
}

describe("P6b Verified Registration Integration (Local DI)", () => {
  it("creates protected name and email on verified signup, readable via strict GET /me and export, and replays idempotently", async () => {
    const fixture = createRegistrationFixture();
    const { rawBrowser, rawProof } = fixture.seedVerifiedIntent("new.user@example.com");
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();

    const res = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "Alice_Reg",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-reg-1",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-1",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: fixture.signInEmail,
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );

    assert.equal(res.status, 201);
    assert.equal(res.body.completed, true);
    const createdUserId = String((res.body.user as any).id);
    assert.ok(createdUserId);

    // Stored profile has encrypted envelopes and no plaintext
    const storedProfile = await store.findByUserId(createdUserId);
    assert.ok(storedProfile);
    assert.equal(JSON.stringify(storedProfile).includes("Alice_Reg"), false);
    assert.equal(JSON.stringify(storedProfile).includes("new.user@example.com"), false);

    // Strict GET /me and strict prepareOwnerExport return protected name and email
    const handlers = createOwnerProfileHandlers({
      getDb: async () => fixture.database,
      resolveOwner: async () => ({ ok: true, userId: createdUserId, sessionId: "sess-1" }),
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    });
    const meApp = new Hono();
    meApp.get("/me", handlers.getOwnerMe);
    const meRes = await meApp.request("/me");
    assert.equal(meRes.status, 200);
    const meBody = await meRes.json();
    assert.equal(meBody.name, "Alice_Reg");
    assert.equal(meBody.email, "new.user@example.com");

    const exported = await prepareOwnerExport(fixture.database, createdUserId, {
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    });
    assert.equal(exported?.profile.name, "Alice_Reg");
    assert.equal(exported?.profile.email, "new.user@example.com");

    // Retry after lost success response with same idempotencyKey replays without creating duplicate records
    const replay = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "Alice_Reg",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-reg-1",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-2",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: fixture.signInEmail,
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );
    assert.equal(replay.status, 200);
    assert.equal(replay.body.idempotentReplay, true);
    assert.equal(fixture.getState().users.length, 1);
    assert.equal(fixture.getState().profiles.length, 1);
  });

  it("rolls back completely on provider failure and keeps proof verified for retry", async () => {
    const fixture = createRegistrationFixture();
    const { rawBrowser, rawProof } = fixture.seedVerifiedIntent("outage.user@example.com");
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    provider.setOutage(true);

    const failRes = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "OutageUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-outage-1",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-outage",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: fixture.signInEmail,
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );

    assert.equal(failRes.status, 503);
    assert.equal(failRes.body.code, "ERR_KEY_PROVIDER_UNAVAILABLE");
    assert.equal(fixture.getState().users.length, 0);
    assert.equal(fixture.getState().accounts.length, 0);
    assert.equal(fixture.getState().sessions.length, 0);
    assert.equal(fixture.getState().lookups.length, 0);
    assert.equal(fixture.getState().profiles.length, 0);
    assert.equal(fixture.getState().intents[0].status, "verified");

    // Once provider recovers, retry with the same verified proof succeeds
    provider.setOutage(false);
    const okRes = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "OutageUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-outage-1",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-retry",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: fixture.signInEmail,
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );
    assert.equal(okRes.status, 201);
    assert.equal(fixture.getState().users.length, 1);
  });

  it("rejects duplicate email or username with 409 and preserves existing signup when protected storage is disabled", async () => {
    const dupEmailFixture = createRegistrationFixture({ existingEmail: "dup@example.com" });
    const dupCreds = dupEmailFixture.seedVerifiedIntent("dup@example.com");
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();

    const dupEmailRes = await completeVerifiedRegistration(
      {
        rawBrowser: dupCreds.rawBrowser,
        rawProof: dupCreds.rawProof,
        username: "UniqueUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-dup-e",
      },
      {
        getDb: async () => dupEmailFixture.database,
        getTxEngine: async () => dupEmailFixture.txEngine,
        signInEmail: dupEmailFixture.signInEmail,
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );
    assert.equal(dupEmailRes.status, 409);
    assert.equal(dupEmailRes.body.code, "ERR_EMAIL_ALREADY_REGISTERED");
    assert.equal(dupEmailFixture.getState().profiles.length, 0);
    assert.equal(dupEmailFixture.getState().intents[0].status, "verified");

    const { computeUsernameLookup } = await import("../../src/identity/registration-crypto");
    const dupUserFixture = createRegistrationFixture({ existingUsernameLookup: computeUsernameLookup("takenuser") });
    const dupUserCreds = dupUserFixture.seedVerifiedIntent("unique.u@example.com");
    const dupUserRes = await completeVerifiedRegistration(
      {
        rawBrowser: dupUserCreds.rawBrowser,
        rawProof: dupUserCreds.rawProof,
        username: "TakenUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-dup-u",
      },
      {
        getDb: async () => dupUserFixture.database,
        getTxEngine: async () => dupUserFixture.txEngine,
        signInEmail: dupUserFixture.signInEmail,
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );
    assert.equal(dupUserRes.status, 409);
    assert.equal(dupUserRes.body.code, "ERR_USERNAME_TAKEN");
    assert.equal(dupUserFixture.getState().profiles.length, 0);
    assert.equal(dupUserFixture.getState().intents[0].status, "verified");

    // Disabled protected storage preserves existing signup
    const plainFixture = createRegistrationFixture();
    const plainCreds = plainFixture.seedVerifiedIntent("plain.reg@example.com");
    const plainRes = await completeVerifiedRegistration(
      {
        rawBrowser: plainCreds.rawBrowser,
        rawProof: plainCreds.rawProof,
        username: "PlainUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-plain",
      },
      {
        getDb: async () => plainFixture.database,
        getTxEngine: async () => plainFixture.txEngine,
        signInEmail: plainFixture.signInEmail,
      }
    );
    assert.equal(plainRes.status, 201);
    assert.equal(plainFixture.getState().users.length, 1);
    assert.equal(plainFixture.getState().profiles[0].keyRef, null);
  });

  it("preserves committed account and protected profile when signInEmail fails post-commit, and replays idempotently", async () => {
    const fixture = createRegistrationFixture();
    const { rawBrowser, rawProof } = fixture.seedVerifiedIntent("signin.fail@example.com");
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();

    const res = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "SignInFailUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-signin-fail",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-signin-fail",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: async () => {
          throw new Error("signInEmail unavailable");
        },
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );

    assert.equal(res.status, 201);
    assert.equal(res.body.sessionEstablished, false);
    assert.equal(res.body.requiresSignIn, true);
    assert.deepEqual(res.sessionSetCookies ?? [], []);
    assert.equal(res.nextBrowserSessionProof, undefined);

    const createdUserId = String((res.body.user as any).id);
    assert.equal(fixture.getState().users.length, 1);
    assert.equal(fixture.getState().accounts.length, 1);
    assert.equal(fixture.getState().lookups.length, 2);
    assert.equal(fixture.getState().profiles.length, 1);
    assert.equal(fixture.getState().sessions.length, 0);
    assert.equal(fixture.getState().intents[0].status, "consumed");
    assert.ok(await store.findByUserId(createdUserId));

    const replay = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "SignInFailUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-signin-fail",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-signin-fail-replay",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: async () => {
          throw new Error("should not be called on replay");
        },
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );
    assert.equal(replay.status, 200);
    assert.equal(replay.body.idempotentReplay, true);
    assert.equal(replay.body.sessionEstablished, false);
    assert.equal(replay.body.requiresSignIn, true);
    assert.equal(fixture.getState().users.length, 1);
    assert.equal(fixture.getState().profiles.length, 1);
  });

  it("deletes engine session and withholds session cookies when resolveAndEnrollSession throws post-commit, and replays idempotently", async () => {
    const fixture = createRegistrationFixture();
    const { rawBrowser, rawProof } = fixture.seedVerifiedIntent("enroll.fail@example.com");
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();

    const res = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "EnrollFailUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-enroll-fail",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-enroll-fail",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: async ({ email }) => {
          fixture.getState().sessions.push({ token: "eng-tok-1", email, createdAt: new Date() });
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "set-cookie": "better-auth.session_token=eng-tok-1.sig; Path=/; HttpOnly" },
          });
        },
        resolveAndEnrollSession: async () => {
          throw new Error("browser_session_sets write failed");
        },
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );

    assert.equal(res.status, 201);
    assert.equal(res.body.sessionEstablished, false);
    assert.equal(res.body.requiresSignIn, true);
    assert.deepEqual(res.sessionSetCookies ?? [], [], "No usable session cookie may reach caller when enrollment fails");
    assert.equal(res.nextBrowserSessionProof, undefined);
    assert.equal(fixture.getState().sessions.length, 0, "Engine session must be deleted when enrollment fails");

    const createdUserId = String((res.body.user as any).id);
    assert.equal(fixture.getState().users.length, 1);
    assert.equal(fixture.getState().accounts.length, 1);
    assert.equal(fixture.getState().lookups.length, 2);
    assert.equal(fixture.getState().profiles.length, 1);
    assert.equal(fixture.getState().intents[0].status, "consumed");
    assert.ok(await store.findByUserId(createdUserId));

    const replay = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "EnrollFailUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-enroll-fail",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-enroll-fail-replay",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: async () => {
          throw new Error("should not be called on replay");
        },
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );
    assert.equal(replay.status, 200);
    assert.equal(replay.body.idempotentReplay, true);
    assert.equal(replay.body.sessionEstablished, false);
    assert.equal(replay.body.requiresSignIn, true);
    assert.equal(fixture.getState().users.length, 1);
    assert.equal(fixture.getState().profiles.length, 1);
  });

  it("maps Better Auth signed session_token cookie to exact stored token, removing only the new session", async () => {
    const { serializeSignedCookie } = await import("../../node_modules/better-call/dist/cookies.mjs");
    const rawNewToken = "baTokNew9876543210abcdef";
    const serializedCookie = await serializeSignedCookie(
      "better-auth.session_token",
      rawNewToken,
      process.env.BETTER_AUTH_SECRET!,
      { path: "/", httpOnly: true }
    );

    const fixture = createRegistrationFixture({
      initialSessions: [{ token: "existing-session-keep", email: "other@example.com", createdAt: new Date() }],
    });
    const { rawBrowser, rawProof } = fixture.seedVerifiedIntent("signed.cookie@example.com");
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();

    const res = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "SignedCookieUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-signed-cookie",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-signed-cookie",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: async ({ email }) => {
          fixture.getState().sessions.push({ token: rawNewToken, email, createdAt: new Date() });
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "set-cookie": serializedCookie },
          });
        },
        resolveAndEnrollSession: async () => ({
          sessionId: "sess-new",
          userId: "user-new",
          ok: false as const,
          status: "capacity_exceeded" as const,
          capacity: 5,
          entriesCount: 5,
          setId: "set-1",
        }),
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );

    assert.equal(res.status, 201);
    assert.equal(res.body.sessionEstablished, false);
    assert.equal(res.body.requiresSignIn, true);
    assert.deepEqual(res.sessionSetCookies ?? [], []);
    assert.deepEqual(
      fixture.getState().sessions.map((s) => s.token),
      ["existing-session-keep"],
      "Cleanup must remove only the newly created session and preserve existing sessions"
    );
  });

  it("returns 201 with no cookies when enrollment and session cleanup deleteOne both fail, leaving residual server session", async () => {
    const rawNewToken = "baTokResidual1234567890";
    const fixture = createRegistrationFixture({ failSessionDelete: true });
    const { rawBrowser, rawProof } = fixture.seedVerifiedIntent("cleanup.fail@example.com");
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();

    const res = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "CleanupFailUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-cleanup-fail",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-cleanup-fail",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: async ({ email }) => {
          fixture.getState().sessions.push({ token: rawNewToken, email, createdAt: new Date() });
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "set-cookie": `better-auth.session_token=${rawNewToken}.sig; Path=/; HttpOnly` },
          });
        },
        resolveAndEnrollSession: async () => {
          throw new Error("browser_session_sets write failed");
        },
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );

    assert.equal(res.status, 201);
    assert.equal(res.body.sessionEstablished, false);
    assert.equal(res.body.requiresSignIn, true);
    assert.deepEqual(res.sessionSetCookies ?? [], []);
    assert.equal(res.nextBrowserSessionProof, undefined);
    assert.equal(fixture.getState().users.length, 1);
    assert.equal(fixture.getState().profiles.length, 1);
    // Residual server-side session remains when deleteOne itself fails, though no cookie reached caller
    assert.deepEqual(fixture.getState().sessions.map((s) => s.token), [rawNewToken]);

    const replay = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "CleanupFailUser",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "idem-cleanup-fail",
        clientIp: "198.51.100.1",
        userAgent: "test-agent",
        requestHeaders: new Headers(),
        requestId: "req-cleanup-fail-replay",
      },
      {
        getDb: async () => fixture.database,
        getTxEngine: async () => fixture.txEngine,
        signInEmail: async () => {
          throw new Error("should not be called on replay");
        },
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );
    assert.equal(replay.status, 200);
    assert.equal(replay.body.idempotentReplay, true);
    assert.equal(fixture.getState().users.length, 1);
    assert.equal(fixture.getState().profiles.length, 1);
  });
});
