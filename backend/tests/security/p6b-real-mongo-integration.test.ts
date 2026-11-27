import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import { prepareOwnerExport } from "../../src/identity/owner-export";
import { MongoProfileCollection } from "../../src/identity/protected-profile-store";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P6b Real MongoDB Replica-Set Integration", { timeout: 60_000 }, () => {
  let suiteCtx: SuiteDatabaseContext;
  let db: any;
  let mongoClient: any;

  before(async () => {
    process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
    process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
    process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
    process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
    process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
    isolateTestEnvironment();
    process.env.NODE_ENV = "test";
    process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
    process.env.IDENTITY_REGISTRATION_MODE = "verified";

    suiteCtx = await setupSuiteDatabase("p6b_real_mongo");
    const mongoMod = await import("../../src/db/mongo");
    db = await mongoMod.getDb();
    mongoClient = mongoMod.client;
  });

  after(async () => {
    const { closeDb } = await import("../../src/db/mongo");
    await closeDb();
    await suiteCtx?.cleanup();
  });

  it("rolls back protected registration on outage, commits on retry, and preserves independent concurrent name/email updates in real Mongo", async () => {
    const { computeBrowserBindingHash, computeEmailLookup, digestToken, encryptContactEmail } = await import(
      "../../src/identity/registration-crypto"
    );
    const { completeVerifiedRegistration } = await import("../../src/identity/registration-complete");
    const { createOwnerProfileHandlers } = await import("../../src/routes/identity-owner-portal");
    const { createEmailChangeHandlers } = await import("../../src/routes/identity-email-change");
    const { createOAuthUserInfoHandler } = await import("../../src/routes/auth-userinfo");
    const { getTestMailSinkMessages } = await import("../../src/identity/mail-service");

    const provider = new InMemoryAccountKeyProvider();
    const store = new MongoProfileCollection(db);
    const rawBrowser = "real-mongo-browser-1";
    const rawProof = "real-mongo-proof-1";
    const intentId = "real-mongo-intent-1";
    const oldEmail = "real.alice.old@example.com";
    const newEmail = "real.alice.new@example.com";
    const emailLookup = computeEmailLookup(oldEmail);

    await db.collection("registration_intents").insertOne({
      intentId,
      browserBindingHash: computeBrowserBindingHash(rawBrowser),
      proofDigest: digestToken(rawProof, "proof"),
      status: "verified",
      emailLookup,
      encryptedEmail: encryptContactEmail(oldEmail, { intentId, emailLookup }),
      termsVersion: "v1",
      expiresAt: new Date(Date.now() + 600_000),
      proofExpiresAt: new Date(Date.now() + 600_000),
    });

    // 1. Key provider outage aborts real MongoDB multi-document transaction
    provider.setOutage(true);
    const failRes = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "RealAlice",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "real-idem-1",
        clientIp: "198.51.100.1",
        userAgent: "real-mongo-test",
        requestHeaders: new Headers(),
        requestId: "real-req-1",
      },
      {
        getDb: async () => db,
        signInEmail: async () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );
    assert.equal(failRes.status, 503);
    assert.equal(failRes.body.code, "ERR_KEY_PROVIDER_UNAVAILABLE");
    assert.equal(await db.collection("user").countDocuments({}), 0);
    assert.equal(await db.collection("account").countDocuments({}), 0);
    assert.equal(await db.collection("identity_lookup").countDocuments({}), 0);
    assert.equal(await db.collection("identity_profiles").countDocuments({}), 0);
    assert.equal((await db.collection("registration_intents").findOne({ intentId }))?.status, "verified");

    // 2. Recover provider and commit verified registration in real MongoDB
    provider.setOutage(false);
    const okRes = await completeVerifiedRegistration(
      {
        rawBrowser,
        rawProof,
        username: "RealAlice",
        password: "Strong!Password#2026",
        acceptedTermsVersion: "v1",
        idempotencyKey: "real-idem-1",
        clientIp: "198.51.100.1",
        userAgent: "real-mongo-test",
        requestHeaders: new Headers(),
        requestId: "real-req-2",
      },
      {
        getDb: async () => db,
        signInEmail: async () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
        protectedProfileStore: store,
        accountKeyProvider: provider,
      }
    );
    assert.equal(okRes.status, 201, JSON.stringify(okRes.body));
    const userId = String((okRes.body.user as any).id);
    const initialProfile = await db.collection("identity_profiles").findOne({ userId });
    assert.ok(initialProfile?.nameEnvelope && initialProfile?.emailEnvelope);

    // 3. Concurrent PATCH /me (display name) and POST /email-change/confirm in real MongoDB
    const profileHandlers = createOwnerProfileHandlers({
      getDb: async () => db,
      startSession: () => mongoClient.startSession(),
      resolveOwner: async () => ({ ok: true, userId, sessionId: "sess-real" }),
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    });
    const emailHandlers = createEmailChangeHandlers({
      getDb: async () => db,
      startSession: () => mongoClient.startSession(),
      resolveOwner: async () => ({ ok: true, userId, sessionId: "sess-real", contextId: "ctx-real" }),
      verifyPassword: async () => true,
      protectedProfileStore: store,
      accountKeyProvider: provider,
    });

    const app = new Hono();
    app.get("/me", profileHandlers.getOwnerMe);
    app.patch("/me", profileHandlers.patchOwnerMe);
    app.post("/email-change/request", emailHandlers.requestEmailChange);
    app.post("/email-change/confirm", emailHandlers.confirmEmailChange);

    const reqEmailRes = await app.request("/email-change/request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ newEmail, password: "Strong!Password#2026" }),
    });
    assert.equal(reqEmailRes.status, 200);
    const mail = getTestMailSinkMessages().findLast((m) => m.to === newEmail)!;
    const tok = mail.text.match(/token:\s*([^\s)]+)/)![1];

    const runNamePatch = () =>
      app.request("/me", {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "Alice Real Mongo Name" }),
      });
    const runEmailConfirm = () =>
      app.request("/email-change/confirm", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: tok }),
      });

    const [pRes, eRes] = await Promise.all([runNamePatch(), runEmailConfirm()]);
    if (pRes.status !== 200) {
      assert.equal((await runNamePatch()).status, 200);
    }
    if (eRes.status !== 200) {
      assert.equal((await runEmailConfirm()).status, 200);
    }

    // 4. Verify final committed state in real MongoDB, GET /me, export, and UserInfo
    const finalUser = await db.collection("user").findOne({ _id: new ObjectId(userId) });
    assert.equal(finalUser?.email, newEmail);
    const finalLookup = await db.collection("identity_lookup").findOne({ kind: "email", userId });
    assert.equal(finalLookup?.keyedLookup, computeEmailLookup(newEmail));
    const finalProfile = await db.collection("identity_profiles").findOne({ userId });
    assert.equal(JSON.stringify(finalProfile?.nameEnvelope).includes("Alice Real Mongo Name"), false);
    assert.equal(JSON.stringify(finalProfile?.emailEnvelope).includes(newEmail), false);

    const meRes = await app.request("/me", { method: "GET" });
    assert.equal(meRes.status, 200);
    const meBody = await meRes.json();
    assert.equal(meBody.name, "Alice Real Mongo Name");
    assert.equal(meBody.email, newEmail);

    const exported = await prepareOwnerExport(db, userId, {
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    });
    assert.equal(exported?.profile.name, "Alice Real Mongo Name");
    assert.equal(exported?.profile.email, newEmail);

    const uiApp = new Hono();
    uiApp.get(
      "/userinfo",
      createOAuthUserInfoHandler({
        getDb: async () => db,
        authHandler: async () =>
          new Response(JSON.stringify({ sub: userId, client_id: "c1" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        resolveClient: async () => ({ clientId: "c1", disabled: false, isAmbiguous: false }),
        checkPrivateAccess: async () => true,
        resolveRole: async () => ({ role: "user", scopedClientId: null }),
        protectedProfileStore: store,
        accountKeyProvider: provider,
        migrationMode: "strict",
      })
    );
    await db.collection("oauthAccessToken").insertOne({
      token: "ui-tok-1",
      clientId: "c1",
      scopes: "openid profile email",
      createdAt: new Date(),
      tokenVersion: finalUser.tokenVersion,
    });
    const uiRes = await uiApp.request("/userinfo", { headers: { Authorization: "Bearer ui-tok-1" } });
    assert.equal(uiRes.status, 200);
    const uiBody = await uiRes.json();
    assert.equal(uiBody.name, "Alice Real Mongo Name");
    assert.equal(uiBody.email, newEmail);
  });
});
