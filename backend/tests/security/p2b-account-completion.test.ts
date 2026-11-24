import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P2b: Transactional Verified Account Completion", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let getTestMailSinkMessages: any;
  let clearTestMailSink: any;
  let setRegistrationCompleteTestHooks: any;
  let ipCounter = 10;
  const gatewaySecret = "g".repeat(32);
  const strongPassword = "Valid!P2b#Password99";

  const hdrs = (extra: Record<string, string> = {}) => ({
    "Content-Type": "application/json",
    "x-gateway-secret": gatewaySecret,
    "x-forwarded-for": `198.51.110.${(++ipCounter % 240) + 1}, 10.0.0.1`,
    Origin: "http://localhost:5174",
    "x-csrf-token": "test-csrf",
    ...extra,
  });

  function extractCookie(res: Response, name: string): string {
    for (const part of (res.headers.get("set-cookie") || "").split(/,(?=[^;]+=)/)) {
      const kv = part.trim().split(";")[0];
      if (kv.startsWith(`${name}=`)) return kv;
    }
    return "";
  }

  async function verifyEmailFlow(email: string) {
    const startRes = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs({ "Idempotency-Key": `start-${crypto.randomUUID()}` }),
      body: JSON.stringify({ email, acceptedTermsVersion: "v1" }),
    });
    assert.equal(startRes.status, 202);
    const { intentId } = (await startRes.json()) as { intentId: string };
    const browserCookie = extractCookie(startRes, "swyra_reg_browser");
    let code = "";
    for (let i = 0; i < 30 && !code; i++) {
      const msg = getTestMailSinkMessages().filter((m: any) => m.to === email).at(-1);
      if (msg) code = msg.text.match(/\b(\d{6})\b/)?.[1] || "";
      else await new Promise((r) => setTimeout(r, 30));
    }
    assert.ok(code, `Expected OTP for ${email}`);
    const verifyRes = await app.request("/api/identity/registration/verify", {
      method: "POST", headers: hdrs({ Cookie: browserCookie }), body: JSON.stringify({ intentId, code }),
    });
    assert.equal(verifyRes.status, 200);
    const proofCookie = extractCookie(verifyRes, "swyra_reg_proof");
    return { intentId, cookieHeader: `${browserCookie}; ${proofCookie}` };
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p2b_completion");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName,
      BETTER_AUTH_SECRET: "a".repeat(32), BETTER_AUTH_URL: "http://localhost:3000",
      FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret,
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      IDENTITY_REGISTRATION_MODE: "verified",
      IDENTITY_OTP_VERIFIER_KEY_REF: "p2b-otp-key-ref-0000000000000001",
      IDENTITY_LOOKUP_KEY_REF: "p2b-lookup-key-ref-0000000000002",
      IDENTITY_MAIL_PAYLOAD_KEY_REF: "p2b-aead-key-ref-000000000000003",
      IDENTITY_MAIL_WEBHOOK_KEY_REF: "p2b-hook-key-ref-000000000000004",
      IDENTITY_MAIL_TRANSPORT: "test_sink",
      IDENTITY_GLOBAL_MAIL_DAILY_BUDGET: "500",
    });
    ({ closeDb, setTestDbOverride } = await import("../../src/db/mongo"));
    ({ getTestMailSinkMessages, clearTestMailSink } = await import("../../src/identity/mail-service"));
    ({ setRegistrationCompleteTestHooks } = await import("../../src/identity/registration-complete"));
    app = (await import("../../src/app")).default;
    client = suite.client; db = client.db(suite.dbName); setTestDbOverride(db);
  });

  after(async () => { setRegistrationCompleteTestHooks(null); await closeDb(); await suite.cleanup(); });

  beforeEach(async () => {
    setRegistrationCompleteTestHooks(null);
    process.env.IDENTITY_REGISTRATION_MODE = "verified";
    clearTestMailSink();
    for (const col of await db.listCollections().toArray()) await db.collection(col.name).deleteMany({});
  });

  it("atomically commits verified user, credential, profile, lookups, audit/outbox, and establishes ordinary session", async () => {
    const email = "alice.verified@example.com";
    const { intentId, cookieHeader } = await verifyEmailFlow(email);
    const res = await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: cookieHeader, "Idempotency-Key": "complete-alice-1" }),
      body: JSON.stringify({
        email: "attacker@evil.example", role: "super-admin", emailVerified: false,
        username: "Alice_Dev01", password: strongPassword, acceptedTermsVersion: "v1",
      }),
    });
    assert.equal(res.status, 201);
    const body = (await res.json()) as any;
    assert.equal(body.completed, true);
    assert.equal(body.sessionEstablished, true);
    assert.equal(body.user.role, "user");
    assert.equal(body.user.username, "Alice_Dev01");

    const userDoc = await db.collection("user").findOne({ email });
    assert.ok(userDoc, "Derived intent email must be used, never client body email");
    assert.equal(await db.collection("user").findOne({ email: "attacker@evil.example" }), null);
    assert.equal(userDoc.role, "user");
    assert.equal(userDoc.scopedClientId ?? null, null);
    assert.equal(userDoc.emailVerified, true);

    const uid = String(userDoc._id);
    assert.equal(await db.collection("account").countDocuments({ userId: { $in: [uid, userDoc._id] }, providerId: "credential" }), 1);
    const profile = await db.collection("identity_profiles").findOne({ userId: uid });
    assert.equal(profile?.keyRef, null);
    assert.equal(await db.collection("identity_lookup").countDocuments({ userId: uid }), 2);
    assert.equal(await db.collection("user_app_registrations").countDocuments(), 0);
    assert.equal(await db.collection("app_admins").countDocuments(), 0);

    const intentAfter = await db.collection("registration_intents").findOne({ intentId });
    assert.equal(intentAfter?.status, "consumed");
    assert.equal(intentAfter?.proofDigest ?? null, null);

    const auditEv = await db.collection("auth_events").findOne({ eventType: "registration_complete", userId: uid });
    assert.ok(auditEv && !JSON.stringify(auditEv).includes(email));
    assert.equal(await db.collection("identity_outbox").countDocuments({ eventType: "identity.account_created", userId: uid }), 1);
    assert.ok(extractCookie(res, "better-auth.session_token"));

    const loginRes = await app.request("/api/auth/sign-in/email", { method: "POST", headers: hdrs(), body: JSON.stringify({ email, password: strongPassword }) });
    assert.equal(loginRes.status, 200);
  });

  it("validates browser binding, proof, and syntax before hashing password, and rechecks proof at commit", async () => {
    let hashCalls = 0;
    setRegistrationCompleteTestHooks({ onBeforePasswordHash: () => { hashCalls++; } });
    assert.equal((await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ username: "gooduser", password: strongPassword, acceptedTermsVersion: "v1" }),
    })).status, 403);
    assert.equal(hashCalls, 0);

    const { cookieHeader, intentId } = await verifyEmailFlow("prehash@example.com");
    assert.equal((await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: cookieHeader }), body: JSON.stringify({ username: "gooduser", password: "weak", acceptedTermsVersion: "v1" }),
    })).status, 400);
    assert.equal((await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: cookieHeader }), body: JSON.stringify({ username: "not@anemail", password: strongPassword, acceptedTermsVersion: "v1" }),
    })).status, 400);
    assert.equal(hashCalls, 0);

    setRegistrationCompleteTestHooks({
      onBeforePasswordHash: () => { hashCalls++; },
      onBeforeCommitTransaction: async () => {
        await db.collection("registration_intents").updateOne({ intentId }, { $set: { proofExpiresAt: new Date(Date.now() - 1000) } });
      },
    });
    const rStale = await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: cookieHeader }), body: JSON.stringify({ username: "gooduser", password: strongPassword, acceptedTermsVersion: "v1" }),
    });
    assert.ok(rStale.status >= 400);
    assert.equal(hashCalls, 1);
    assert.equal(await db.collection("user").countDocuments(), 0);
  });

  it("preserves proof on username collision, resolves concurrent two-intent username race, and enforces email uniqueness", async () => {
    const u1 = await verifyEmailFlow("one@example.com");
    assert.equal((await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: u1.cookieHeader }), body: JSON.stringify({ username: "SharedName", password: strongPassword, acceptedTermsVersion: "v1" }),
    })).status, 201);

    const u2 = await verifyEmailFlow("two@example.com");
    const collide = await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: u2.cookieHeader }), body: JSON.stringify({ username: "sharedname", password: strongPassword, acceptedTermsVersion: "v1" }),
    });
    assert.equal(collide.status, 409);
    const intent2 = await db.collection("registration_intents").findOne({ intentId: u2.intentId });
    assert.equal(intent2?.status, "verified");
    assert.ok(intent2?.proofDigest);
    assert.equal((await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: u2.cookieHeader }), body: JSON.stringify({ username: "unique_two", password: strongPassword, acceptedTermsVersion: "v1" }),
    })).status, 201);

    // Concurrent same-intent race produces one account
    const u3 = await verifyEmailFlow("race@example.com");
    const [a, b] = await Promise.all([
      app.request("/api/identity/registration/complete", { method: "POST", headers: hdrs({ Cookie: u3.cookieHeader }), body: JSON.stringify({ username: "race_a", password: strongPassword, acceptedTermsVersion: "v1" }) }),
      app.request("/api/identity/registration/complete", { method: "POST", headers: hdrs({ Cookie: u3.cookieHeader }), body: JSON.stringify({ username: "race_b", password: strongPassword, acceptedTermsVersion: "v1" }) }),
    ]);
    assert.equal([a.status, b.status].filter((s) => s === 201).length, 1);

    // Concurrent different-intent username race: one wins, loser gets ERR_USERNAME_TAKEN and keeps usable proof
    const [cA, cB] = await Promise.all([verifyEmailFlow("conca@example.com"), verifyEmailFlow("concb@example.com")]);
    const [rCA, rCB] = await Promise.all([
      app.request("/api/identity/registration/complete", { method: "POST", headers: hdrs({ Cookie: cA.cookieHeader }), body: JSON.stringify({ username: "concurrent_u", password: strongPassword, acceptedTermsVersion: "v1" }) }),
      app.request("/api/identity/registration/complete", { method: "POST", headers: hdrs({ Cookie: cB.cookieHeader }), body: JSON.stringify({ username: "CONCURRENT_U", password: strongPassword, acceptedTermsVersion: "v1" }) }),
    ]);
    assert.equal([rCA.status, rCB.status].filter((s) => s === 201).length, 1);
    const loserRes = rCA.status === 201 ? rCB : rCA;
    const loserCtx = rCA.status === 201 ? cB : cA;
    assert.equal(loserRes.status, 409);
    assert.equal(((await loserRes.json()) as any).code, "ERR_USERNAME_TAKEN");
    assert.equal((await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: loserCtx.cookieHeader }), body: JSON.stringify({ username: "concurrent_u_alt", password: strongPassword, acceptedTermsVersion: "v1" }),
    })).status, 201);

    // Duplicate email second intent fails cleanly
    await db.collection("mail_budgets").deleteMany({});
    clearTestMailSink();
    const u3Dup = await verifyEmailFlow("race@example.com");
    assert.equal((await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: u3Dup.cookieHeader }), body: JSON.stringify({ username: "unused_handle", password: strongPassword, acceptedTermsVersion: "v1" }),
    })).status, 409);
  });

  it("rolls back failed tx cleanly, supports idempotent lost-response retry, and preserves committed account when session fails", async () => {
    const uFail = await verifyEmailFlow("rollback@example.com");
    setRegistrationCompleteTestHooks({ onInsideTransactionAfterUser: () => { throw new Error("simulated credential/outbox write failure"); } });
    assert.equal((await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: uFail.cookieHeader }), body: JSON.stringify({ username: "roll_back", password: strongPassword, acceptedTermsVersion: "v1" }),
    })).status, 500);
    for (const col of ["user", "account", "identity_profiles", "identity_lookup", "auth_events", "identity_outbox", "session"]) {
      assert.equal(await db.collection(col).countDocuments(), 0, `${col} must roll back`);
    }
    assert.equal((await db.collection("registration_intents").findOne({ intentId: uFail.intentId }))?.status, "verified");

    setRegistrationCompleteTestHooks({ onSessionCreate: () => { throw new Error("transient session failure"); } });
    const uOk = await verifyEmailFlow("sessionfail@example.com");
    const idem = `idem-${crypto.randomUUID()}`;
    const c1 = await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: uOk.cookieHeader, "Idempotency-Key": idem }),
      body: JSON.stringify({ username: "survivor_01", password: strongPassword, acceptedTermsVersion: "v1" }),
    });
    assert.equal(c1.status, 201);
    const b1 = (await c1.json()) as any;
    assert.equal(b1.completed, true);
    assert.equal(b1.sessionEstablished, false);
    assert.equal(b1.requiresSignIn, true);
    assert.equal(await db.collection("user").countDocuments(), 1);

    const c2 = await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: uOk.cookieHeader, "Idempotency-Key": idem }),
      body: JSON.stringify({ username: "survivor_01", password: strongPassword, acceptedTermsVersion: "v1" }),
    });
    assert.equal(c2.status, 200);
    const b2 = (await c2.json()) as any;
    assert.equal(b2.idempotentReplay, true);
    assert.equal(b2.requiresSignIn, true);
    assert.equal(await db.collection("user").countDocuments(), 1);

    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: "sessionfail@example.com", password: strongPassword }),
    });
    assert.equal(loginRes.status, 200);
  });
});
