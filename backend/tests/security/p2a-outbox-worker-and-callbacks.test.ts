import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P2a: Transactional Outbox, Leased Worker, Retries & Suppression Callbacks", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let setTestMailTransportOverride: any;
  let setMailWorkerAutoDispatchForTesting: any;
  let processNextMailOutboxJob: any;
  let getTestMailSinkMessages: any;
  let clearTestMailSink: any;
  const gatewaySecret = "g".repeat(32);
  const webhookSecret = "webhook-hmac-secret-ref-key-0004";
  let ipCounter = 300;

  const hdrs = (extra: Record<string, string> = {}) => ({
    "Content-Type": "application/json",
    "x-gateway-secret": gatewaySecret,
    "x-forwarded-for": `198.51.103.${(++ipCounter % 240) + 1}, 10.0.0.1`,
    Origin: "http://localhost:5174",
    "x-csrf-token": "test-csrf",
    ...extra,
  });

  function signCallback(payload: string, tsSec: number, nonce: string) {
    const bodyHash = crypto.createHash("sha256").update(payload).digest("hex");
    return crypto.createHmac("sha256", webhookSecret).update(`${tsSec}.${nonce}.${bodyHash}`).digest("hex");
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p2a_outbox_worker");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName, BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000", FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret, TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      IDENTITY_REGISTRATION_MODE: "verified", IDENTITY_OTP_VERIFIER_KEY_REF: "otp-verifier-secret-ref-key-0001",
      IDENTITY_LOOKUP_KEY_REF: "lookup-hmac-secret-ref-key-0002", IDENTITY_MAIL_PAYLOAD_KEY_REF: "mail-aead-secret-ref-key-0003",
      IDENTITY_MAIL_WEBHOOK_KEY_REF: webhookSecret, IDENTITY_MAIL_TRANSPORT: "test_sink",
      IDENTITY_MAIL_FROM: "no-reply@swyra.test", IDENTITY_GLOBAL_MAIL_DAILY_BUDGET: "500",
    });
    const mongoMod = await import("../../src/db/mongo");
    closeDb = mongoMod.closeDb; setTestDbOverride = mongoMod.setTestDbOverride;
    const mailMod = await import("../../src/identity/mail-service");
    setTestMailTransportOverride = mailMod.setTestMailTransportOverride;
    setMailWorkerAutoDispatchForTesting = mailMod.setMailWorkerAutoDispatchForTesting;
    processNextMailOutboxJob = mailMod.processNextMailOutboxJob;
    getTestMailSinkMessages = mailMod.getTestMailSinkMessages;
    clearTestMailSink = mailMod.clearTestMailSink;
    app = (await import("../../src/app")).default;
    client = suite.client; db = client.db(suite.dbName); setTestDbOverride(db);
  });

  beforeEach(async () => {
    setMailWorkerAutoDispatchForTesting(false);
    setTestMailTransportOverride(null);
    clearTestMailSink();
    for (const col of ["registration_intents", "mail_outbox", "mail_budgets", "mail_suppressions", "mail_callback_events"]) {
      await db.collection(col).deleteMany({});
    }
  });

  after(async () => {
    if (setMailWorkerAutoDispatchForTesting) setMailWorkerAutoDispatchForTesting(true);
    if (setTestMailTransportOverride) setTestMailTransportOverride(null);
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("rolls back budget and intent cleanly when outbox write fails and deduplicates on idempotency key", async () => {
    const outboxFailProxy = new Proxy(db, {
      get(t, p) {
        if (p === "collection") {
          return (name: string) => {
            const c = t.collection(name);
            if (name !== "mail_outbox") return c;
            return new Proxy(c, {
              get(ct, cp) {
                if (cp === "insertOne") return async () => { throw new Error("Simulated outbox disk failure"); };
                const v = (ct as any)[cp]; return typeof v === "function" ? v.bind(ct) : v;
              },
            });
          };
        }
        const v = (t as any)[p]; return typeof v === "function" ? v.bind(t) : v;
      },
    });
    setTestDbOverride(outboxFailProxy);
    try {
      const r = await app.request("/api/identity/registration/start", {
        method: "POST", headers: hdrs(), body: JSON.stringify({ email: "txfail@example.com", acceptedTermsVersion: "v1" }),
      });
      assert.equal(r.status, 503);
    } finally { setTestDbOverride(db); }
    assert.equal(await db.collection("registration_intents").countDocuments(), 0);
    assert.equal(await db.collection("mail_budgets").countDocuments(), 0);
    assert.equal(await db.collection("mail_outbox").countDocuments(), 0);

    const idemKey = `idem-${crypto.randomBytes(6).toString("hex")}`;
    const first = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs({ "Idempotency-Key": idemKey }),
      body: JSON.stringify({ email: "idem@example.com", acceptedTermsVersion: "v1" }),
    });
    assert.equal(first.status, 202);
    const cookie = (first.headers.get("set-cookie") || "").split(";")[0];
    const dup = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs({ "Idempotency-Key": idemKey, Cookie: cookie }),
      body: JSON.stringify({ email: "idem@example.com", acceptedTermsVersion: "v1" }),
    });
    assert.equal(dup.status, 202);
    assert.equal((await dup.json()).intentId, (await first.json()).intentId);
    assert.equal(await db.collection("mail_outbox").countDocuments(), 1, "Idempotent repeat must enqueue only one outbox job");
  });

  it("enforces worker lease fencing, deadline expiry, superseded discard, bounded retries, and payload scrubbing", async () => {
    const r = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: "retry@example.com", acceptedTermsVersion: "v1" }),
    });
    assert.equal(r.status, 202);
    const { intentId } = await r.json();

    let calls = 0;
    const seenKeys = new Set<string>();
    setTestMailTransportOverride({
      async send(_msg: any, idempotencyKey: string, deadlineMs: number) {
        calls++;
        seenKeys.add(idempotencyKey);
        assert.ok(deadlineMs > Date.now());
        const err: any = new Error("Simulated transient 5s timeout");
        err.transient = true;
        throw err;
      },
    });

    for (let i = 0; i < 3; i++) {
      await db.collection("mail_outbox").updateOne({ intentId }, { $set: { nextAttemptAt: new Date(Date.now() - 10) } });
      await processNextMailOutboxJob();
    }
    assert.equal(calls, 3, "Must retry at most 3 total attempts");
    assert.equal(seenKeys.size, 1, "All retries must reuse the exact same idempotencyKey");
    const dead = await db.collection("mail_outbox").findOne({ intentId });
    assert.equal(dead?.status, "dead_letter");
    assert.equal(dead?.encryptedPayload, undefined, "Dead-letter jobs must scrub encrypted payload");

    // Expired deadline job drops cleanly before decrypt/send
    setTestMailTransportOverride(null);
    const rExp = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: "drop@example.com", acceptedTermsVersion: "v1" }),
    });
    const { intentId: dropId } = await rExp.json();
    await db.collection("mail_outbox").updateOne({ intentId: dropId }, { $set: { deadline: new Date(Date.now() - 1000) } });
    await processNextMailOutboxJob();
    const dropped = await db.collection("mail_outbox").findOne({ intentId: dropId });
    assert.equal(dropped?.status, "discarded");
    assert.equal(dropped?.encryptedPayload, undefined);
    assert.equal(getTestMailSinkMessages().length, 0);

    // Lost-lease worker recovery: crashed/expired lease is reclaimed with incremented fence and delivered cleanly
    const rRec = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: "recover@example.com", acceptedTermsVersion: "v1" }),
    });
    const { intentId: recId } = await rRec.json();
    await db.collection("mail_outbox").updateOne(
      { intentId: recId },
      { $set: { status: "sending", leaseOwner: "crashed-worker", fence: 1, leaseExpiry: new Date(Date.now() - 5000) } }
    );
    await processNextMailOutboxJob();
    const recDoc = await db.collection("mail_outbox").findOne({ intentId: recId });
    assert.equal(recDoc?.status, "sent", "Recovered worker must complete delivery");
    assert.equal(recDoc?.fence, 2, "Reclaimed lease must bump monotonic fence token");
    assert.equal(recDoc?.encryptedPayload, undefined);
  });

  it("verifies authenticated bounce/complaint webhooks, blocks replay/forged signatures, and suppresses silently", async () => {
    const targetEmail = "bounce@example.com";
    const sRes = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: targetEmail, acceptedTermsVersion: "v1" }),
    });
    assert.equal(sRes.status, 202);
    await processNextMailOutboxJob();
    const jobDoc = await db.collection("mail_outbox").findOne({});
    assert.ok(jobDoc?.providerMessageId);

    const payload = JSON.stringify({ eventId: "evt-bounce-1", type: "bounce", bounceType: "hard", providerMessageId: jobDoc.providerMessageId, purpose: "registration" });
    const tsSec = Math.floor(Date.now() / 1000);
    const nonce = "nonce-1";

    const forged = await app.request("/api/identity/mail/callbacks", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Mail-Timestamp": String(tsSec), "X-Mail-Nonce": nonce, "X-Mail-Signature": "0".repeat(64) },
      body: payload,
    });
    assert.equal(forged.status, 401);

    const validSig = signCallback(payload, tsSec, nonce);
    const ok = await app.request("/api/identity/mail/callbacks", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Mail-Timestamp": String(tsSec), "X-Mail-Nonce": nonce, "X-Mail-Signature": validSig },
      body: payload,
    });
    assert.equal(ok.status, 200);

    const replay = await app.request("/api/identity/mail/callbacks", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Mail-Timestamp": String(tsSec), "X-Mail-Nonce": nonce, "X-Mail-Signature": validSig },
      body: payload,
    });
    assert.equal(replay.status, 409, "Replayed callback event must be rejected");

    clearTestMailSink();
    process.env.IDENTITY_MAIL_RESEND_SECONDS = "1";
    await new Promise((r) => setTimeout(r, 1100));
    const afterBounce = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: targetEmail, acceptedTermsVersion: "v1" }),
    });
    process.env.IDENTITY_MAIL_RESEND_SECONDS = "60";
    assert.equal(afterBounce.status, 202, "Suppressed address must still receive generic 202");
    await processNextMailOutboxJob();
    assert.equal(getTestMailSinkMessages().length, 0, "Suppressed address must emit 0 deliveries");
  });
});
