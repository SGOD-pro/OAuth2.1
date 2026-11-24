import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P2a: Registration Intents, OTP Limits, Budgets & Proof Issuance", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let getTestMailSinkMessages: any;
  let clearTestMailSink: any;
  let runMailOutboxPass: any;
  let setMailWorkerAutoDispatchForTesting: any;
  let ipCounter = 100;
  const gatewaySecret = "g".repeat(32);

  const hdrs = (extra: Record<string, string> = {}) => ({
    "Content-Type": "application/json",
    "x-gateway-secret": gatewaySecret,
    "x-forwarded-for": `198.51.102.${(++ipCounter % 240) + 1}, 10.0.0.1`,
    Origin: "http://localhost:5174",
    "x-csrf-token": "test-csrf",
    ...extra,
  });

  async function assertZeroIdentitiesAndSessions(ctxLabel: string) {
    for (const col of ["user", "account", "session", "oauthConsent", "user_app_registrations", "oauthAccessToken", "oauthRefreshToken"]) {
      assert.equal(await db.collection(col).countDocuments(), 0, `${ctxLabel}: ${col} must have 0 documents`);
    }
  }

  function extractCookie(res: Response, name: string): string {
    const raw = res.headers.get("set-cookie") || "";
    const parts = raw.split(/,(?=[^;]+=)/);
    for (const part of parts) {
      const kv = part.trim().split(";")[0];
      if (kv.startsWith(`${name}=`)) return kv;
    }
    return "";
  }

  function extractCodeFromSink(email: string): string {
    const msgs = getTestMailSinkMessages().filter((m: any) => m.to === email);
    const latest = msgs[msgs.length - 1];
    assert.ok(latest, `Expected test_sink email delivered to ${email}`);
    const m = latest.text.match(/\b(\d{6})\b/);
    assert.ok(m, "Expected 6-digit OTP in test_sink text body");
    assert.ok(!latest.text.includes(`code=${m[1]}`), "OTP must never be placed inside a URL");
    return m[1];
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p2a_intents_otp");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName, BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000", FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret, TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      IDENTITY_REGISTRATION_MODE: "disabled", IDENTITY_OTP_VERIFIER_KEY_REF: "otp-verifier-secret-ref-key-0001",
      IDENTITY_LOOKUP_KEY_REF: "lookup-hmac-secret-ref-key-0002", IDENTITY_MAIL_PAYLOAD_KEY_REF: "mail-aead-secret-ref-key-0003",
      IDENTITY_MAIL_WEBHOOK_KEY_REF: "webhook-hmac-secret-ref-key-0004", IDENTITY_MAIL_TRANSPORT: "test_sink",
      IDENTITY_MAIL_FROM: "no-reply@swyra.test", IDENTITY_GLOBAL_MAIL_DAILY_BUDGET: "500",
      IDENTITY_MAIL_RESEND_SECONDS: "60", IDENTITY_OTP_TTL_SECONDS: "300", IDENTITY_INTENT_TTL_SECONDS: "1800", IDENTITY_PROOF_TTL_SECONDS: "600",
    });
    const mongoMod = await import("../../src/db/mongo");
    closeDb = mongoMod.closeDb; setTestDbOverride = mongoMod.setTestDbOverride;
    const mailMod = await import("../../src/identity/mail-service");
    getTestMailSinkMessages = mailMod.getTestMailSinkMessages;
    clearTestMailSink = mailMod.clearTestMailSink;
    runMailOutboxPass = mailMod.runMailOutboxPass;
    setMailWorkerAutoDispatchForTesting = mailMod.setMailWorkerAutoDispatchForTesting;
    app = (await import("../../src/app")).default;
    client = suite.client; db = client.db(suite.dbName); setTestDbOverride(db);
  });

  beforeEach(async () => {
    setMailWorkerAutoDispatchForTesting(false);
    clearTestMailSink();
    process.env.IDENTITY_REGISTRATION_MODE = "verified";
    process.env.IDENTITY_MAIL_RESEND_SECONDS = "60";
    process.env.IDENTITY_GLOBAL_MAIL_DAILY_BUDGET = "500";
    for (const col of ["registration_intents", "mail_outbox", "mail_budgets", "mail_suppressions", "user", "account", "session"]) {
      await db.collection(col).deleteMany({});
    }
  });

  after(async () => {
    if (setMailWorkerAutoDispatchForTesting) setMailWorkerAutoDispatchForTesting(true);
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("enforces default-off registration mode, same-origin CORS, and browser binding", async () => {
    process.env.IDENTITY_REGISTRATION_MODE = "disabled";
    const disRes = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: "off@example.com", acceptedTermsVersion: "v1" }),
    });
    assert.equal(disRes.status, 403);
    assert.equal((await disRes.json()).code, "ERR_REGISTRATION_DISABLED");
    await assertZeroIdentitiesAndSessions("disabled mode");

    process.env.IDENTITY_REGISTRATION_MODE = "verified";
    await db.collection("oauthClient").insertOne({ clientId: "consumer-cors", allowedOrigins: ["https://consumer.example.com"], disabled: false });
    const crossRes = await app.request("/api/identity/registration/start", {
      method: "POST",
      headers: hdrs({ Origin: "https://consumer.example.com" }),
      body: JSON.stringify({ email: "cors@example.com", acceptedTermsVersion: "v1" }),
    });
    assert.equal(crossRes.status, 403, "Consumer CORS origin must never access /api/identity/*");
  });

  it("enforces store failure closed, inline expiry, malformed attempt budget, and zero accounts on failed verify", async () => {
    const failProxyDb = new Proxy(db, {
      get(t, p) {
        if (p === "collection") {
          return (name: string) => {
            const c = t.collection(name);
            if (name !== "mail_budgets") return c;
            return new Proxy(c, {
              get(ct, cp) {
                if (cp === "findOneAndUpdate" || cp === "updateOne" || cp === "insertOne") return async () => { throw new Error("Budget store down"); };
                const v = (ct as any)[cp]; return typeof v === "function" ? v.bind(ct) : v;
              },
            });
          };
        }
        const v = (t as any)[p]; return typeof v === "function" ? v.bind(t) : v;
      },
    });
    setTestDbOverride(failProxyDb);
    try {
      const storeFail = await app.request("/api/identity/registration/start", {
        method: "POST", headers: hdrs(), body: JSON.stringify({ email: "storefail@example.com", acceptedTermsVersion: "v1" }),
      });
      assert.equal(storeFail.status, 503);
    } finally { setTestDbOverride(db); }
    assert.equal(await db.collection("registration_intents").countDocuments(), 0);
    assert.equal(await db.collection("mail_outbox").countDocuments(), 0);
    assert.equal(getTestMailSinkMessages().length, 0);

    const email = "verify-neg@example.com";
    const startRes = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email, acceptedTermsVersion: "v1" }),
    });
    assert.equal(startRes.status, 202);
    assert.equal(startRes.headers.get("cache-control"), "no-store");
    const browserCookie = extractCookie(startRes, "swyra_reg_browser");
    assert.ok(browserCookie, "Must set HttpOnly browser binding cookie");
    const { intentId } = await startRes.json();
    await runMailOutboxPass();
    const realCode = extractCodeFromSink(email);

    const noCookie = await app.request("/api/identity/registration/verify", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ intentId, code: realCode }),
    });
    assert.equal(noCookie.status, 403, "Guessed handle without browser binding cookie must fail");

    const malformed = await app.request("/api/identity/registration/verify", {
      method: "POST", headers: hdrs({ Cookie: browserCookie }), body: JSON.stringify({ intentId, code: "12ab" }),
    });
    assert.equal(malformed.status, 400);
    let intentDoc = await db.collection("registration_intents").findOne({ intentId });
    assert.equal(intentDoc?.attemptCount, 1, "Malformed OTP must consume generation attempt budget");

    for (let i = 0; i < 4; i++) {
      const w = await app.request("/api/identity/registration/verify", {
        method: "POST", headers: hdrs({ Cookie: browserCookie }), body: JSON.stringify({ intentId, code: "000000" === realCode ? "000001" : "000000" }),
      });
      assert.equal(w.status, 400);
    }
    intentDoc = await db.collection("registration_intents").findOne({ intentId });
    assert.equal(intentDoc?.status, "exhausted", "5 failed tries must exhaust generation");

    const afterExhaust = await app.request("/api/identity/registration/verify", {
      method: "POST", headers: hdrs({ Cookie: browserCookie }), body: JSON.stringify({ intentId, code: realCode }),
    });
    assert.equal(afterExhaust.status, 400, "Correct code after exhaustion must be rejected");
    await assertZeroIdentitiesAndSessions("after failed/exhausted OTP verification");

    // Inline expiry test without waiting for Mongo TTL
    const start2 = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: "exp@example.com", acceptedTermsVersion: "v1" }),
    });
    const cookie2 = extractCookie(start2, "swyra_reg_browser");
    const { intentId: id2 } = await start2.json();
    await runMailOutboxPass();
    const code2 = extractCodeFromSink("exp@example.com");
    await db.collection("registration_intents").updateOne({ intentId: id2 }, { $set: { otpExpiresAt: new Date(Date.now() - 1000) } });
    const expRes = await app.request("/api/identity/registration/verify", {
      method: "POST", headers: hdrs({ Cookie: cookie2 }), body: JSON.stringify({ intentId: id2, code: code2 }),
    });
    assert.equal(expRes.status, 400);
    await assertZeroIdentitiesAndSessions("after inline expired OTP");
  });

  it("resend invalidates previous code and proof without resetting aggregate budgets; successful verify creates zero accounts/sessions", async () => {
    process.env.IDENTITY_MAIL_RESEND_SECONDS = "1";
    const email = "verify-ok@example.com";
    const ipHdr = { "x-forwarded-for": "198.51.102.222, 10.0.0.1" };
    const s1 = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs(ipHdr), body: JSON.stringify({ email, acceptedTermsVersion: "v1" }),
    });
    assert.equal(s1.status, 202);
    const cookie = extractCookie(s1, "swyra_reg_browser");
    const { intentId } = await s1.json();
    await runMailOutboxPass();
    const codeGen1 = extractCodeFromSink(email);

    // Concurrent verification produces at most 1 proof and zero accounts/sessions
    const [vA, vB] = await Promise.all([
      app.request("/api/identity/registration/verify", { method: "POST", headers: hdrs({ ...ipHdr, Cookie: cookie }), body: JSON.stringify({ intentId, code: codeGen1 }) }),
      app.request("/api/identity/registration/verify", { method: "POST", headers: hdrs({ ...ipHdr, Cookie: cookie }), body: JSON.stringify({ intentId, code: codeGen1 }) }),
    ]);
    const okCount = [vA, vB].filter((r) => r.status === 200).length;
    assert.equal(okCount, 1, "Concurrent verification must mint at most one proof");
    const winner = vA.status === 200 ? vA : vB;
    const proofCookie = extractCookie(winner, "swyra_reg_proof");
    assert.ok(proofCookie, "Winning verification must deliver proof in HttpOnly cookie");
    assert.ok((winner.headers.get("set-cookie") || "").includes("HttpOnly"));
    const winBody = await winner.json();
    assert.equal(winBody.verified, true);
    assert.equal(winBody.proof, undefined, "Raw verification proof must never be returned to JS");
    await assertZeroIdentitiesAndSessions("after successful OTP verification");

    // Cooldown enforced immediately on resend
    const cool = await app.request("/api/identity/registration/resend", {
      method: "POST", headers: hdrs({ ...ipHdr, Cookie: cookie }), body: JSON.stringify({ intentId }),
    });
    assert.equal(cool.status, 429);

    // After cooldown, resend invalidates previous proof and gen-1 code without extending intent expiresAt
    const beforeDoc = await db.collection("registration_intents").findOne({ intentId });
    await new Promise((r) => setTimeout(r, 1100));
    const r2 = await app.request("/api/identity/registration/resend", {
      method: "POST", headers: hdrs({ ...ipHdr, Cookie: cookie }), body: JSON.stringify({ intentId }),
    });
    assert.equal(r2.status, 202);
    await runMailOutboxPass();
    const codeGen2 = extractCodeFromSink(email);
    assert.notEqual(codeGen2, codeGen1);
    const afterResendDoc = await db.collection("registration_intents").findOne({ intentId });
    assert.equal(afterResendDoc?.generation, 2);
    assert.equal(afterResendDoc?.proofDigest, undefined, "Resend must clear prior verification proof");
    assert.equal(afterResendDoc?.expiresAt.getTime(), beforeDoc?.expiresAt.getTime(), "Resend must not extend intent lifetime");

    const oldFail = await app.request("/api/identity/registration/verify", {
      method: "POST", headers: hdrs({ ...ipHdr, Cookie: cookie }), body: JSON.stringify({ intentId, code: codeGen1 }),
    });
    assert.equal(oldFail.status, 400, "Old generation code must fail after resend");

    const newWin = await app.request("/api/identity/registration/verify", {
      method: "POST", headers: hdrs({ ...ipHdr, Cookie: cookie }), body: JSON.stringify({ intentId, code: codeGen2 }),
    });
    assert.equal(newWin.status, 200);
    await assertZeroIdentitiesAndSessions("after resend + successful OTP verification");
  });
});
