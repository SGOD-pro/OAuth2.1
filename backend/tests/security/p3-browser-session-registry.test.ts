import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { ObjectId, MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P3a: Browser Session Registry Coexistence, Capacity & Isolation", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let authProvider: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let getTestMailSinkMessages: any;
  let clearTestMailSink: any;
  let ipCounter = 10;
  const gatewaySecret = "g".repeat(32);
  const strongPassword = "P3a!Registry#Password99";

  const hdrs = (extra: Record<string, string> = {}) => ({
    "Content-Type": "application/json",
    "x-gateway-secret": gatewaySecret,
    "x-forwarded-for": `198.51.120.${(++ipCounter % 240) + 1}, 10.0.0.1`,
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

  function extractAllSetCookies(res: Response): string[] {
    return typeof (res.headers as any).getSetCookie === "function"
      ? (res.headers as any).getSetCookie()
      : (res.headers.get("set-cookie") ? [res.headers.get("set-cookie")!] : []);
  }

  async function seedVerifiedUser(email: string, username: string) {
    await authProvider.api.signUpEmail({ body: { email, password: strongPassword, name: username } });
    const u = await db.collection("user").findOne({ email });
    await db.collection("user").updateOne(
      { email },
      { $set: { role: "user", emailVerified: true, username, scopedClientId: null } }
    );
    if (u) await db.collection("session").deleteMany({ userId: u._id });
    return db.collection("user").findOne({ email });
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p3_browser_registry");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName,
      BETTER_AUTH_SECRET: "a".repeat(32), BETTER_AUTH_URL: "http://localhost:3000",
      FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret,
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      IDENTITY_REGISTRATION_MODE: "disabled",
      IDENTITY_OTP_VERIFIER_KEY_REF: "p3a-otp-key-ref-0000000000000001",
      IDENTITY_LOOKUP_KEY_REF: "p3a-lookup-key-ref-0000000000002",
      IDENTITY_MAIL_PAYLOAD_KEY_REF: "p3a-aead-key-ref-000000000000003",
      IDENTITY_MAIL_WEBHOOK_KEY_REF: "p3a-hook-key-ref-000000000000004",
      IDENTITY_MAIL_TRANSPORT: "test_sink",
      IDENTITY_GLOBAL_MAIL_DAILY_BUDGET: "500",
    });
    ({ closeDb, setTestDbOverride } = await import("../../src/db/mongo"));
    ({ getTestMailSinkMessages, clearTestMailSink } = await import("../../src/identity/mail-service"));
    authProvider = (await import("../../src/utils/auth")).authProvider;
    app = (await import("../../src/app")).default;
    client = suite.client; db = client.db(suite.dbName); setTestDbOverride(db);
  });

  after(async () => { await closeDb(); await suite.cleanup(); });

  beforeEach(async () => {
    process.env.IDENTITY_REGISTRATION_MODE = "disabled";
    clearTestMailSink();
    for (const col of await db.listCollections().toArray()) await db.collection(col.name).deleteMany({});
  });

  it("coexists ordinary verified-registered account A and signed-in account B, rotating proof without leaking tokens", async () => {
    // 1. Register Account A via verified registration flow
    process.env.IDENTITY_REGISTRATION_MODE = "verified";
    const startA = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs({ "Idempotency-Key": `s-${crypto.randomUUID()}` }),
      body: JSON.stringify({ email: "alice-p3@example.com", acceptedTermsVersion: "v1" }),
    });
    assert.equal(startA.status, 202);
    const { intentId } = (await startA.json()) as any;
    const regBrowser = extractCookie(startA, "swyra_reg_browser");
    let otp = "";
    for (let i = 0; i < 30 && !otp; i++) {
      const m = getTestMailSinkMessages().find((x: any) => x.to === "alice-p3@example.com");
      if (m) otp = m.text.match(/\b(\d{6})\b/)?.[1] || "";
      else await new Promise((r) => setTimeout(r, 30));
    }
    const verA = await app.request("/api/identity/registration/verify", {
      method: "POST", headers: hdrs({ Cookie: regBrowser }), body: JSON.stringify({ intentId, code: otp }),
    });
    const regProof = extractCookie(verA, "swyra_reg_proof");
    const compA = await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: `${regBrowser}; ${regProof}` }),
      body: JSON.stringify({ username: "alice_p3", password: strongPassword, acceptedTermsVersion: "v1" }),
    });
    assert.equal(compA.status, 201);
    const browserCookie1 = extractCookie(compA, "swyra-browser");
    assert.ok(browserCookie1, "Verified registration must set swyra-browser cookie");
    const setCookies1 = extractAllSetCookies(compA).find((c) => c.startsWith("swyra-browser=")) || "";
    assert.match(setCookies1, /HttpOnly/i);
    assert.match(setCookies1, /SameSite=Lax/i);

    // 2. Seed B & sign in via ordinary password login carrying browserCookie1
    process.env.IDENTITY_REGISTRATION_MODE = "disabled";
    await seedVerifiedUser("bob-p3@example.com", "bob_p3");
    const loginB = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs({ Cookie: browserCookie1 }),
      body: JSON.stringify({ email: "bob-p3@example.com", password: strongPassword }),
    });
    assert.equal(loginB.status, 200);
    const browserCookie2 = extractCookie(loginB, "swyra-browser");
    assert.ok(browserCookie2, "Ordinary sign-in must rotate swyra-browser cookie");
    assert.notEqual(browserCookie2, browserCookie1, "Proof handle must rotate when adding B");

    // Raw proof must NEVER be persisted in DB; only digest stored
    const rawProofVal2 = browserCookie2.split("=")[1];
    const sets = await db.collection("browser_session_sets").find({}).toArray();
    assert.equal(sets.length, 1);
    assert.ok(!JSON.stringify(sets[0]).includes(rawProofVal2));
    assert.equal(sets[0].entries.length, 2);

    // 3. List accounts: only opaque entry handles/labels/status, zero raw tokens or emails
    const listRes = await app.request("/api/identity/accounts", { headers: hdrs({ Cookie: browserCookie2 }) });
    assert.equal(listRes.status, 200);
    const listText = await listRes.clone().text();
    const sessions = await db.collection("session").find({}).toArray();
    assert.equal(sessions.length, 2);
    for (const s of sessions) assert.ok(!listText.includes(s.token), "Response must never leak session tokens");
    assert.ok(!listText.includes("alice-p3@example.com") && !listText.includes("bob-p3@example.com"), "Omit plaintext emails");
    const listJson = JSON.parse(listText);
    assert.equal(listJson.accounts.length, 2);
    assert.ok(listJson.accounts.every((a: any) => a.entryId.startsWith("ent_") && a.status === "active"));
  });

  it("signing out or expiring A keeps B active and usable, without cross-account loss", async () => {
    const uA = await seedVerifiedUser("a-exp@example.com", "user_a_exp");
    const uB = await seedVerifiedUser("b-exp@example.com", "user_b_exp");

    const lA = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: "a-exp@example.com", password: strongPassword }),
    });
    const bc1 = extractCookie(lA, "swyra-browser");
    const lB = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs({ Cookie: bc1 }), body: JSON.stringify({ email: "b-exp@example.com", password: strongPassword }),
    });
    const bc2 = extractCookie(lB, "swyra-browser");

    const list1 = await (await app.request("/api/identity/accounts", { headers: hdrs({ Cookie: bc2 }) })).json() as any;
    const entryA = list1.accounts.find((x: any) => x.label.includes("user_a_exp"));
    const entryB = list1.accounts.find((x: any) => x.label.includes("user_b_exp"));
    assert.ok(entryA && entryB);

    // Expire A's session in DB -> A shows signed_out, B stays active & usable
    await db.collection("session").updateMany({ userId: uA!._id }, { $set: { expiresAt: new Date(Date.now() - 5000) } });
    const listAfterExp = await (await app.request("/api/identity/accounts", { headers: hdrs({ Cookie: bc2 }) })).json() as any;
    assert.equal(listAfterExp.accounts.find((x: any) => x.entryId === entryA.entryId)?.status, "signed_out");
    assert.equal(listAfterExp.accounts.find((x: any) => x.entryId === entryB.entryId)?.status, "active");

    // Sign out A explicitly -> deletes A's session, removes/retires A cleanly, leaves B's session alive
    const { resolveVerifiedBrowserEntry } = await import("../../src/identity/session-adapter");
    const signOutA = await app.request("/api/identity/accounts/sign-out", {
      method: "POST", headers: hdrs({ Cookie: bc2 }), body: JSON.stringify({ entryId: entryA.entryId }),
    });
    assert.equal(signOutA.status, 200);
    const bc3 = extractCookie(signOutA, "swyra-browser") || bc2;
    assert.equal(await db.collection("session").countDocuments({ userId: uB!._id }), 1, "B session must survive A sign-out");
    const resolvedB = await resolveVerifiedBrowserEntry(authProvider, db, bc3.split("=")[1], entryB.entryId);
    assert.equal(resolvedB.userId, String(uB!._id));
    await assert.rejects(resolveVerifiedBrowserEntry(authProvider, db, bc3.split("=")[1], entryA.entryId));
  });

  it("denies forged/invalid browser proofs and never silently evicts at 10-account capacity", async () => {
    const seeded: string[] = [];
    for (let i = 1; i <= 11; i++) {
      const email = `cap-${i}@example.com`;
      await seedVerifiedUser(email, `cap_user_${i}`);
      seeded.push(email);
    }

    // Invalid proof cannot list
    assert.equal((await app.request("/api/identity/accounts", { headers: hdrs({ Cookie: "swyra-browser=forged-proof-123" }) })).status, 401);

    // Add 10 accounts sequentially
    let browserCookie = "";
    for (let i = 0; i < 10; i++) {
      const r = await app.request("/api/auth/sign-in/email", {
        method: "POST",
        headers: hdrs(browserCookie ? { Cookie: browserCookie } : {}),
        body: JSON.stringify({ email: seeded[i], password: strongPassword }),
      });
      assert.equal(r.status, 200);
      browserCookie = extractCookie(r, "swyra-browser");
      assert.ok(browserCookie);
    }

    // Forged proof on sign-in for existing user NEVER attaches to the 10-account set
    const forgedLogin = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs({ Cookie: "swyra-browser=attacker-guessed-proof" }),
      body: JSON.stringify({ email: seeded[10], password: strongPassword }),
    });
    assert.equal(forgedLogin.status, 200);
    const isolatedSetCookie = extractCookie(forgedLogin, "swyra-browser");
    assert.notEqual(isolatedSetCookie, browserCookie);
    const isolatedList = await (await app.request("/api/identity/accounts", { headers: hdrs({ Cookie: isolatedSetCookie }) })).json() as any;
    assert.equal(isolatedList.accounts.length, 1);

    // Attempting to sign in 11th account using genuine 10-account browserCookie returns 409 without evicting 1..10
    const overflow = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs({ Cookie: browserCookie }),
      body: JSON.stringify({ email: seeded[10], password: strongPassword }),
    });
    assert.equal(overflow.status, 409);
    const overflowJson = (await overflow.json()) as any;
    assert.equal(overflowJson.code, "ERR_SESSION_SET_FULL");

    const fullList = await (await app.request("/api/identity/accounts", { headers: hdrs({ Cookie: browserCookie }) })).json() as any;
    assert.equal(fullList.accounts.length, 10);
    assert.ok(fullList.accounts.every((a: any) => a.status === "active"), "All 10 original accounts must remain active");

    // Explicit sign-out + remove frees one slot so 11th can enroll cleanly
    const targetId = fullList.accounts[0].entryId;
    const soRes = await app.request("/api/identity/accounts/sign-out", {
      method: "POST", headers: hdrs({ Cookie: browserCookie }), body: JSON.stringify({ entryId: targetId }),
    });
    browserCookie = extractCookie(soRes, "swyra-browser") || browserCookie;
    const rmRes = await app.request("/api/identity/accounts/remove", {
      method: "POST", headers: hdrs({ Cookie: browserCookie }), body: JSON.stringify({ entryId: targetId }),
    });
    assert.equal(rmRes.status, 200);
    browserCookie = extractCookie(rmRes, "swyra-browser") || browserCookie;

    const addEleventh = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs({ Cookie: browserCookie }),
      body: JSON.stringify({ email: seeded[10], password: strongPassword }),
    });
    assert.equal(addEleventh.status, 200);
    const finalList = await (await app.request("/api/identity/accounts", { headers: hdrs({ Cookie: extractCookie(addEleventh, "swyra-browser") }) })).json() as any;
    assert.equal(finalList.accounts.length, 10);
  });
});
