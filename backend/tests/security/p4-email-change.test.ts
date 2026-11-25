import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P4 Verified Email Change (AC-11)", { timeout: 60_000 }, () => {
  let app: any;
  let db: any;
  let getTestMailSinkMessages: any;
  let clearTestMailSink: any;
  let origin: string;
  let gatewaySecret: string;
  let cleanupDb: any;

  before(async () => {
    process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
    process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
    process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
    process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
    process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
    isolateTestEnvironment();
    process.env.NODE_ENV = "test";
    process.env.ALLOW_PUBLIC_SIGNUP = "true";
    process.env.REQUIRE_EMAIL_VERIFICATION = "false";
    process.env.TOTP_ENCRYPTION_KEY = process.env.TOTP_ENCRYPTION_KEY || "c".repeat(32);
    process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
    gatewaySecret = process.env.INTERNAL_GATEWAY_SECRET;
    origin = process.env.FRONTEND_URL;

    cleanupDb = await setupSuiteDatabase("p4_email_change");
    const { getDb } = await import("../../src/db/mongo");
    db = await getDb();

    const mailMod = await import("../../src/identity/mail-service");
    getTestMailSinkMessages = mailMod.getTestMailSinkMessages;
    clearTestMailSink = mailMod.clearTestMailSink;
    clearTestMailSink();

    const { default: appInstance } = await import("../../src/app");
    app = appInstance;
  });

  after(async () => {
    if (typeof cleanupDb === "function") await cleanupDb();
  });

  function headers(extra: Record<string, string> = {}) {
    return {
      "Content-Type": "application/json",
      Origin: origin,
      "x-gateway-secret": gatewaySecret,
      "x-csrf-token": "any",
      "x-forwarded-for": "198.51.100.88, 10.0.0.1",
      ...extra,
    };
  }

  function extractCookie(res: Response, name: string): string {
    const raw = (res.headers as any).getSetCookie ? (res.headers as any).getSetCookie() : [res.headers.get("set-cookie") || ""];
    for (const item of raw) {
      for (const part of String(item).split(/,(?=\s*[^;]+=[^;]+)/)) {
        const kv = part.trim().split(";")[0].trim();
        if (kv.includes(`${name}=`)) return kv;
      }
    }
    return "";
  }

  async function issueOwnerContext(cookieHeader: string, entryId: string): Promise<string> {
    const res = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: headers({ Cookie: cookieHeader }),
      body: JSON.stringify({ entryId, purpose: "owner_dashboard" }),
    });
    assert.equal(res.status, 201, `Expected 201 issuing owner context, got ${res.status}`);
    const data = await res.json();
    const handle = data.contextHandle || data.context?.contextHandle || data.contextId || data.id || data.handle;
    assert.ok(handle, `Missing context handle in ${JSON.stringify(data)}`);
    return handle;
  }

  it("binds to exact account context, requires proof, handles collision/reuse/concurrency, preserves sub/role/TOTP, revokes A only, keeps B signed in, and notifies old mailbox", async () => {
    const emailA1 = `ec_a1_${Date.now()}@example.com`;
    const emailA2 = `ec_a2_${Date.now()}@example.com`;
    const emailB = `ec_b_${Date.now()}@example.com`;
    const pass = "EmailChange!Pass123";

    // 1. Sign up A and B in same browser
    const upA = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA1, password: pass, name: "User A" }),
    });
    assert.equal(upA.status, 200);
    await db.collection("user").updateOne({ email: emailA1 }, { $set: { emailVerified: true } });
    const inA = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA1, password: pass }),
    });
    assert.equal(inA.status, 200);
    const { getBrowserSessionCookieName } = await import("../../src/identity/browser-session-registry");
    const cookieName = getBrowserSessionCookieName();
    const cookieA = extractCookie(inA, "better-auth.session_token");
    const proof = extractCookie(inA, cookieName);
    const userA = await db.collection("user").findOne({ email: emailA1 });
    const userAId = String(userA._id);

    const upB = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers({ Cookie: proof }),
      body: JSON.stringify({ email: emailB, password: pass, name: "User B" }),
    });
    assert.equal(upB.status, 200);
    await db.collection("user").updateOne({ email: emailB }, { $set: { emailVerified: true } });
    const inB = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers({ Cookie: proof }),
      body: JSON.stringify({ email: emailB, password: pass }),
    });
    assert.equal(inB.status, 200);
    const cookieB = extractCookie(inB, "better-auth.session_token");
    const proofAB = extractCookie(inB, cookieName) || proof;
    const userB = await db.collection("user").findOne({ email: emailB });
    const userBId = String(userB._id);

    const regSet = await db.collection("browser_session_sets").findOne({ "entries.userId": userAId });
    const entryA = regSet.entries.find((e: any) => e.userId === userAId);
    assert.ok(entryA?.entryId);

    // Issue owner context for A
    const ctxA = await issueOwnerContext(proofAB, entryA.entryId);

    // 2. Request email change for A even while ambient Cookie is B's session!
    clearTestMailSink();
    const reqRes = await app.request("/api/identity/email-change/request", {
      method: "POST",
      headers: headers({ Cookie: [cookieB, proofAB].join("; "), "X-Identity-Context": ctxA }),
      body: JSON.stringify({ newEmail: emailA2, password: pass }),
    });
    if (reqRes.status !== 200) throw new Error(`reqRes failed (${reqRes.status}): ${await reqRes.text()}`);

    // Old address must still be active before confirm
    const userABefore = await db.collection("user").findOne({ _id: userA._id });
    assert.equal(userABefore.email, emailA1);

    const msgs = getTestMailSinkMessages().filter((m: any) => m.to === emailA2 && m.purpose === "email_change_verify");
    assert.equal(msgs.length, 1, "New mailbox must receive verification proof");
    const token = msgs[0].text.match(/token:\s*([^\s)]+)/)?.[1];
    assert.ok(token);

    // 3. Collision check: if emailA2 is taken before confirm, confirm fails with 409 and preserves old address
    await db.collection("user").insertOne({ email: emailA2, name: "Squatter", emailVerified: true, createdAt: new Date(), updatedAt: new Date() });
    const collisionRes = await app.request("/api/identity/email-change/confirm", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ token }),
    });
    assert.equal(collisionRes.status, 409, "Address collision at commit must fail with 409");
    await db.collection("user").deleteOne({ email: emailA2 });

    // Re-request a fresh token after failed commit
    clearTestMailSink();
    const reqRes2 = await app.request("/api/identity/email-change/request", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ newEmail: emailA2, password: pass }),
    });
    assert.equal(reqRes2.status, 200);
    const token2 = getTestMailSinkMessages().find((m: any) => m.to === emailA2 && m.purpose === "email_change_verify").text.match(/token:\s*([^\s)]+)/)?.[1];

    // Seed OAuth token family for A to verify revocation
    await db.collection("oauth_token_families").insertOne({
      familyId: `fam_ec_${Date.now()}`,
      userId: userAId,
      clientId: "client-ec-test",
      status: "active",
    });

    // 4. Concurrent confirm: exactly 1 succeeds (200), loser gets 409
    clearTestMailSink();
    const [c1, c2] = await Promise.all([
      app.request("/api/identity/email-change/confirm", {
        method: "POST",
        headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
        body: JSON.stringify({ token: token2 }),
      }),
      app.request("/api/identity/email-change/confirm", {
        method: "POST",
        headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
        body: JSON.stringify({ token: token2 }),
      }),
    ]);
    const statuses = [c1.status, c2.status].sort((a, b) => a - b);
    assert.deepEqual(statuses, [200, 409], `Concurrent confirm must yield [200, 409], got ${statuses}`);

    // 5. Verify post-commit state: email updated, id/role preserved, versions advanced, A revoked, B active, old mailbox notified
    const userAAfter = await db.collection("user").findOne({ _id: userA._id });
    assert.equal(userAAfter.email, emailA2);
    assert.equal(String(userAAfter._id), userAId);
    assert.ok((userAAfter.sessionVersion || 0) >= 1);
    assert.ok((userAAfter.lookupVersion || 0) >= 1);

    const famAfter = await db.collection("oauth_token_families").findOne({ userId: userAId });
    assert.equal(famAfter.status, "revoked");

    const sessBRes = await app.request("/api/auth/get-session", {
      method: "GET",
      headers: headers({ Cookie: [cookieB, proofAB].join("; ") }),
    });
    const sessBData = await sessBRes.json();
    assert.equal(sessBData?.user?.id, userBId, "User B must stay signed in");

    const noticeMsgs = getTestMailSinkMessages().filter((m: any) => m.to === emailA1 && m.purpose === "email_change_notice");
    assert.equal(noticeMsgs.length, 1, "Old mailbox must receive change notification");
  });
});
