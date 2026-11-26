import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import { describe, it, before, after } from "node:test";
import { createOTP } from "@better-auth/utils/otp";
import { base32 } from "@better-auth/utils/base32";
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
    process.exit(0);
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

    // Enroll A in real TOTP before changing email
    const enRes = await app.request("/api/auth/two-factor/enable", {
      method: "POST",
      headers: headers({ Cookie: cookieA }),
      body: JSON.stringify({ password: pass }),
    });
    assert.equal(enRes.status, 200);
    const { totpURI } = await enRes.json();
    const b32Secret = new URL(totpURI).searchParams.get("secret")!;
    const rawSecret = Buffer.from(base32.decode(b32Secret)).toString();
    const enrollCode = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
    const verEnRes = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: headers({ Cookie: [cookieA, proof].filter(Boolean).join("; ") }),
      body: JSON.stringify({ code: enrollCode }),
    });
    assert.equal(verEnRes.status, 200);
    const rotatedCookieA = extractCookie(verEnRes, "better-auth.session_token") || cookieA;
    const proofAfterTotp = extractCookie(verEnRes, cookieName) || proof;

    const upB = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers({ Cookie: proofAfterTotp }),
      body: JSON.stringify({ email: emailB, password: pass, name: "User B" }),
    });
    assert.equal(upB.status, 200);
    await db.collection("user").updateOne({ email: emailB }, { $set: { emailVerified: true } });
    const inB = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers({ Cookie: proofAfterTotp }),
      body: JSON.stringify({ email: emailB, password: pass }),
    });
    assert.equal(inB.status, 200);
    const cookieB = extractCookie(inB, "better-auth.session_token");
    const proofAB = extractCookie(inB, cookieName) || proofAfterTotp;
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

    // Register a real public PKCE client and issue real pre-change OAuth credentials for A and B (success control)
    const realClientId = `ec_real_client_${Date.now()}`;
    const realRedirectUri = `${origin}/cb`;
    await db.collection("oauthClient").insertOne({
      clientId: realClientId,
      name: "P4 Email Change Real Client",
      redirectUris: [realRedirectUri],
      type: "public",
      tokenEndpointAuthMethod: "none",
      grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"],
      isPublic: true,
      isDev: true,
      clientType: "public",
      accessPolicy: "open",
      disabled: false,
      skipConsent: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    async function issueRealOAuthTokens(cookieHeader: string) {
      const verifier = crypto.randomBytes(32).toString("base64url");
      const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
      const state = crypto.randomBytes(12).toString("hex");
      const authzRes = await app.request(
        `/api/auth/oauth2/authorize?client_id=${encodeURIComponent(realClientId)}&redirect_uri=${encodeURIComponent(realRedirectUri)}&response_type=code&scope=openid%20offline_access&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`,
        { method: "GET", headers: headers({ Cookie: cookieHeader }) }
      );
      assert.equal(authzRes.status, 302, "Pre-change authorize control must redirect");
      const loc = authzRes.headers.get("location") || "";
      const code = new URL(loc).searchParams.get("code");
      assert.ok(code, `Pre-change authorize control must issue code, got ${loc}`);
      const tokRes = await app.request("/api/auth/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: realRedirectUri,
          client_id: realClientId,
          code_verifier: verifier,
        }).toString(),
      });
      assert.equal(tokRes.status, 200, "Pre-change token exchange control must succeed");
      return tokRes.json();
    }

    const preTokensA = await issueRealOAuthTokens(rotatedCookieA);
    assert.ok(preTokensA.refresh_token, "A must receive pre-change refresh_token");
    const preTokensB = await issueRealOAuthTokens(cookieB);
    assert.ok(preTokensB.refresh_token, "B must receive pre-change refresh_token");

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
    assert.equal(userAAfter.tokenVersion, 2, "Missing legacy tokenVersion (effective 1) must advance to 2");
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

    // Prior session for A must be revoked and cannot authorize a new OAuth code
    const oldSessARes = await app.request("/api/auth/get-session", {
      method: "GET",
      headers: headers({ Cookie: rotatedCookieA }),
    });
    const oldSessAData = await oldSessARes.json().catch(() => null);
    assert.equal(oldSessAData?.user ?? null, null, "Prior session for A must be revoked");

    const staleVerifier = crypto.randomBytes(32).toString("base64url");
    const staleChallenge = crypto.createHash("sha256").update(staleVerifier).digest("base64url");
    const staleAuthzRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${encodeURIComponent(realClientId)}&redirect_uri=${encodeURIComponent(realRedirectUri)}&response_type=code&scope=openid%20offline_access&state=s_after&code_challenge=${staleChallenge}&code_challenge_method=S256`,
      { method: "GET", headers: headers({ Cookie: rotatedCookieA }) }
    );
    assert.ok(staleAuthzRes.status === 302 || staleAuthzRes.status === 400 || staleAuthzRes.status === 401, "Prior session must not issue OAuth code");
    const staleLoc = staleAuthzRes.headers.get("location") || "";
    assert.ok(!staleLoc.includes("code="), "Prior session must never yield an authorization code");

    // Pre-change real refresh_token for A must fail closed
    const staleRefreshRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: preTokensA.refresh_token,
        client_id: realClientId,
      }).toString(),
    });
    assert.ok(staleRefreshRes.status === 400 || staleRefreshRes.status === 401, "Pre-change refresh token for A must be rejected");

    // B's pre-change real refresh_token must still succeed
    const bRefreshRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: preTokensB.refresh_token,
        client_id: realClientId,
      }).toString(),
    });
    assert.equal(bRefreshRes.status, 200, "B's pre-change refresh token must remain usable");

    // Stale token from first request must not overwrite newer contact
    const staleConfirm = await app.request("/api/identity/email-change/confirm", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ token }),
    });
    assert.ok(staleConfirm.status === 401 || staleConfirm.status === 409, "Stale token/context must be rejected");

    // Signing in with new email must still require TOTP and preserve role/sub
    const signInNew = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA2, password: pass }),
    });
    assert.equal(signInNew.status, 200);
    const signInNewBody = await signInNew.json();
    assert.equal(signInNewBody.twoFactorRedirect, true, "New email sign-in must still require TOTP");
    const twoFactorCookie = extractCookie(signInNew, "better-auth.two_factor");
    const nextCode = await createOTP(rawSecret, { digits: 6, period: 30 }).hotp(Math.floor(Date.now() / 30000) + 1);
    const verNext = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: headers({ Cookie: twoFactorCookie }),
      body: JSON.stringify({ code: nextCode }),
    });
    assert.equal(verNext.status, 200, "TOTP verification must succeed for new email");
    assert.equal(userAAfter.role, userA.role, "User role must be preserved");
  });

  it("rejects admin email-change via ordinary-user owner context (unsupported admin path)", async () => {
    const adminEmail = `ec_admin_${Date.now()}@example.com`;
    const pass = "AdminEmail!Pass123";
    const up = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: adminEmail, password: pass, name: "Admin EC" }),
    });
    assert.equal(up.status, 200);
    await db.collection("user").updateOne({ email: adminEmail }, { $set: { emailVerified: true, role: "admin" } });

    const inRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: adminEmail, password: pass }),
    });
    assert.equal(inRes.status, 200);
    const adminDoc = await db.collection("user").findOne({ email: adminEmail });
    const regSet = await db.collection("browser_session_sets").findOne({ "entries.userId": String(adminDoc._id) });
    assert.equal(regSet, null, "Admin accounts must not be enrolled in ordinary-user browser_session_sets");

    const reqRes = await app.request("/api/identity/email-change/request", {
      method: "POST",
      headers: headers({ Cookie: extractCookie(inRes, "better-auth.session_token") }),
      body: JSON.stringify({ newEmail: `ec_admin_new_${Date.now()}@example.com`, password: pass }),
    });
    assert.equal(reqRes.status, 401, "Admin email-change via ordinary-user owner-context route must fail closed");
  });
});
