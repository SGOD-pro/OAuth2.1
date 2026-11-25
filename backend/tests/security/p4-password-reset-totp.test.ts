import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { describe, it, before, after } from "node:test";
import { createOTP } from "@better-auth/utils/otp";
import { base32 } from "@better-auth/utils/base32";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P4 Password Reset with TOTP Enabled (AC-11)", { timeout: 60_000 }, () => {
  let app: any;
  let db: any;
  let getTestMailSinkMessages: any;
  let clearTestMailSink: any;
  let origin: string;
  let gatewaySecret: string;
  let cleanupDb: (() => Promise<void>) | undefined;

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
    origin = process.env.FRONTEND_URL || "http://localhost:5174";

    cleanupDb = await setupSuiteDatabase("p4-password-reset-totp");
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
      "x-forwarded-for": "198.51.100.77, 10.0.0.1",
      ...extra,
    };
  }

  function extractCookie(res: Response, name: string): string {
    const raw = (res.headers as any).getSetCookie ? (res.headers as any).getSetCookie() : [res.headers.get("set-cookie") || ""];
    for (const item of raw) {
      for (const part of String(item).split(/,(?=\s*[^;]+=[^;]+)/)) {
        const kv = part.trim().split(";")[0].trim();
        if (kv.startsWith(`${name}=`)) return kv;
      }
    }
    return "";
  }

  it("preserves TOTP, revokes affected account sessions/contexts/refresh families, keeps second browser account active, and requires TOTP on next sign-in", async () => {
    const emailA = `reset_a_${Date.now()}@example.com`;
    const passA1 = "ResetPassA1!2345";
    const passA2 = "ResetPassA2!6789";
    const emailB = `reset_b_${Date.now()}@example.com`;
    const passB = "ResetPassB1!2345";

    // 1. Sign up User A and User B
    const upA = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: passA1, name: "User A" }),
    });
    assert.equal(upA.status, 200);
    const cookieA = extractCookie(upA, "better-auth.session_token");
    const proofA = extractCookie(upA, "swyra_browser_session");
    const userA = await db.collection("user").findOne({ email: emailA });
    assert.ok(userA?._id);
    const userAId = String(userA._id);

    const upB = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers({ Cookie: proofA }),
      body: JSON.stringify({ email: emailB, password: passB, name: "User B" }),
    });
    assert.equal(upB.status, 200);
    const cookieB = extractCookie(upB, "better-auth.session_token");
    const proofAB = extractCookie(upB, "swyra_browser_session") || proofA;
    const userB = await db.collection("user").findOne({ email: emailB });
    const userBId = String(userB._id);

    // 2. Enroll TOTP for User A
    const enRes = await app.request("/api/auth/two-factor/enable", {
      method: "POST",
      headers: headers({ Cookie: cookieA }),
      body: JSON.stringify({ password: passA1 }),
    });
    assert.equal(enRes.status, 200);
    const { totpURI } = await enRes.json();
    const b32Secret = new URL(totpURI).searchParams.get("secret")!;
    const rawSecret = Buffer.from(base32.decode(b32Secret)).toString();
    const enrollCode = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
    const verEnRes = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: headers({ Cookie: cookieA }),
      body: JSON.stringify({ code: enrollCode }),
    });
    assert.equal(verEnRes.status, 200);
    const rotatedCookieA = extractCookie(verEnRes, "better-auth.session_token") || cookieA;

    // 3. Seed an owner identity_context and an OAuth refresh token family for User A
    const ctxId = `ctx_reset_${Date.now()}`;
    await db.collection("identity_contexts").insertOne({
      contextId: ctxId,
      userId: userAId,
      revokedAt: null,
      expiresAt: new Date(Date.now() + 600_000),
    });
    await db.collection("oauth_token_families").insertOne({
      familyId: `fam_reset_${Date.now()}`,
      userId: userAId,
      clientId: "client-reset-test",
      status: "active",
    });

    // 4. Request password reset via local mail sink
    clearTestMailSink();
    const reqReset = await app.request("/api/auth/request-password-reset", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, redirectTo: `${origin}/reset-password` }),
    });
    assert.equal(reqReset.status, 200);

    const msgs = getTestMailSinkMessages().filter((m: any) => m.to === emailA && m.purpose === "password_reset");
    assert.equal(msgs.length, 1, "Local mail sink must receive password reset email");
    const tokenMatch = msgs[0].text.match(/token:\s*([^\s)]+)/);
    assert.ok(tokenMatch?.[1], "Reset email must contain token");
    const resetToken = tokenMatch[1];

    // 5. Complete password reset
    const doReset = await app.request("/api/auth/reset-password", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ newPassword: passA2, token: resetToken }),
    });
    assert.equal(doReset.status, 200);

    // 6. Verify TOTP is preserved, User A's prior session/context/family/browser-entry are revoked, and User B stays active
    const userAAfter = await db.collection("user").findOne({ _id: userA._id });
    assert.equal(userAAfter.twoFactorEnabled, true, "TOTP must remain enabled after password reset");

    const oldSessRes = await app.request("/api/auth/get-session", {
      method: "GET",
      headers: headers({ Cookie: rotatedCookieA }),
    });
    const oldSessData = await oldSessRes.json().catch(() => null);
    assert.equal(oldSessData?.user ?? null, null, "Prior Better Auth session must be revoked");

    const ctxAfter = await db.collection("identity_contexts").findOne({ contextId: ctxId });
    assert.ok(ctxAfter.revokedAt instanceof Date, "Owner identity_context must be revoked");

    const famAfter = await db.collection("oauth_token_families").findOne({ userId: userAId });
    assert.equal(famAfter.status, "revoked", "OAuth token family must be revoked");

    const browserSet = await db.collection("browser_session_sets").findOne({ "entries.userId": userBId });
    if (browserSet) {
      const entryA = browserSet.entries.find((e: any) => e.userId === userAId);
      const entryB = browserSet.entries.find((e: any) => e.userId === userBId);
      if (entryA) assert.equal(entryA.status, "signed_out", "User A browser entry must be signed out");
      if (entryB) assert.equal(entryB.status, "active", "User B browser entry must stay active");
    }

    const sessBRes = await app.request("/api/auth/get-session", {
      method: "GET",
      headers: headers({ Cookie: [cookieB, proofAB].filter(Boolean).join("; ") }),
    });
    const sessBData = await sessBRes.json().catch(() => null);
    assert.equal(sessBData?.user?.id, userBId, "User B must stay signed in");

    // 7. Next sign-in for User A with new password must still require TOTP
    const signInA = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: passA2 }),
    });
    assert.equal(signInA.status, 200);
    const signInBody = await signInA.json();
    assert.equal(signInBody.twoFactorRedirect, true, "Next sign-in must still require TOTP");

    const twoFactorCookie = extractCookie(signInA, "better-auth.two_factor");
    assert.ok(twoFactorCookie, "Sign-in must issue two_factor challenge cookie");
    const nextCode = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
    const verifyNext = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: headers({ Cookie: twoFactorCookie }),
      body: JSON.stringify({ code: nextCode }),
    });
    assert.equal(verifyNext.status, 200, "Valid TOTP must complete sign-in after password reset");
  });
});
