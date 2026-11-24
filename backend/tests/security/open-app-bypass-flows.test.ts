import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import * as jose from "jose";
import { createOTP } from "@better-auth/utils/otp";
import { base32 } from "@better-auth/utils/base32";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("Open-App Membership Bypass Complex Flows Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let authProvider: any;

  const openConsentClient = "test-open-consent-app";
  const openConsentCb = "https://open-consent.example.com/cb";
  const openMfaClient = "test-open-mfa-app";
  const openMfaCb = "https://open-mfa.example.com/cb";
  const openSocialClient = "test-open-social-app";
  const openSocialCb = "https://open-social.example.com/cb";

  let testUserSession = "";
  let testUserId = "";
  let mfaUserEmail = "";
  let mfaUserPass = "MfaUserPass123!Secure";
  let mfaUserId = "";
  let mfaRawSecret = "";

  let mockGoogle = { sub: `g_sub_${crypto.randomBytes(4).toString("hex")}`, email: `g_${Date.now()}@example.com`, name: "Mock User" };
  let ipCounter = 900;
  const getHeaders = (extra: Record<string, string> = {}) => ({
    host: "localhost:3000", origin: "http://localhost:5174", "x-forwarded-for": `198.51.100.${(++ipCounter % 240) + 1}, 10.0.0.1`, "x-gateway-secret": "g".repeat(32), ...extra,
  });

  const makePkce = () => {
    const verifier = crypto.randomBytes(32).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    return { verifier, challenge };
  };

  const origFetch = globalThis.fetch;

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("open_bypass_flows");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName, BETTER_AUTH_SECRET: "a".repeat(32), BETTER_AUTH_URL: "http://localhost:3000",
      FRONTEND_URL: "http://localhost:5174", INTERNAL_GATEWAY_SECRET: "g".repeat(32), TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      GOOGLE_CLIENT_ID: "test-google-id", GOOGLE_CLIENT_SECRET: "test-google-secret", OPEN_APP_MEMBERSHIP_BYPASS_ENABLED: "true",
    });

    const googleKey = await jose.generateKeyPair("RS256");
    const pubJwk: any = await jose.exportJWK(googleKey.publicKey);
    pubJwk.kid = "test-google-kid"; pubJwk.alg = "RS256"; pubJwk.use = "sig";

    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as any)?.url || "";
      if (url.startsWith("https://oauth2.googleapis.com/token")) {
        const idToken = await new jose.SignJWT({ iss: "https://accounts.google.com", aud: "test-google-id", sub: mockGoogle.sub, email: mockGoogle.email, email_verified: true, name: mockGoogle.name })
          .setProtectedHeader({ alg: "RS256", kid: "test-google-kid" }).setIssuedAt().setExpirationTime("1h").sign(googleKey.privateKey);
        return new Response(JSON.stringify({ access_token: "mock_at", id_token: idToken, token_type: "Bearer", expires_in: 3600 }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      if (url.startsWith("https://www.googleapis.com/oauth2/v3/certs")) {
        return new Response(JSON.stringify({ keys: [pubJwk] }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return origFetch(input, init);
    };

    const mongoModule = await import("../../src/db/mongo");
    closeDb = mongoModule.closeDb; setTestDbOverride = mongoModule.setTestDbOverride;
    app = (await import("../../src/app")).default;
    authProvider = (await import("../../src/utils/auth")).authProvider;
    client = suite.client; db = client.db(suite.dbName); setTestDbOverride(db);

    await db.collection("oauthClient").insertMany([
      { clientId: openConsentClient, name: "Open Consent App", clientType: "public", accessPolicy: "open", isPublic: true, redirectUris: [openConsentCb], disabled: false, skipConsent: false, tokenEndpointAuthMethod: "none", createdAt: new Date() },
      { clientId: openMfaClient, name: "Open MFA App", clientType: "public", accessPolicy: "open", isPublic: true, redirectUris: [openMfaCb], disabled: false, skipConsent: true, tokenEndpointAuthMethod: "none", createdAt: new Date() },
      { clientId: openSocialClient, name: "Open Social App", clientType: "public", accessPolicy: "open", isPublic: true, redirectUris: [openSocialCb], disabled: false, skipConsent: true, tokenEndpointAuthMethod: "none", createdAt: new Date() },
    ]);

    const uEmail = `c-user-${Date.now()}@example.com`;
    const signupRes = await app.request("/api/auth/sign-up/email", { method: "POST", headers: { ...getHeaders(), "Content-Type": "application/json" }, body: JSON.stringify({ email: uEmail, password: "Password12345!Secure", name: "C User" }) });
    testUserSession = (signupRes.headers.get("set-cookie") || "").split(";")[0];
    const uDoc = await db.collection("user").findOne({ email: uEmail });
    testUserId = String(uDoc?._id || uDoc?.id);

    mfaUserEmail = `mfa-user-${Date.now()}@example.com`;
    const mfaSignUp = await authProvider.api.signUpEmail({ body: { email: mfaUserEmail, password: mfaUserPass, name: "MFA User" } });
    mfaUserId = String(mfaSignUp.user.id);
    const mfaPre = await authProvider.api.signInEmail({ body: { email: mfaUserEmail, password: mfaUserPass }, asResponse: true });
    const mfaPreCookie = (mfaPre.headers.get("set-cookie") || "").split(";")[0];
    const mfaSetup = await authProvider.api.enableTwoFactor({ body: { password: mfaUserPass, method: "totp" }, headers: new Headers({ cookie: mfaPreCookie }) });
    mfaRawSecret = new TextDecoder().decode(base32.decode(new URL(mfaSetup.totpURI).searchParams.get("secret")!));
    const initCode = await createOTP(mfaRawSecret, { digits: 6, period: 30 }).totp();
    await authProvider.api.verifyTOTP({ body: { code: initCode }, headers: new Headers({ cookie: mfaPreCookie }), asResponse: true });
  });

  after(async () => {
    globalThis.fetch = origFetch;
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("exercises consent-required authorization with zero ambient writes when enabled, and records row when disabled", async () => {
    const pkce = makePkce();
    const authUrl = `/api/auth/oauth2/authorize?client_id=${openConsentClient}&response_type=code&redirect_uri=${encodeURIComponent(openConsentCb)}&scope=openid+profile+email&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=s_c`;
    const authRes = await app.request(authUrl, { method: "GET", headers: getHeaders({ cookie: testUserSession }) });
    assert.equal(authRes.status, 302);
    const loc = authRes.headers.get("location") || "";
    assert.ok(loc.includes("/consent"));
    const consentQuery = new URL(loc, "http://localhost:5174").search.slice(1);
    const authCookies = authRes.headers.get("set-cookie") || "";

    const consentRes = await app.request("/api/auth/oauth2/consent", {
      method: "POST", headers: getHeaders({ "Content-Type": "application/json", Cookie: `${testUserSession}; ${authCookies}` }),
      body: JSON.stringify({ accept: true, oauth_query: consentQuery }),
    });
    assert.ok(consentRes.status === 200 || consentRes.status === 302);
    const cJson = consentRes.status === 200 ? await consentRes.json() : null;
    let target = consentRes.headers.get("location") || cJson?.url || cJson?.redirect_uri;
    assert.ok(target && new URL(target).searchParams.get("code"));

    const regCount = await db.collection("user_app_registrations").countDocuments({ clientId: openConsentClient, userId: testUserId });
    assert.equal(regCount, 0, "Zero registration rows under bypass");

    process.env.OPEN_APP_MEMBERSHIP_BYPASS_ENABLED = "false";
    try {
      await app.request("/api/auth/oauth2/consent", {
        method: "POST", headers: getHeaders({ "Content-Type": "application/json", Cookie: `${testUserSession}; ${authCookies}` }),
        body: JSON.stringify({ accept: true, oauth_query: consentQuery }),
      });
      const reg = await db.collection("user_app_registrations").findOne({ clientId: openConsentClient, userId: testUserId });
      assert.ok(reg, "Must record compatibility registration when bypass disabled");
    } finally {
      process.env.OPEN_APP_MEMBERSHIP_BYPASS_ENABLED = "true";
      await db.collection("user_app_registrations").deleteMany({ clientId: openConsentClient, userId: testUserId });
    }
  });

  it("exercises MFA continuation with zero ambient writes when enabled, and records row when disabled", async () => {
    const pkce = makePkce();
    const authUrl = `/api/auth/oauth2/authorize?client_id=${openMfaClient}&response_type=code&redirect_uri=${encodeURIComponent(openMfaCb)}&scope=openid+profile+email&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=s_m`;
    const initRes = await app.request(authUrl, { method: "GET", headers: getHeaders() });
    const txCookie = (initRes.headers.get("set-cookie") || "").split(";")[0];

    const signInRes = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: { ...getHeaders({ Cookie: txCookie }), "Content-Type": "application/json" },
      body: JSON.stringify({ email: mfaUserEmail, password: mfaUserPass }),
    });
    const mfaCookie = (signInRes.headers.get("set-cookie") || "").split(",").map((s) => s.trim().split(";")[0]).filter((c) => c.includes("two_factor")).join("; ");

    const totp = await createOTP(mfaRawSecret, { digits: 6, period: 30 }).totp();
    const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST", headers: { ...getHeaders({ Cookie: `${mfaCookie}; ${txCookie}` }), "Content-Type": "application/json" },
      body: JSON.stringify({ code: totp }),
    });
    assert.equal(verifyRes.status, 200);
    const sessionCookie = (verifyRes.headers.get("set-cookie") || "").split(",").map((s) => s.trim().split(";")[0]).filter((c) => c.includes("session_token")).join("; ");

    const resumeRes = await app.request(authUrl, { method: "GET", headers: getHeaders({ Cookie: `${sessionCookie}; ${txCookie}` }) });
    assert.equal(resumeRes.status, 302);
    assert.ok(new URL(resumeRes.headers.get("location")!).searchParams.get("code"));

    const count = await db.collection("user_app_registrations").countDocuments({ clientId: openMfaClient, userId: mfaUserId });
    assert.equal(count, 0, "Zero registration rows on MFA continuation under bypass");

    process.env.OPEN_APP_MEMBERSHIP_BYPASS_ENABLED = "false";
    try {
      const initRes2 = await app.request(authUrl, { method: "GET", headers: getHeaders() });
      const txCookie2 = (initRes2.headers.get("set-cookie") || "").split(";")[0];
      const sign2 = await app.request("/api/auth/sign-in/email", {
        method: "POST", headers: { ...getHeaders({ Cookie: txCookie2 }), "Content-Type": "application/json" },
        body: JSON.stringify({ email: mfaUserEmail, password: mfaUserPass }),
      });
      const mfaCookie2 = (sign2.headers.get("set-cookie") || "").split(",").map((s) => s.trim().split(";")[0]).filter((c) => c.includes("two_factor")).join("; ");
      const totp2 = await createOTP(mfaRawSecret, { digits: 6, period: 30 }).totp();
      await app.request("/api/auth/two-factor/verify-totp", {
        method: "POST", headers: { ...getHeaders({ Cookie: `${mfaCookie2}; ${txCookie2}` }), "Content-Type": "application/json" },
        body: JSON.stringify({ code: totp2 }),
      });
      const reg = await db.collection("user_app_registrations").findOne({ clientId: openMfaClient, userId: mfaUserId });
      assert.ok(reg, "Must record compatibility registration on MFA verify when bypass disabled");
    } finally {
      process.env.OPEN_APP_MEMBERSHIP_BYPASS_ENABLED = "true";
      await db.collection("user_app_registrations").deleteMany({ clientId: openMfaClient, userId: mfaUserId });
    }
  });

  it("exercises social callback path with zero ambient writes when enabled, and records row when disabled", async () => {
    mockGoogle = { sub: `g_open_${crypto.randomBytes(4).toString("hex")}`, email: `g_open_${Date.now()}@example.com`, name: "Social User" };
    const initRes = await app.request("/api/auth/sign-in/social", {
      method: "POST", headers: { ...getHeaders({ Cookie: `current_client_id=${openSocialClient}` }), "Content-Type": "application/json" },
      body: JSON.stringify({ provider: "google", callbackURL: "http://localhost:5174/dashboard" }),
    });
    const stateParam = new URL((await initRes.json()).url).searchParams.get("state") || "";
    const stateCookie = (initRes.headers.get("set-cookie") || "").split(",").map((s) => s.trim().split(";")[0]).find((c) => c.includes("better-auth.state")) || "";

    const cbRes = await app.request(`/api/auth/callback/google?state=${encodeURIComponent(stateParam)}&code=valid_test_code`, {
      method: "GET", headers: getHeaders({ Cookie: `${stateCookie}; current_client_id=${openSocialClient}` }),
    });
    assert.equal(cbRes.status, 302);

    const sUser = await db.collection("user").findOne({ email: mockGoogle.email });
    assert.ok(sUser);
    const sUserId = String(sUser._id || sUser.id);
    const count = await db.collection("user_app_registrations").countDocuments({ clientId: openSocialClient, userId: sUserId });
    assert.equal(count, 0, "Zero registration rows on social callback under bypass");

    process.env.OPEN_APP_MEMBERSHIP_BYPASS_ENABLED = "false";
    try {
      mockGoogle = { sub: `g_compat_${crypto.randomBytes(4).toString("hex")}`, email: `g_compat_${Date.now()}@example.com`, name: "Compat User" };
      const init2 = await app.request("/api/auth/sign-in/social", {
        method: "POST", headers: { ...getHeaders({ Cookie: `current_client_id=${openSocialClient}` }), "Content-Type": "application/json" },
        body: JSON.stringify({ provider: "google", callbackURL: "http://localhost:5174/dashboard" }),
      });
      const state2 = new URL((await init2.json()).url).searchParams.get("state") || "";
      const stateCookie2 = (init2.headers.get("set-cookie") || "").split(",").map((s) => s.trim().split(";")[0]).find((c) => c.includes("better-auth.state")) || "";

      await app.request(`/api/auth/callback/google?state=${encodeURIComponent(state2)}&code=valid_test_code_2`, {
        method: "GET", headers: getHeaders({ Cookie: `${stateCookie2}; current_client_id=${openSocialClient}` }),
      });
      const uCompat = await db.collection("user").findOne({ email: mockGoogle.email });
      assert.ok(uCompat);
      const reg = await db.collection("user_app_registrations").findOne({ clientId: openSocialClient, userId: String(uCompat._id || uCompat.id) });
      assert.ok(reg, "Must record compatibility registration on social callback when bypass disabled");
    } finally {
      process.env.OPEN_APP_MEMBERSHIP_BYPASS_ENABLED = "true";
    }
  });
});
