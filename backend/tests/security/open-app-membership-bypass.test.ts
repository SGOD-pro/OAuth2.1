import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("Open-App Membership Bypass Test Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;

  const openPubClientId = "test-open-pub-app";
  const openPubRedirect = "https://open-pub.example.com/callback";

  const openConfClientId = "test-open-conf-app";
  const openConfSecret = "open-conf-secret-value-12345";
  const openConfSecretHash = crypto.createHash("sha256").update(openConfSecret).digest("base64url");
  const openConfRedirect = "https://open-conf.example.com/callback";

  let userSession = "";
  let userEmail = "";
  let userId = "";
  let ipCounter = 700;

  function getTestHeaders(extra: Record<string, string> = {}): Record<string, string> {
    const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
    return {
      host: "localhost:3000",
      origin: "http://localhost:5174",
      "x-forwarded-for": `${ip}, 10.0.0.1`,
      "x-gateway-secret": "g".repeat(32),
      ...extra,
    };
  }

  function makePkce() {
    const verifier = crypto.randomBytes(32).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    return { verifier, challenge };
  }

  async function authorize(clientId: string, redirectUri: string, pkce: { verifier: string; challenge: string }, cookie = userSession) {
    const authUrl = `/api/auth/oauth2/authorize?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent("openid profile email offline_access")}&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=state_${Date.now()}`;
    const res = await app.request(authUrl, { method: "GET", headers: getTestHeaders({ cookie }) });
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location")!);
    const code = loc.searchParams.get("code")!;
    assert.ok(code, "Must receive authorization code in 302 location");
    return code;
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("open_app_bypass");
    const mongoUri = suite.uri;
    const dbName = suite.dbName;

    Object.assign(process.env, {
      NODE_ENV: "test",
      MONGO_URI: mongoUri,
      DB_NAME: dbName,
      BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000",
      FRONTEND_URL: "http://localhost:5174",
      GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret",
      INTERNAL_GATEWAY_SECRET: "g".repeat(32),
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      OPEN_APP_MEMBERSHIP_BYPASS_ENABLED: "true",
    });

    const mongoModule = await import("../../src/db/mongo");
    closeDb = mongoModule.closeDb;
    setTestDbOverride = mongoModule.setTestDbOverride;
    const appModule = await import("../../src/app");
    app = appModule.default;

    client = suite.client;
    db = client.db(dbName);
    setTestDbOverride(db);

    await db.collection("oauthClient").insertMany([
      {
        clientId: openPubClientId,
        name: "Open Public App",
        clientType: "public",
        accessPolicy: "open",
        isPublic: true,
        redirectUris: [openPubRedirect],
        allowedOrigins: ["https://open-pub.example.com"],
        disabled: false,
        skipConsent: true,
        tokenEndpointAuthMethod: "none",
        createdAt: new Date(),
      },
      {
        clientId: openConfClientId,
        name: "Open Confidential App",
        clientType: "confidential",
        accessPolicy: "open",
        isPublic: true,
        clientSecret: openConfSecretHash,
        redirectUris: [openConfRedirect],
        allowedOrigins: ["https://open-conf.example.com"],
        disabled: false,
        skipConsent: true,
        tokenEndpointAuthMethod: "client_secret_basic",
        createdAt: new Date(),
      },
    ]);

    userEmail = `bypass-user-${Date.now()}@example.com`;
    const signupRes = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: { ...getTestHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ email: userEmail, password: "Password12345!Secure", name: "Bypass User" }),
    });
    const cookieHeader = signupRes.headers.get("set-cookie") || "";
    userSession = cookieHeader.split(";")[0];
    const userDoc = await db.collection("user").findOne({ email: userEmail });
    userId = String(userDoc?.id || userDoc?._id);
    assert.ok(userId);
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("authorizes open public app with zero rows in user_app_registrations when bypass enabled", async () => {
    const regCountBefore = await db.collection("user_app_registrations").countDocuments({ clientId: openPubClientId });
    assert.equal(regCountBefore, 0, "Initial registration count must be 0");

    const pkce = makePkce();
    const code = await authorize(openPubClientId, openPubRedirect, pkce);

    // Verify 0 rows in user_app_registrations after authorize
    const regCountAfterAuth = await db.collection("user_app_registrations").countDocuments({ clientId: openPubClientId });
    assert.equal(regCountAfterAuth, 0, "Bypass must create zero rows in user_app_registrations on authorize");

    // Token exchange
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: openPubClientId,
        code,
        redirect_uri: openPubRedirect,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const tokenBody = await tokenRes.json();
    assert.ok(tokenBody.access_token);
    assert.ok(tokenBody.refresh_token);

    // Token refresh
    const refreshRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: openPubClientId,
        refresh_token: tokenBody.refresh_token,
      }).toString(),
    });
    assert.equal(refreshRes.status, 200);
    const refreshBody = await refreshRes.json();
    assert.ok(refreshBody.access_token);

    // UserInfo
    const userInfoRes = await app.request("/api/auth/oauth2/userinfo", {
      method: "GET",
      headers: getTestHeaders({ authorization: `Bearer ${refreshBody.access_token}` }),
    });
    assert.equal(userInfoRes.status, 200);
    const userInfoBody = await userInfoRes.json();
    assert.equal(userInfoBody.sub, userId);

    // Final registration count must remain exactly 0
    const finalRegCount = await db.collection("user_app_registrations").countDocuments({ clientId: openPubClientId });
    assert.equal(finalRegCount, 0, "Open public flow must complete with zero registration rows created");
  });

  it("authorizes open confidential app with zero rows in user_app_registrations when bypass enabled", async () => {
    const regCountBefore = await db.collection("user_app_registrations").countDocuments({ clientId: openConfClientId });
    assert.equal(regCountBefore, 0);

    const pkce = makePkce();
    const code = await authorize(openConfClientId, openConfRedirect, pkce);

    const regCountAfterAuth = await db.collection("user_app_registrations").countDocuments({ clientId: openConfClientId });
    assert.equal(regCountAfterAuth, 0, "Authorize must not create registration row");

    // Token exchange with Basic credentials
    const basicAuth = Buffer.from(`${openConfClientId}:${openConfSecret}`).toString("base64");
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basicAuth}`,
      }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: openConfRedirect,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);

    const finalRegCount = await db.collection("user_app_registrations").countDocuments({ clientId: openConfClientId });
    assert.equal(finalRegCount, 0, "Confidential open app flow must create zero registration rows");
  });

  it("writes compatibility row to user_app_registrations when bypass is disabled", async () => {
    process.env.OPEN_APP_MEMBERSHIP_BYPASS_ENABLED = "false";
    try {
      const uniqueClient = "test-open-compat-app";
      const uniqueRedirect = "https://open-compat.example.com/callback";
      await db.collection("oauthClient").insertOne({
        clientId: uniqueClient,
        name: "Open Compat App",
        clientType: "public",
        accessPolicy: "open",
        isPublic: true,
        redirectUris: [uniqueRedirect],
        allowedOrigins: ["https://open-compat.example.com"],
        disabled: false,
        skipConsent: true,
        tokenEndpointAuthMethod: "none",
        createdAt: new Date(),
      });

      const pkce = makePkce();
      await authorize(uniqueClient, uniqueRedirect, pkce);

      const reg = await db.collection("user_app_registrations").findOne({ clientId: uniqueClient, userId });
      assert.ok(reg, "Must create compatibility membership row when bypass is disabled");
    } finally {
      process.env.OPEN_APP_MEMBERSHIP_BYPASS_ENABLED = "true";
    }
  });

  it("skips ambient writes in email sign-up and sign-in when bypass is enabled", async () => {
    const ambientEmail = `ambient-${Date.now()}@example.com`;
    // Direct sign-up with ambient client context
    await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: { ...getTestHeaders({ "x-client-id": openPubClientId }), "Content-Type": "application/json" },
      body: JSON.stringify({ email: ambientEmail, password: "Password12345!Secure", name: "Ambient User" }),
    });

    const ambientDoc = await db.collection("user").findOne({ email: ambientEmail });
    assert.ok(ambientDoc);
    const ambientUserId = String(ambientDoc.id || ambientDoc._id);

    const regAfterSignup = await db.collection("user_app_registrations").findOne({ clientId: openPubClientId, userId: ambientUserId });
    assert.equal(regAfterSignup, null, "Ambient sign-up must not insert into user_app_registrations");

    // Direct sign-in with ambient client context
    await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: { ...getTestHeaders({ "x-client-id": openPubClientId }), "Content-Type": "application/json" },
      body: JSON.stringify({ email: ambientEmail, password: "Password12345!Secure" }),
    });

    const regAfterSignin = await db.collection("user_app_registrations").findOne({ clientId: openPubClientId, userId: ambientUserId });
    assert.equal(regAfterSignin, null, "Ambient sign-in must not insert into user_app_registrations");
  });
});
