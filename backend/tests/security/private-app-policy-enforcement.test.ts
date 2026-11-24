import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("Private App Policy Enforcement Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;

  const privConfClientId = "test-priv-conf-app";
  const privConfSecret = "priv-conf-secret-value-12345";
  const privConfSecretHash = crypto.createHash("sha256").update(privConfSecret).digest("base64url");
  const privConfRedirect = "https://priv-conf.example.com/callback";

  let memberSession = "";
  let memberUserId = "";
  let unassignedSession = "";
  let superAdminSession = "";
  let ipCounter = 600;

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

  async function registerUser(email: string, role = "user") {
    const res = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: { ...getTestHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: "Password12345!Secure", name: "Test User" }),
    });
    const cookie = (res.headers.get("set-cookie") || "").split(";")[0];
    const userDoc = await db.collection("user").findOne({ email });
    if (role !== "user") {
      await db.collection("user").updateOne({ _id: userDoc!._id }, { $set: { role } });
    }
    return { cookie, userId: String(userDoc!.id || userDoc!._id) };
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("priv_policy_enforcement");
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

    await db.collection("oauthClient").insertOne({
      clientId: privConfClientId,
      name: "Private Confidential App",
      clientType: "confidential",
      accessPolicy: "private",
      isPublic: false,
      clientSecret: privConfSecretHash,
      redirectUris: [privConfRedirect],
      allowedOrigins: ["https://priv-conf.example.com"],
      disabled: false,
      skipConsent: true,
      tokenEndpointAuthMethod: "client_secret_basic",
      createdAt: new Date(),
    });

    const m = await registerUser(`member-${Date.now()}@example.com`);
    memberSession = m.cookie;
    memberUserId = m.userId;

    const u = await registerUser(`unassigned-${Date.now()}@example.com`);
    unassignedSession = u.cookie;

    const s = await registerUser(`superadmin-${Date.now()}@example.com`, "super-admin");
    superAdminSession = s.cookie;

    // Provision active membership for memberUserId
    await db.collection("user_app_registrations").insertOne({
      userId: memberUserId,
      clientId: privConfClientId,
      registeredAt: new Date(),
      status: "active",
      isActive: true,
      revoked: false,
    });
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("denies unassigned user with 302 access_denied on private app", async () => {
    const pkce = makePkce();
    const authUrl = `/api/auth/oauth2/authorize?client_id=${privConfClientId}&response_type=code&redirect_uri=${encodeURIComponent(privConfRedirect)}&scope=openid&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=state_unassigned`;
    const res = await app.request(authUrl, { method: "GET", headers: getTestHeaders({ cookie: unassignedSession }) });
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location")!);
    assert.equal(loc.searchParams.get("error"), "access_denied");
  });

  it("strictly excludes super-admin from private app with 302 access_denied", async () => {
    const pkce = makePkce();
    const authUrl = `/api/auth/oauth2/authorize?client_id=${privConfClientId}&response_type=code&redirect_uri=${encodeURIComponent(privConfRedirect)}&scope=openid&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=state_superadmin`;
    const res = await app.request(authUrl, { method: "GET", headers: getTestHeaders({ cookie: superAdminSession }) });
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location")!);
    assert.equal(loc.searchParams.get("error"), "access_denied");
  });

  it("allows active member, then revoking access invalidates refresh, UserInfo, and introspection", async () => {
    const pkce = makePkce();
    const authUrl = `/api/auth/oauth2/authorize?client_id=${privConfClientId}&response_type=code&redirect_uri=${encodeURIComponent(privConfRedirect)}&scope=${encodeURIComponent("openid profile email offline_access")}&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=state_member`;
    const res = await app.request(authUrl, { method: "GET", headers: getTestHeaders({ cookie: memberSession }) });
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location")!);
    const code = loc.searchParams.get("code")!;
    assert.ok(code);

    // Initial valid exchange
    const basicAuth = Buffer.from(`${privConfClientId}:${privConfSecret}`).toString("base64");
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basicAuth}`,
      }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: privConfRedirect,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const tokenBody = await tokenRes.json();
    assert.ok(tokenBody.access_token);
    assert.ok(tokenBody.refresh_token);

    // Initial UserInfo succeeds
    const userinfoBefore = await app.request("/api/auth/oauth2/userinfo", {
      method: "GET",
      headers: getTestHeaders({ authorization: `Bearer ${tokenBody.access_token}` }),
    });
    assert.equal(userinfoBefore.status, 200);

    // Initial introspection returns active: true
    const introspectBefore = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basicAuth}`,
      }),
      body: new URLSearchParams({ token: tokenBody.access_token }).toString(),
    });
    assert.equal(introspectBefore.status, 200);
    const introBeforeBody = await introspectBefore.json();
    assert.equal(introBeforeBody.active, true);

    // NOW REVOKE MEMBERSHIP
    await db.collection("user_app_registrations").updateOne(
      { userId: memberUserId, clientId: privConfClientId },
      { $set: { status: "revoked", revoked: true, isActive: false, active: false } }
    );

    // 1. Subsequent authorize must be denied (302 access_denied)
    const pkce2 = makePkce();
    const authRevokedRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${privConfClientId}&response_type=code&redirect_uri=${encodeURIComponent(privConfRedirect)}&scope=openid&code_challenge=${pkce2.challenge}&code_challenge_method=S256&state=state_revoked`,
      { method: "GET", headers: getTestHeaders({ cookie: memberSession }) }
    );
    assert.equal(authRevokedRes.status, 302);
    const locRevoked = new URL(authRevokedRes.headers.get("location")!);
    assert.equal(locRevoked.searchParams.get("error"), "access_denied");

    // 2. Token refresh must be rejected (401 invalid_grant) and revoke family
    const refreshRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basicAuth}`,
      }),
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokenBody.refresh_token,
      }).toString(),
    });
    assert.equal(refreshRes.status, 401);
    const refreshBody = await refreshRes.json();
    assert.equal(refreshBody.error, "invalid_grant");

    const familyDoc = await db.collection("oauth_token_families").findOne({ clientId: privConfClientId, userId: memberUserId });
    assert.ok(familyDoc);
    assert.equal(familyDoc.status, "revoked", "Family must be marked revoked on private membership denial");

    // 3. UserInfo must be forbidden (403 forbidden)
    const userinfoAfter = await app.request("/api/auth/oauth2/userinfo", {
      method: "GET",
      headers: getTestHeaders({ authorization: `Bearer ${tokenBody.access_token}` }),
    });
    assert.equal(userinfoAfter.status, 403);

    // 4. Introspection must return { active: false }
    const introspectAfter = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basicAuth}`,
      }),
      body: new URLSearchParams({ token: tokenBody.access_token }).toString(),
    });
    assert.equal(introspectAfter.status, 200);
    const introAfterBody = await introspectAfter.json();
    assert.equal(introAfterBody.active, false);
  });
});
