import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P1b: Client Policy Enforcement and Ambiguous Denial Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let resolveOAuthClient: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let authProvider: any;
  let validSessionCookie = "";
  let testUserId = "";
  let dbName = "";
  const rawSecret = "test-secret-value-12345";
  const rawSecretHash = crypto.createHash("sha256").update(rawSecret).digest("base64url");

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p1b_enforcement");
    dbName = suite.dbName;
    const mongoUri = suite.uri;

    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: mongoUri, DB_NAME: dbName,
      BETTER_AUTH_SECRET: "a".repeat(32), BETTER_AUTH_URL: "http://localhost:3000",
      FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: "g".repeat(32),
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
    });

    const mongoModule = await import("../../src/db/mongo");
    closeDb = mongoModule.closeDb;
    setTestDbOverride = mongoModule.setTestDbOverride;
    const authModule = await import("../../src/utils/auth");
    authProvider = authModule.authProvider;
    const appModule = await import("../../src/app");
    app = appModule.default;
    const resolverModule = await import("../../src/utils/client-resolver");
    resolveOAuthClient = resolverModule.resolveOAuthClient;

    client = suite.client;
    db = client.db(dbName);
    setTestDbOverride(db);

    await db.collection("oauthClient").insertMany([
      { clientId: "c-open-pub", isPublic: true, is_public: true, redirectUris: ["https://open-pub.com/cb"] },
      { clientId: "c-priv-conf", isPublic: false, clientSecret: rawSecretHash, redirectUris: ["https://priv-conf.com/cb"] },
      { clientId: "c-open-conf", isPublic: true, clientSecret: rawSecretHash, redirectUris: ["https://open-conf.com/cb"] },
      { clientId: "c-priv-pub", isPublic: false, application_type: "native", redirectUris: ["https://native.com/cb"] },
      { clientId: "c-migrated", clientType: "confidential", accessPolicy: "open", clientSecret: rawSecretHash, redirectUris: ["https://v2.com/cb"] },
      { clientId: "c-ambiguous", isPublic: true, redirectUris: ["https://bad.com/cb#fragment"] },
    ]);

    const testEmail = "testuser@example.com";
    const testPassword = "Password@1234!";
    const signUpResult = await authProvider.api.signUpEmail({
      body: { email: testEmail, password: testPassword, name: "Test User" },
    });
    testUserId = signUpResult.user.id;

    const signInRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: testEmail, password: testPassword }),
    });
    const rawSetCookie = signInRes.headers.get("set-cookie") || "";
    const tokenMatch = rawSetCookie.match(/better-auth\.session_token=([^;]+)/);
    validSessionCookie = tokenMatch ? `better-auth.session_token=${tokenMatch[1]}` : "";

    await db.collection("oauth_token_families").insertOne({
      familyId: "fam-ambig-test", clientId: "c-ambiguous", activeTokenHash: "dummy-active-hash", status: "active", createdAt: new Date(),
    });
    await db.collection("oauthAccessToken").insertOne({
      token: "dummy-token-for-revoke", clientId: "c-ambiguous", familyId: "fam-ambig-test",
    });
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("carries validated policy dimensions through canonical client representation", async () => {
    const expectations = [
      { id: "c-open-pub", type: "public", policy: "open", class: "COMPATIBLE_OPEN_PUBLIC", ambig: false },
      { id: "c-priv-conf", type: "confidential", policy: "private", class: "COMPATIBLE_PRIVATE_CONFIDENTIAL", ambig: false },
      { id: "c-open-conf", type: "confidential", policy: "open", class: "COMPATIBLE_OPEN_CONFIDENTIAL", ambig: false },
      { id: "c-priv-pub", type: "public", policy: "private", class: "COMPATIBLE_PRIVATE_PUBLIC", ambig: false },
      { id: "c-migrated", type: "confidential", policy: "open", class: "MIGRATED", ambig: false },
      { id: "c-ambiguous", ambig: true, class: "AMBIGUOUS" },
    ];
    for (const exp of expectations) {
      const doc = await resolveOAuthClient(db, exp.id);
      assert.ok(doc, `Client ${exp.id} must be resolved`);
      assert.equal(doc.isAmbiguous, exp.ambig);
      assert.equal(doc.classification, exp.class);
      if (exp.type) assert.equal(doc.clientType, exp.type);
      if (exp.policy) assert.equal(doc.accessPolicy, exp.policy);
    }
  });

  it("rejects ambiguous client at authorize with direct HTTP 400 (no redirect)", async () => {
    const res = await app.request(
      "/api/auth/oauth2/authorize?client_id=c-ambiguous&redirect_uri=https%3A%2F%2Fbad.com%2Fcb&response_type=code&state=xyz123"
    );
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");
    assert.ok(body.error_description.includes("ambiguous"));
  });

  it("rejects ambiguous client at consent and continuation with direct HTTP 400", async () => {
    const consentRes = await app.request("/api/auth/oauth2/consent", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174", "Cookie": validSessionCookie },
      body: JSON.stringify({ client_id: "c-ambiguous", consent: true }),
    });
    assert.equal(consentRes.status, 400);
    const consentBody = await consentRes.json();
    assert.equal(consentBody.error, "invalid_client");

    const continueRes = await app.request("/api/auth/oauth2/continue", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174", "Cookie": validSessionCookie },
      body: JSON.stringify({ client_id: "c-ambiguous" }),
    });
    assert.equal(continueRes.status, 400);
    const continueBody = await continueRes.json();
    assert.equal(continueBody.error, "invalid_client");
  });

  it("rejects ambiguous client at token code and refresh grant with HTTP 401", async () => {
    const codeRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code: "test-code", client_id: "c-ambiguous" }).toString(),
    });
    assert.equal(codeRes.status, 401);
    const codeBody = await codeRes.json();
    assert.equal(codeBody.error, "invalid_client");

    const refreshRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: "test-refresh", client_id: "c-ambiguous" }).toString(),
    });
    assert.equal(refreshRes.status, 401);
    const refreshBody = await refreshRes.json();
    assert.equal(refreshBody.error, "invalid_client");
  });

  it("rejects ambiguous calling client at introspect with HTTP 401", async () => {
    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: "dummy-token", client_id: "c-ambiguous" }).toString(),
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");
  });

  it("includes Basic challenge header when ambiguous client uses Basic auth", async () => {
    const creds = Buffer.from("c-ambiguous:dummy").toString("base64");
    const endpoints = [
      { path: "/api/auth/oauth2/token", body: "grant_type=authorization_code&code=test" },
      { path: "/api/auth/oauth2/revoke", body: "token=dummy" },
      { path: "/api/auth/oauth2/introspect", body: "token=dummy" },
    ];
    for (const ep of endpoints) {
      const res = await app.request(ep.path, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "Authorization": `Basic ${creds}` },
        body: ep.body,
      });
      assert.equal(res.status, 401);
      assert.equal(res.headers.get("www-authenticate"), 'Basic realm="OAuth"');
      const json = await res.json();
      assert.equal(json.error, "invalid_client");
    }
  });

  it("rejects ambiguous calling client at revoke with HTTP 401 and zero mutations", async () => {
    const res = await app.request("/api/auth/oauth2/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: "dummy-token-for-revoke", client_id: "c-ambiguous" }).toString(),
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");

    const family = await db.collection("oauth_token_families").findOne({ familyId: "fam-ambig-test" });
    assert.ok(family);
    assert.equal(family.status, "active", "Token family status must remain active");

    const tokenDoc = await db.collection("oauthAccessToken").findOne({ token: "dummy-token-for-revoke" });
    assert.ok(tokenDoc, "Access token must not be deleted");
  });

  it("returns active false on authenticated introspection of token targeting ambiguous client", async () => {
    const { mintJwtAccessToken } = await import("../../src/routes/auth-jwt");
    const token = await mintJwtAccessToken({ userId: testUserId, clientId: "c-ambiguous" });
    assert.ok(token);

    await db.collection("oauthAccessToken").insertOne({
      token, clientId: "c-ambiguous", userId: testUserId, expiresAt: new Date(Date.now() + 3600000),
    });

    const validCreds = Buffer.from(`c-open-conf:${rawSecret}`).toString("base64");
    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Authorization": `Basic ${validCreds}` },
      body: new URLSearchParams({ token }).toString(),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.active, false);
  });

  it("rejects ambiguous client at initiate, sign in, and sign up with HTTP 400", async () => {
    const initRes = await app.request("/api/auth/oauth/initiate?client_id=c-ambiguous");
    assert.equal(initRes.status, 400);

    const signInRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: "user@example.com", password: "Password123!", client_id: "c-ambiguous" }),
    });
    assert.equal(signInRes.status, 400);

    const signUpRes = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: "newuser@example.com", password: "Password123!", client_id: "c-ambiguous" }),
    });
    assert.equal(signUpRes.status, 400);
  });

  it("allows clean legacy clients to proceed through authorize endpoint", async () => {
    const res = await app.request(
      "/api/auth/oauth2/authorize?client_id=c-open-pub&redirect_uri=https%3A%2F%2Fopen-pub.com%2Fcb&response_type=code&state=clean-state-123"
    );
    assert.equal(res.status, 302);
    const location = res.headers.get("location");
    assert.ok(location);
    const cookies = res.headers.get("set-cookie");
    assert.ok(cookies?.includes("oauth_transaction_id"));
  });
});
