import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { MongoMemoryServer } from "mongodb-memory-server";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("OAuth V2 P1b: Client Policy Enforcement and Ambiguous Denial Suite", () => {
  let mongod: MongoMemoryServer;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let resolveOAuthClient: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let authProvider: any;
  let validSessionCookie = "";
  const dbName = "p1b_runtime_enforcement";
  const rawSecret = "test-secret-value-12345";

  before(async () => {
    isolateTestEnvironment();
    mongod = await MongoMemoryServer.create({ binary: { version: "7.0.24" } });
    const mongoUri = mongod.getUri();

    process.env.NODE_ENV = "test";
    process.env.MONGO_URI = mongoUri;
    process.env.DB_NAME = dbName;
    process.env.BETTER_AUTH_SECRET = "a".repeat(32);
    process.env.BETTER_AUTH_URL = "http://localhost:3000";
    process.env.FRONTEND_URL = "http://localhost:5174";
    process.env.GOOGLE_CLIENT_ID = "test-google-id";
    process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
    process.env.INTERNAL_GATEWAY_SECRET = "g".repeat(32);
    process.env.TRUSTED_PROXY_CIDRS = "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32";

    const mongoModule = await import("../../src/db/mongo");
    closeDb = mongoModule.closeDb;
    setTestDbOverride = mongoModule.setTestDbOverride;

    const authModule = await import("../../src/utils/auth");
    authProvider = authModule.authProvider;

    const appModule = await import("../../src/app");
    app = appModule.default;
    const resolverModule = await import("../../src/utils/client-resolver");
    resolveOAuthClient = resolverModule.resolveOAuthClient;

    client = new MongoClient(mongoUri);
    await client.connect();
    db = client.db(dbName);
    setTestDbOverride(db);

    // Seed fixture clients: 4 clean classes, 1 migrated, 1 ambiguous
    await db.collection("oauthClient").insertMany([
      { clientId: "c-open-pub", isPublic: true, is_public: true, redirectUris: ["https://open-pub.com/cb"] },
      { clientId: "c-priv-conf", isPublic: false, clientSecret: rawSecret, redirectUris: ["https://priv-conf.com/cb"] },
      { clientId: "c-open-conf", isPublic: true, client_secret: rawSecret, redirectUris: ["https://open-conf.com/cb"] },
      { clientId: "c-priv-pub", isPublic: false, application_type: "native", redirectUris: ["https://native.com/cb"] },
      { clientId: "c-migrated", clientType: "confidential", accessPolicy: "open", clientSecret: rawSecret, redirectUris: ["https://v2.com/cb"] },
      { clientId: "c-ambiguous", isPublic: true, redirectUris: ["https://bad.com/cb#fragment"] },
    ]);

    // Create test user and obtain valid session cookie for consent endpoints
    const testEmail = "testuser@example.com";
    const testPassword = "Password@1234!";
    await authProvider.api.signUpEmail({
      body: { email: testEmail, password: testPassword, name: "Test User" },
    });
    const signInRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: testEmail, password: testPassword }),
    });
    const rawSetCookie = signInRes.headers.get("set-cookie") || "";
    const tokenMatch = rawSetCookie.match(/better-auth\.session_token=([^;]+)/);
    validSessionCookie = tokenMatch ? `better-auth.session_token=${tokenMatch[1]}` : "";

    // Seed token family and tokens for revocation zero mutation verification
    await db.collection("oauth_token_families").insertOne({
      familyId: "fam-ambig-test",
      clientId: "c-ambiguous",
      activeTokenHash: "dummy-active-hash",
      status: "active",
      createdAt: new Date(),
    });
    await db.collection("oauthAccessToken").insertOne({
      token: "dummy-token-for-revoke",
      clientId: "c-ambiguous",
      familyId: "fam-ambig-test",
    });
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (client) await client.close();
    if (closeDb) await closeDb();
    if (mongod) await mongod.stop();
  });

  it("carries validated policy dimensions through canonical client representation", async () => {
    const openPub = await resolveOAuthClient(db, "c-open-pub");
    assert.ok(openPub);
    assert.equal(openPub.clientType, "public");
    assert.equal(openPub.accessPolicy, "open");
    assert.equal(openPub.classification, "COMPATIBLE_OPEN_PUBLIC");
    assert.equal(openPub.isAmbiguous, false);

    const privConf = await resolveOAuthClient(db, "c-priv-conf");
    assert.ok(privConf);
    assert.equal(privConf.clientType, "confidential");
    assert.equal(privConf.accessPolicy, "private");
    assert.equal(privConf.classification, "COMPATIBLE_PRIVATE_CONFIDENTIAL");
    assert.equal(privConf.isAmbiguous, false);

    const openConf = await resolveOAuthClient(db, "c-open-conf");
    assert.ok(openConf);
    assert.equal(openConf.clientType, "confidential");
    assert.equal(openConf.accessPolicy, "open");
    assert.equal(openConf.classification, "COMPATIBLE_OPEN_CONFIDENTIAL");
    assert.equal(openConf.isAmbiguous, false);

    const privPub = await resolveOAuthClient(db, "c-priv-pub");
    assert.ok(privPub);
    assert.equal(privPub.clientType, "public");
    assert.equal(privPub.accessPolicy, "private");
    assert.equal(privPub.classification, "COMPATIBLE_PRIVATE_PUBLIC");
    assert.equal(privPub.isAmbiguous, false);

    const migrated = await resolveOAuthClient(db, "c-migrated");
    assert.ok(migrated);
    assert.equal(migrated.clientType, "confidential");
    assert.equal(migrated.accessPolicy, "open");
    assert.equal(migrated.classification, "MIGRATED");
    assert.equal(migrated.isAmbiguous, false);

    const ambiguous = await resolveOAuthClient(db, "c-ambiguous");
    assert.ok(ambiguous);
    assert.equal(ambiguous.isAmbiguous, true);
    assert.equal(ambiguous.classification, "AMBIGUOUS");
    assert.ok(ambiguous.ambiguityReasonCodes.includes("INVALID_REDIRECT_URI"));
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
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost:5174",
        "Cookie": validSessionCookie,
      },
      body: JSON.stringify({ client_id: "c-ambiguous", consent: true }),
    });
    assert.equal(consentRes.status, 400);
    const consentBody = await consentRes.json();
    assert.equal(consentBody.error, "invalid_client");

    const continueRes = await app.request("/api/auth/oauth2/continue", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost:5174",
        "Cookie": validSessionCookie,
      },
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
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "test-code",
        client_id: "c-ambiguous",
      }).toString(),
    });
    assert.equal(codeRes.status, 401);
    const codeBody = await codeRes.json();
    assert.equal(codeBody.error, "invalid_client");

    const refreshRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: "test-refresh",
        client_id: "c-ambiguous",
      }).toString(),
    });
    assert.equal(refreshRes.status, 401);
    const refreshBody = await refreshRes.json();
    assert.equal(refreshBody.error, "invalid_client");
  });

  it("rejects ambiguous calling client at introspect with HTTP 401", async () => {
    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: "dummy-token",
        client_id: "c-ambiguous",
      }).toString(),
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");
  });

  it("rejects ambiguous calling client at revoke with HTTP 401 and zero mutations", async () => {
    const res = await app.request("/api/auth/oauth2/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: "dummy-token-for-revoke",
        client_id: "c-ambiguous",
      }).toString(),
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");

    // Verify zero mutations occurred
    const family = await db.collection("oauth_token_families").findOne({ familyId: "fam-ambig-test" });
    assert.ok(family);
    assert.equal(family.status, "active", "Token family status must remain active");

    const tokenDoc = await db.collection("oauthAccessToken").findOne({ token: "dummy-token-for-revoke" });
    assert.ok(tokenDoc, "Access token must not be deleted");
  });

  it("rejects ambiguous client at initiate, sign in, and sign up with HTTP 400", async () => {
    const initRes = await app.request("/api/auth/oauth/initiate?client_id=c-ambiguous");
    assert.equal(initRes.status, 400);

    const signInRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost:5174",
      },
      body: JSON.stringify({ email: "user@example.com", password: "Password123!", client_id: "c-ambiguous" }),
    });
    assert.equal(signInRes.status, 400);

    const signUpRes = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost:5174",
      },
      body: JSON.stringify({ email: "newuser@example.com", password: "Password123!", client_id: "c-ambiguous" }),
    });
    assert.equal(signUpRes.status, 400);
  });

  it("allows clean legacy clients to proceed through authorize endpoint", async () => {
    const res = await app.request(
      "/api/auth/oauth2/authorize?client_id=c-open-pub&redirect_uri=https%3A%2F%2Fopen-pub.com%2Fcb&response_type=code&state=clean-state-123"
    );
    // Unauthenticated user is redirected (302) to login with transaction cookie set
    assert.equal(res.status, 302);
    const location = res.headers.get("location");
    assert.ok(location);
    const cookies = res.headers.get("set-cookie");
    assert.ok(cookies?.includes("oauth_transaction_id"));
  });
});
