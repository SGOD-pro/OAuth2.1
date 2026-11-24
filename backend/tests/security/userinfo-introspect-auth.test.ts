import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db, ObjectId } from "mongodb";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("UserInfo Engine-Success & Introspection Auth Gating Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let privateKey: any;
  const kid = "test-key-ui-intro-auth";

  const privClientId = "test-ui-priv-app";
  const otherClientId = "test-ui-other-app";
  const postClientId = "test-ui-post-app";
  const clientSecret = "secret-value-12345";
  const hashedSecret = crypto.createHash("sha256").update(clientSecret).digest("base64url");
  const postSecret = "post-secret-67890";
  const postSecretHash = crypto.createHash("sha256").update(postSecret).digest("base64url");
  const basicAuth = Buffer.from(`${privClientId}:${clientSecret}`).toString("base64");
  const otherBasicAuth = Buffer.from(`${otherClientId}:${clientSecret}`).toString("base64");

  let testUserId = "";
  const rawOpaqueToken = "opaque_token_valid_engine_success_12345";
  const hashedOpaqueToken = crypto.createHash("sha256").update(rawOpaqueToken).digest("base64url");
  let validJwtToken = "";
  let ipCounter = 900;

  function getHeaders(extra: Record<string, string> = {}): Record<string, string> {
    const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
    return { host: "localhost:3000", origin: "http://localhost:5174", "x-forwarded-for": `${ip}, 10.0.0.1`, "x-gateway-secret": "g".repeat(32), ...extra };
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("ui_intro_auth");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName, BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000", FRONTEND_URL: "http://localhost:5174", INTERNAL_GATEWAY_SECRET: "g".repeat(32),
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32", GOOGLE_CLIENT_ID: "test-google-id", GOOGLE_CLIENT_SECRET: "test-google-secret",
      OPEN_APP_MEMBERSHIP_BYPASS_ENABLED: "true",
    });

    const keypair = await generateKeyPair("RS256", { extractable: true });
    privateKey = keypair.privateKey;
    const pubJwk: any = await exportJWK(keypair.publicKey);
    pubJwk.kid = kid; pubJwk.alg = "RS256"; pubJwk.use = "sig";
    const privJwk: any = await exportJWK(privateKey);
    privJwk.kid = kid; privJwk.alg = "RS256"; privJwk.use = "sig";

    const { symmetricEncrypt } = await import("better-auth/crypto");
    const enc = await symmetricEncrypt({ key: process.env.BETTER_AUTH_SECRET!, data: JSON.stringify(privJwk) });

    const mongoModule = await import("../../src/db/mongo");
    closeDb = mongoModule.closeDb;
    setTestDbOverride = mongoModule.setTestDbOverride;
    app = (await import("../../src/app")).default;
    client = suite.client;
    db = client.db(suite.dbName);
    setTestDbOverride(db);

    await db.collection("jwks").insertOne({ id: kid, kid, alg: "RS256", publicKey: JSON.stringify(pubJwk), privateKey: JSON.stringify(enc), createdAt: new Date() });
    await db.collection("oauthClient").insertMany([
      { clientId: privClientId, clientSecret: hashedSecret, name: "Private UI App", clientType: "confidential", accessPolicy: "private", isPublic: false, redirectUris: ["https://priv.example.com/cb"], tokenEndpointAuthMethod: "client_secret_basic", createdAt: new Date() },
      { clientId: otherClientId, clientSecret: hashedSecret, name: "Other App", clientType: "confidential", accessPolicy: "private", isPublic: false, redirectUris: ["https://other.example.com/cb"], tokenEndpointAuthMethod: "client_secret_basic", createdAt: new Date() },
      { clientId: postClientId, clientSecret: postSecretHash, name: "Post App", clientType: "confidential", accessPolicy: "open", isPublic: true, redirectUris: ["https://post.example.com/cb"], tokenEndpointAuthMethod: "client_secret_post", token_endpoint_auth_method: "client_secret_post", createdAt: new Date() },
    ]);

    const userOid = new ObjectId();
    testUserId = userOid.toHexString();
    await db.collection("user").insertOne({ _id: userOid, id: testUserId, email: "ui-user@example.com", emailVerified: true, name: "UI User", role: "user", createdAt: new Date(), updatedAt: new Date() });
    await db.collection("user_app_registrations").insertOne({ userId: testUserId, clientId: privClientId, registeredAt: new Date() });
    await db.collection("oauthAccessToken").insertOne({ token: hashedOpaqueToken, clientId: privClientId, userId: testUserId, scopes: ["openid", "profile", "email"], createdAt: new Date(), expiresAt: new Date(Date.now() + 3600000) });

    validJwtToken = await new SignJWT({ sub: testUserId, client_id: privClientId, aud: privClientId, scope: "openid profile email", token_version: 1 })
      .setProtectedHeader({ alg: "RS256", kid }).setIssuer("http://localhost:3000").setIssuedAt().setExpirationTime("1h").sign(privateKey);
    await db.collection("oauthAccessToken").insertOne({ token: validJwtToken, clientId: privClientId, userId: testUserId, createdAt: new Date(), expiresAt: new Date(Date.now() + 3600000) });
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  // --- USERINFO ENGINE-SUCCESS TESTS ---
  it("UserInfo engine-success allows valid access for authorized member on private client", async () => {
    const res = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getHeaders({ Authorization: `Bearer ${rawOpaqueToken}` }) });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.sub, testUserId);
    assert.equal(body.role, "user");
    assert.equal(body.scoped_client_id, null);
  });

  it("UserInfo engine-success denies access (403) when private client assignment is deleted", async () => {
    await db.collection("user_app_registrations").deleteOne({ userId: testUserId, clientId: privClientId });
    const res = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getHeaders({ Authorization: `Bearer ${rawOpaqueToken}` }) });
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.error, "forbidden");
    await db.collection("user_app_registrations").insertOne({ userId: testUserId, clientId: privClientId, registeredAt: new Date() });
  });

  it("UserInfo engine-success rejects query-client substitution (400)", async () => {
    const res = await app.request(`/api/auth/oauth2/userinfo?client_id=${otherClientId}`, { method: "GET", headers: getHeaders({ Authorization: `Bearer ${rawOpaqueToken}` }) });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, "invalid_request");
  });

  it("UserInfo engine-success fails closed (401) when client context is missing", async () => {
    const orphanRaw = "orphan_opaque_token_raw";
    const orphanHash = crypto.createHash("sha256").update(orphanRaw).digest("base64url");
    await db.collection("oauthAccessToken").insertOne({ token: orphanHash, userId: testUserId, scopes: ["openid", "profile", "email"], createdAt: new Date(), expiresAt: new Date(Date.now() + 3600000) });
    const res = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getHeaders({ Authorization: `Bearer ${orphanRaw}` }) });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "invalid_token");
  });

  // --- INTROSPECTION AUTHENTICATION GATING TESTS ---
  it("Introspection rejects unauthenticated caller with missing credentials (401)", async () => {
    const res = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded" }), body: `token=${validJwtToken}` });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");
    assert.notEqual(body.active, true);
  });

  it("Introspection rejects confidential caller supplying client_id without client_secret (401)", async () => {
    const res = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded" }), body: `token=${validJwtToken}&client_id=${privClientId}` });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");
    assert.notEqual(body.active, true);
  });

  it("Introspection preserves engine rejection for wrong Basic credentials (401)", async () => {
    const badBasic = Buffer.from(`${privClientId}:wrongsecret`).toString("base64");
    const res = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${badBasic}` }), body: `token=${validJwtToken}` });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");
    assert.notEqual(body.active, true);
  });

  it("Introspection preserves engine rejection for wrong body credentials (400)", async () => {
    const res = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded" }), body: `token=${validJwtToken}&client_id=${postClientId}&client_secret=wrong_post_secret` });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");
    assert.notEqual(body.active, true);
  });

  it("Introspection denies cross-client token introspection (200 active: false)", async () => {
    const res = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${otherBasicAuth}` }), body: `token=${validJwtToken}` });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).active, false);
  });

  it("Introspection allows valid authenticated caller to introspect their own RS256 token (200 active: true)", async () => {
    const res = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }), body: `token=${validJwtToken}` });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.active, true);
    assert.equal(body.sub, testUserId);
    assert.equal(body.client_id, privClientId);
  });

  it("Introspection fails closed and never returns active:true on engine error", async () => {
    const res = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded" }), body: `token=${validJwtToken}&client_id=nonexistent_client&client_secret=foo` });
    assert.notEqual(res.status, 200);
    assert.notEqual((await res.json()).active, true);
  });
});
