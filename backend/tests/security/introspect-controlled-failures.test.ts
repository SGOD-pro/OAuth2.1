import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db, ObjectId } from "mongodb";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("Introspection Controlled Engine Failures & Auth Gating Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let authModule: any;
  let originalHandler: any;
  let privateKey: any;
  const kid = "test-key-intro-ctrl-fail";

  const privClientId = "test-ctrl-priv-app";
  const postClientId = "test-ctrl-post-app";
  const clientSecret = "secret-value-12345";
  const hashedSecret = crypto.createHash("sha256").update(clientSecret).digest("base64url");
  const postSecret = "post-secret-67890";
  const postSecretHash = crypto.createHash("sha256").update(postSecret).digest("base64url");
  const basicAuth = Buffer.from(`${privClientId}:${clientSecret}`).toString("base64");

  let testUserId = "";
  let validJwtToken = "";
  let ipCounter = 700;

  function getHeaders(extra: Record<string, string> = {}): Record<string, string> {
    const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
    return { host: "localhost:3000", origin: "http://localhost:5174", "x-forwarded-for": `${ip}, 10.0.0.1`, "x-gateway-secret": "g".repeat(32), ...extra };
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("intro_ctrl_fail");
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
    authModule = await import("../../src/utils/auth");
    originalHandler = authModule.authProvider.handler;
    app = (await import("../../src/app")).default;
    client = suite.client;
    db = client.db(suite.dbName);
    setTestDbOverride(db);

    await db.collection("jwks").insertOne({ id: kid, kid, alg: "RS256", publicKey: JSON.stringify(pubJwk), privateKey: JSON.stringify(enc), createdAt: new Date() });
    await db.collection("oauthClient").insertMany([
      { clientId: privClientId, clientSecret: hashedSecret, name: "Private Ctrl App", clientType: "confidential", accessPolicy: "private", isPublic: false, redirectUris: ["https://priv.example.com/cb"], tokenEndpointAuthMethod: "client_secret_basic", createdAt: new Date() },
      { clientId: postClientId, clientSecret: postSecretHash, name: "Post Ctrl App", clientType: "confidential", accessPolicy: "open", isPublic: true, redirectUris: ["https://post.example.com/cb"], tokenEndpointAuthMethod: "client_secret_post", token_endpoint_auth_method: "client_secret_post", createdAt: new Date() },
    ]);

    const userOid = new ObjectId();
    testUserId = userOid.toHexString();
    await db.collection("user").insertOne({ _id: userOid, id: testUserId, email: "ctrl-user@example.com", emailVerified: true, name: "Ctrl User", role: "user", createdAt: new Date(), updatedAt: new Date() });
    await db.collection("user_app_registrations").insertOne({ userId: testUserId, clientId: privClientId, registeredAt: new Date() });

    validJwtToken = await new SignJWT({ sub: testUserId, client_id: privClientId, aud: privClientId, scope: "openid profile email", token_version: 1 })
      .setProtectedHeader({ alg: "RS256", kid }).setIssuer("http://localhost:3000").setIssuedAt().setExpirationTime("1h").sign(privateKey);
    await db.collection("oauthAccessToken").insertOne({ token: validJwtToken, clientId: privClientId, userId: testUserId, createdAt: new Date(), expiresAt: new Date(Date.now() + 3600000) });
  });

  after(async () => {
    if (authModule && originalHandler) authModule.authProvider.handler = originalHandler;
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  afterEach(() => {
    if (authModule && originalHandler) authModule.authProvider.handler = originalHandler;
  });

  // --- CONTROLLED ENGINE RESPONSES ---

  it("Introspection preserves engine HTTP 403 response and headers, never active:true", async () => {
    authModule.authProvider.handler = async () => {
      return new Response(JSON.stringify({ error: "forbidden", error_description: "Access forbidden" }), {
        status: 403,
        headers: { "Content-Type": "application/json", "X-Custom-Denial": "policy-denied" },
      });
    };

    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }),
      body: `token=${validJwtToken}`,
    });

    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-custom-denial"), "policy-denied");
    const body = await res.json();
    assert.notEqual(body.active, true);
    assert.equal(body.error, "forbidden");
  });

  it("Introspection preserves engine HTTP 429 rate limit response and Retry-After header, never active:true", async () => {
    authModule.authProvider.handler = async () => {
      return new Response(JSON.stringify({ error: "slow_down", error_description: "Rate limit exceeded" }), {
        status: 429,
        headers: { "Content-Type": "application/json", "Retry-After": "120" },
      });
    };

    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }),
      body: `token=${validJwtToken}`,
    });

    assert.equal(res.status, 429);
    assert.equal(res.headers.get("retry-after"), "120");
    const body = await res.json();
    assert.notEqual(body.active, true);
  });

  it("Introspection fails closed on engine HTTP 500 error, never active:true", async () => {
    authModule.authProvider.handler = async () => {
      return new Response(JSON.stringify({ error: "server_error", error_description: "Internal database panic" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    };

    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }),
      body: `token=${validJwtToken}`,
    });

    assert.equal(res.status, 500);
    const body = await res.json();
    assert.notEqual(body.active, true);
    assert.equal(body.error, "server_error");
  });

  it("Introspection fails closed (502) on malformed engine HTTP 200 payload lacking active boolean", async () => {
    authModule.authProvider.handler = async () => {
      return new Response(JSON.stringify({ notActive: true, unexpected: "payload" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }),
      body: `token=${validJwtToken}`,
    });

    assert.equal(res.status, 502);
    const body = await res.json();
    assert.notEqual(body.active, true);
    assert.equal(body.error, "server_error");
  });

  it("Introspection fails closed (502) when sentinel probe unexpectedly returns active:true", async () => {
    authModule.authProvider.handler = async () => {
      return new Response(JSON.stringify({ active: true, sub: "anomaly" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }),
      body: `token=${validJwtToken}`,
    });

    assert.equal(res.status, 502);
    const body = await res.json();
    assert.notEqual(body.active, true);
    assert.equal(body.error, "server_error");
  });

  it("Introspection fails closed (503) when engine handler throws unexpected exception", async () => {
    authModule.authProvider.handler = async () => {
      throw new Error("Engine crashed abruptly");
    };

    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }),
      body: `token=${validJwtToken}`,
    });

    assert.equal(res.status, 503);
    const body = await res.json();
    assert.notEqual(body.active, true);
    assert.equal(body.error, "server_error");
  });

  // --- GENUINE ENGINE AUTHENTICATION VERIFICATION ---

  it("Introspection succeeds with genuine engine probe for valid Basic credentials (200 active:true)", async () => {
    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }),
      body: `token=${validJwtToken}`,
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.active, true);
    assert.equal(body.sub, testUserId);
    assert.equal(body.client_id, privClientId);
  });

  it("Introspection rejects with genuine engine for invalid Basic credentials (401)", async () => {
    const badBasic = Buffer.from(`${privClientId}:wrongsecret`).toString("base64");
    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${badBasic}` }),
      body: `token=${validJwtToken}`,
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.notEqual(body.active, true);
    assert.equal(body.error, "invalid_client");
  });

  it("Introspection rejects with genuine engine for invalid body credentials (400)", async () => {
    const res = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: `token=${validJwtToken}&client_id=${postClientId}&client_secret=wrong_post_secret`,
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.notEqual(body.active, true);
    assert.equal(body.error, "invalid_client");
  });
});
