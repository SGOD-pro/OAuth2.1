import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("Client Secret Post Engine Authentication Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;

  const postClientId = "test-conf-post-app";
  const postSecret = "post-secret-value-12345";
  const postSecretHash = crypto.createHash("sha256").update(postSecret).digest("base64url");
  const postRedirectUri = "https://post.example.com/callback";

  let userSession = "";
  let ipCounter = 800;

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

  function exchange(params: Record<string, string>, extraHeaders: Record<string, string> = {}) {
    return app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", ...extraHeaders }),
      body: new URLSearchParams(params).toString(),
    });
  }

  async function authorizeCode(state: string, pkce: { verifier: string; challenge: string }, scope = "openid profile email") {
    const authUrl = `/api/auth/oauth2/authorize?client_id=${postClientId}&response_type=code&redirect_uri=${encodeURIComponent(postRedirectUri)}&scope=${encodeURIComponent(scope)}&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=${state}`;
    const res = await app.request(authUrl, { method: "GET", headers: getTestHeaders({ cookie: userSession }) });
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location")!);
    const code = loc.searchParams.get("code")!;
    assert.ok(code);
    return code;
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("repro_post_auth");
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
      clientId: postClientId,
      name: "Repro Post Confidential App",
      clientType: "confidential",
      accessPolicy: "open",
      isPublic: true,
      clientSecret: postSecretHash,
      redirectUris: [postRedirectUri],
      allowedOrigins: ["https://post.example.com"],
      disabled: false,
      skipConsent: true,
      tokenEndpointAuthMethod: "client_secret_post",
      token_endpoint_auth_method: "client_secret_post",
      createdAt: new Date(),
    });

    const userEmail = `post-user-${Date.now()}@example.com`;
    const signupRes = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: { ...getTestHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ email: userEmail, password: "Password12345!Secure", name: "Post User" }),
    });
    const cookieHeader = signupRes.headers.get("set-cookie") || "";
    userSession = cookieHeader.split(";")[0];
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("rejects client_secret_post with bad body secret without consuming code", async () => {
    const pkce = makePkce();
    const code = await authorizeCode("state_post_1", pkce);

    const badTokenRes = await exchange({
      grant_type: "authorization_code",
      client_id: postClientId,
      client_secret: "wrong-post-secret",
      code,
      redirect_uri: postRedirectUri,
      code_verifier: pkce.verifier,
    });

    assert.ok(badTokenRes.status === 400 || badTokenRes.status === 401, `Expected 400 or 401 but got ${badTokenRes.status}`);
    const badBody = await badTokenRes.json();
    assert.equal(badBody.error, "invalid_client");

    const codeDoc = await db.collection("oauthAuthorizationCode").findOne({ code });
    assert.ok(codeDoc, "Authorization code document must still exist");
    assert.equal(codeDoc.status, "pending", "Code must remain pending after rejected client auth");
    assert.equal(codeDoc.consumedAt, undefined, "consumedAt must remain unset");

    // Legitimate client exchanges with valid body secret
    const goodTokenRes = await exchange({
      grant_type: "authorization_code",
      client_id: postClientId,
      client_secret: postSecret,
      code,
      redirect_uri: postRedirectUri,
      code_verifier: pkce.verifier,
    });

    assert.equal(goodTokenRes.status, 200);
    const goodBody = await goodTokenRes.json();
    assert.ok(goodBody.access_token, "Must return access token");
  });

  it("preserves token family when replay request uses invalid credentials", async () => {
    const pkce = makePkce();
    const code = await authorizeCode("state_post_2", pkce, "openid profile email offline_access");

    // Legitimate initial exchange
    const tokenRes = await exchange({
      grant_type: "authorization_code",
      client_id: postClientId,
      client_secret: postSecret,
      code,
      redirect_uri: postRedirectUri,
      code_verifier: pkce.verifier,
    });
    assert.equal(tokenRes.status, 200);
    const tokenBody = await tokenRes.json();
    assert.ok(tokenBody.refresh_token, "Must return refresh token with offline_access scope");

    const family = await db.collection("oauth_token_families").findOne({ clientId: postClientId });
    assert.ok(family);
    assert.equal(family.status, "active");

    // Attacker attempts replay with bad credentials
    const replayRes = await exchange({
      grant_type: "authorization_code",
      client_id: postClientId,
      client_secret: "wrong-secret-replay",
      code,
      redirect_uri: postRedirectUri,
      code_verifier: pkce.verifier,
    });
    assert.ok(replayRes.status === 400 || replayRes.status === 401, `Expected 400 or 401 but got ${replayRes.status}`);

    // Family must remain active because attacker failed client authentication
    const familyAfter = await db.collection("oauth_token_families").findOne({ familyId: family.familyId });
    assert.ok(familyAfter);
    assert.equal(familyAfter.status, "active", "Family must not be revoked on rejected credentials");
  });
});
