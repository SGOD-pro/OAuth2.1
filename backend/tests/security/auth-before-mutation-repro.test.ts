import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("Authenticate Before Code Mutation Regression Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;

  const confClientId = "test-repro-conf-app";
  const confSecret = "conf-secret-value-12345";
  const confSecretHash = crypto.createHash("sha256").update(confSecret).digest("base64url");
  const confRedirectUri = "https://conf.example.com/callback";

  let userSession = "";
  let ipCounter = 900;

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

  function exchange(extraHeaders: Record<string, string>, params: Record<string, string>) {
    return app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", ...extraHeaders }),
      body: new URLSearchParams(params).toString(),
    });
  }

  async function authorizeCode(state: string, pkce: { verifier: string; challenge: string }, scope = "openid profile email") {
    const authUrl = `/api/auth/oauth2/authorize?client_id=${confClientId}&response_type=code&redirect_uri=${encodeURIComponent(confRedirectUri)}&scope=${encodeURIComponent(scope)}&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=${state}`;
    const res = await app.request(authUrl, { method: "GET", headers: getTestHeaders({ cookie: userSession }) });
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location")!);
    const code = loc.searchParams.get("code")!;
    assert.ok(code);
    return code;
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("repro_auth_mutation");
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
      clientId: confClientId,
      name: "Repro Confidential App",
      clientType: "confidential",
      accessPolicy: "open",
      isPublic: true,
      clientSecret: confSecretHash,
      redirectUris: [confRedirectUri],
      allowedOrigins: ["https://conf.example.com"],
      disabled: false,
      skipConsent: true,
      tokenEndpointAuthMethod: "client_secret_basic",
      createdAt: new Date(),
    });

    const userEmail = `repro-user-${Date.now()}@example.com`;
    const signupRes = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: { ...getTestHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ email: userEmail, password: "Password12345!Secure", name: "Repro User" }),
    });
    const cookieHeader = signupRes.headers.get("set-cookie") || "";
    userSession = cookieHeader.split(";")[0];
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("REPRO 1: wrong Basic secret does not consume code and allows legitimate exchange", async () => {
    const pkce = makePkce();
    const code = await authorizeCode("state_repro_1", pkce);

    // 1. Attacker attempts code exchange with WRONG secret
    const badBasic = Buffer.from(`${confClientId}:wrong-attacker-secret`).toString("base64");
    const badTokenRes = await exchange({ authorization: `Basic ${badBasic}` }, {
      grant_type: "authorization_code",
      code,
      redirect_uri: confRedirectUri,
      code_verifier: pkce.verifier,
    });

    assert.equal(badTokenRes.status, 401);
    const badBody = await badTokenRes.json();
    assert.equal(badBody.error, "invalid_client");

    // Code MUST remain pending in database (not consumed, not burned)
    const codeDocAfterBad = await db.collection("oauthAuthorizationCode").findOne({ code });
    assert.ok(codeDocAfterBad, "Code document must still exist");
    assert.equal(codeDocAfterBad.status, "pending", "Code must still be pending after rejected client auth");
    assert.equal(codeDocAfterBad.consumedAt, undefined, "consumedAt must remain unset");

    // 2. Legitimate client exchanges with CORRECT secret
    const goodBasic = Buffer.from(`${confClientId}:${confSecret}`).toString("base64");
    const goodTokenRes = await exchange({ authorization: `Basic ${goodBasic}` }, {
      grant_type: "authorization_code",
      code,
      redirect_uri: confRedirectUri,
      code_verifier: pkce.verifier,
    });

    assert.equal(goodTokenRes.status, 200, "Legitimate exchange must succeed after rejected attempt");
    const goodBody = await goodTokenRes.json();
    assert.ok(goodBody.access_token, "Access token must be returned");
  });

  it("REPRO 2: wrong body client_secret does not consume code and allows legitimate exchange", async () => {
    const pkce = makePkce();
    const code = await authorizeCode("state_repro_2", pkce);

    // 1. Attacker attempts code exchange with wrong body client_secret
    const badTokenRes = await exchange({}, {
      grant_type: "authorization_code",
      client_id: confClientId,
      client_secret: "wrong-body-secret",
      code,
      redirect_uri: confRedirectUri,
      code_verifier: pkce.verifier,
    });

    assert.equal(badTokenRes.status, 401);

    // Code MUST remain pending in database
    const codeDocAfterBad = await db.collection("oauthAuthorizationCode").findOne({ code });
    assert.ok(codeDocAfterBad);
    assert.equal(codeDocAfterBad.status, "pending");
    assert.equal(codeDocAfterBad.consumedAt, undefined);

    // 2. Legitimate client exchanges with correct Basic credentials
    const goodBasic = Buffer.from(`${confClientId}:${confSecret}`).toString("base64");
    const goodTokenRes = await exchange({ authorization: `Basic ${goodBasic}` }, {
      grant_type: "authorization_code",
      code,
      redirect_uri: confRedirectUri,
      code_verifier: pkce.verifier,
    });

    assert.equal(goodTokenRes.status, 200);
    const goodBody = await goodTokenRes.json();
    assert.ok(goodBody.access_token);
  });

  it("REPRO 3: replaying code with wrong credentials does NOT revoke legitimate token family", async () => {
    const pkce = makePkce();
    const code = await authorizeCode("state_repro_3", pkce, "openid profile email offline_access");

    // Initial legitimate exchange
    const goodBasic = Buffer.from(`${confClientId}:${confSecret}`).toString("base64");
    const goodTokenRes = await exchange({ authorization: `Basic ${goodBasic}` }, {
      grant_type: "authorization_code",
      code,
      redirect_uri: confRedirectUri,
      code_verifier: pkce.verifier,
    });

    assert.equal(goodTokenRes.status, 200);
    const goodBody = await goodTokenRes.json();
    assert.ok(goodBody.refresh_token);

    // Find the token family
    const codeDoc = await db.collection("oauthAuthorizationCode").findOne({ code });
    assert.ok(codeDoc?.familyId, "Code document must record familyId");
    const familyId = codeDoc.familyId;

    let familyDoc = await db.collection("oauth_token_families").findOne({ familyId });
    assert.ok(familyDoc);
    assert.equal(familyDoc.status, "active", "Family must be active after exchange");

    // Attacker replays consumed code with WRONG credentials
    const badBasic = Buffer.from(`${confClientId}:attacker-wrong-secret`).toString("base64");
    const replayBadRes = await exchange({ authorization: `Basic ${badBasic}` }, {
      grant_type: "authorization_code",
      code,
      redirect_uri: confRedirectUri,
      code_verifier: pkce.verifier,
    });

    assert.equal(replayBadRes.status, 401);

    // Family MUST STILL BE ACTIVE! Not revoked by unauthenticated attacker!
    familyDoc = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(familyDoc?.status, "active", "Family must remain active when replay request has invalid credentials");

    // Legitimate client replays consumed code with CORRECT credentials
    const replayGoodRes = await exchange({ authorization: `Basic ${goodBasic}` }, {
      grant_type: "authorization_code",
      code,
      redirect_uri: confRedirectUri,
      code_verifier: pkce.verifier,
    });

    assert.equal(replayGoodRes.status, 400);
    const replayBody = await replayGoodRes.json();
    assert.equal(replayBody.error, "invalid_grant");

    // NOW family must be revoked due to legitimate client replay
    familyDoc = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(familyDoc?.status, "revoked", "Family must be revoked after legitimate client replay");
    assert.equal(familyDoc?.revokedReason, "code_replayed");
  });
});
