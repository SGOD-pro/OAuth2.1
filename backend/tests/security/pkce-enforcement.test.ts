import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P1b: PKCE S256 Mandatory Enforcement Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let authProvider: any;

  const pubClientId = "test-pkce-public-app";
  const pubRedirectUri = "https://pub.example.com/callback";

  const confClientId = "test-pkce-conf-app";
  const confSecret = "conf-secret-value-12345";
  const confSecretHash = crypto.createHash("sha256").update(confSecret).digest("base64url");
  const confRedirectUri = "https://conf.example.com/callback";

  const privClientId = "test-pkce-priv-app";
  const privSecret = "priv-secret-value-12345";
  const privSecretHash = crypto.createHash("sha256").update(privSecret).digest("base64url");
  const privRedirectUri = "https://priv.example.com/callback";

  const consentClientId = "test-pkce-consent-app";
  const consentRedirectUri = "https://consent.example.com/callback";

  let assignedUserSession = "";
  let assignedUserId = "";
  let unassignedUserSession = "";
  let superAdminSession = "";

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

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p1b_pkce");
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
    const authModule = await import("../../src/utils/auth");
    authProvider = authModule.authProvider;
    const appModule = await import("../../src/app");
    app = appModule.default;

    client = suite.client;
    db = client.db(dbName);
    setTestDbOverride(db);

    await db.collection("oauthClient").insertMany([
      {
        clientId: pubClientId,
        name: "Public App",
        clientType: "public",
        accessPolicy: "open",
        isPublic: true,
        redirectUris: [pubRedirectUri],
        allowedOrigins: ["https://pub.example.com"],
        disabled: false,
        skipConsent: true,
        tokenEndpointAuthMethod: "none",
        createdAt: new Date(),
      },
      {
        clientId: confClientId,
        name: "Confidential App",
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
      },
      {
        clientId: privClientId,
        name: "Private App",
        clientType: "confidential",
        accessPolicy: "private",
        isPublic: false,
        clientSecret: privSecretHash,
        redirectUris: [privRedirectUri],
        allowedOrigins: ["https://priv.example.com"],
        disabled: false,
        skipConsent: true,
        tokenEndpointAuthMethod: "client_secret_basic",
        createdAt: new Date(),
      },
      {
        clientId: consentClientId,
        name: "Consent App",
        clientType: "public",
        accessPolicy: "open",
        isPublic: true,
        redirectUris: [consentRedirectUri],
        allowedOrigins: ["https://consent.example.com"],
        disabled: false,
        skipConsent: false,
        tokenEndpointAuthMethod: "none",
        createdAt: new Date(),
      },
    ]);

    // Create assigned user
    const suffix = crypto.randomBytes(4).toString("hex");
    const assignedEmail = `pkce-assigned-${suffix}@example.com`;
    const password = "Password@1234!";
    const assignedSignUp = await authProvider.api.signUpEmail({
      body: { email: assignedEmail, password, name: "Assigned User" },
    }).catch((e: any) => { console.error("assignedSignUp error:", e); return null; });
    console.log("assignedSignUp:", assignedSignUp ? assignedSignUp.user?.email : "NULL");
    assignedUserId = assignedSignUp.user.id;

    const assignedLogin = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ email: assignedEmail, password }),
    });
    const assignedToken = (assignedLogin.headers.get("set-cookie") || "").match(/better-auth\.session_token=([^;]+)/);
    assignedUserSession = assignedToken ? `better-auth.session_token=${assignedToken[1]}` : "";

    await db.collection("user_app_registrations").insertOne({
      userId: assignedUserId,
      clientId: privClientId,
      registeredAt: new Date(),
    });

    // Create unassigned user
    const unassignedEmail = `pkce-unassigned-${suffix}@example.com`;
    await authProvider.api.signUpEmail({
      body: { email: unassignedEmail, password, name: "Unassigned User" },
    });
    const unassignedLogin = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ email: unassignedEmail, password }),
    });
    const unassignedToken = (unassignedLogin.headers.get("set-cookie") || "").match(/better-auth\.session_token=([^;]+)/);
    unassignedUserSession = unassignedToken ? `better-auth.session_token=${unassignedToken[1]}` : "";

    // Create super-admin user
    const adminEmail = `pkce-admin-${suffix}@example.com`;
    await authProvider.api.signUpEmail({
      body: { email: adminEmail, password, name: "Super Admin" },
    });
    await db.collection("user").updateOne({ email: adminEmail }, { $set: { role: "super-admin" } });
    const adminLogin = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ email: adminEmail, password }),
    });
    const adminToken = (adminLogin.headers.get("set-cookie") || "").match(/better-auth\.session_token=([^;]+)/);
    superAdminSession = adminToken ? `better-auth.session_token=${adminToken[1]}` : "";
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("completes full S256 code flow and token exchange for Public client", async () => {
    const pkce = makePkce();
    const state = "pub_state_001";
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${pubClientId}&redirect_uri=${encodeURIComponent(pubRedirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=${state}`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const loc = new URL(authRes.headers.get("location") || "");
    const code = loc.searchParams.get("code");
    assert.ok(code, "Must receive authorization code");
    assert.equal(loc.searchParams.get("state"), state);

    // Verify code was bound in oauthAuthorizationCode
    const codeDoc = await db.collection("oauthAuthorizationCode").findOne({ code });
    assert.ok(codeDoc, "Code must be recorded in oauthAuthorizationCode");
    assert.equal(codeDoc.codeChallenge, pkce.challenge);
    assert.equal(codeDoc.codeChallengeMethod, "S256");
    assert.equal(codeDoc.clientId, pubClientId);

    // Exchange code with matching verifier (no secret)
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: pubRedirectUri,
        code_verifier: pkce.verifier,
        client_id: pubClientId,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const data = await tokenRes.json();
    assert.ok(data.access_token, "Must receive access token");
  });

  it("completes full S256 code flow and token exchange for Confidential client with HTTP Basic", async () => {
    const pkce = makePkce();
    const state = "conf_basic_state";
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${confClientId}&redirect_uri=${encodeURIComponent(confRedirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=${state}`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const loc = new URL(authRes.headers.get("location") || "");
    const code = loc.searchParams.get("code");
    assert.ok(code);

    const basicAuth = Buffer.from(`${confClientId}:${confSecret}`).toString("base64");
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: confRedirectUri,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const data = await tokenRes.json();
    assert.ok(data.access_token);
  });

  it("completes full S256 code flow and token exchange for Confidential client with body secret", async () => {
    const pkce = makePkce();
    const state = "conf_body_state";
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${confClientId}&redirect_uri=${encodeURIComponent(confRedirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=${state}`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const loc = new URL(authRes.headers.get("location") || "");
    const code = loc.searchParams.get("code");
    assert.ok(code);

    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: confRedirectUri,
        code_verifier: pkce.verifier,
        client_id: confClientId,
        client_secret: confSecret,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const data = await tokenRes.json();
    assert.ok(data.access_token);
  });

  it("rejects authorize request missing code_challenge with 302 invalid_request", async () => {
    const state = "missing_challenge_state";
    const res = await app.request(
      `/api/auth/oauth2/authorize?client_id=${pubClientId}&redirect_uri=${encodeURIComponent(pubRedirectUri)}&response_type=code&state=${state}`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location") || "");
    assert.equal(loc.searchParams.get("error"), "invalid_request");
    assert.equal(loc.searchParams.get("state"), state);
    assert.ok(loc.searchParams.get("error_description")?.includes("code_challenge is required"));
  });

  it("rejects confidential client authorize missing code_challenge with 302 invalid_request", async () => {
    const state = "conf_missing_challenge";
    const res = await app.request(
      `/api/auth/oauth2/authorize?client_id=${confClientId}&redirect_uri=${encodeURIComponent(confRedirectUri)}&response_type=code&state=${state}`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location") || "");
    assert.equal(loc.searchParams.get("error"), "invalid_request");
    assert.equal(loc.searchParams.get("state"), state);
  });

  it("rejects code_challenge_method=plain with 302 invalid_request", async () => {
    const state = "plain_method_state";
    const res = await app.request(
      `/api/auth/oauth2/authorize?client_id=${pubClientId}&redirect_uri=${encodeURIComponent(pubRedirectUri)}&response_type=code&code_challenge=1234567890123456789012345678901234567890123&code_challenge_method=plain&state=${state}`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location") || "");
    assert.equal(loc.searchParams.get("error"), "invalid_request");
    assert.ok(loc.searchParams.get("error_description")?.includes("only S256 is supported"));
    assert.equal(loc.searchParams.get("state"), state);
  });

  it("rejects malformed code_challenge syntax with 302 invalid_request", async () => {
    const state = "malformed_syntax_state";
    // Too short (5 characters)
    const resShort = await app.request(
      `/api/auth/oauth2/authorize?client_id=${pubClientId}&redirect_uri=${encodeURIComponent(pubRedirectUri)}&response_type=code&code_challenge=short&code_challenge_method=S256&state=${state}`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    assert.equal(resShort.status, 302);
    const locShort = new URL(resShort.headers.get("location") || "");
    assert.equal(locShort.searchParams.get("error"), "invalid_request");
    assert.ok(locShort.searchParams.get("error_description")?.includes("syntax"));

    // Invalid characters (spaces and symbols)
    const resInvalidChars = await app.request(
      `/api/auth/oauth2/authorize?client_id=${pubClientId}&redirect_uri=${encodeURIComponent(pubRedirectUri)}&response_type=code&code_challenge=invalid!@#$%^&*()_+~<>?:{}|12345678901234567&code_challenge_method=S256&state=${state}`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    assert.equal(resInvalidChars.status, 302);
    const locChars = new URL(resInvalidChars.headers.get("location") || "");
    assert.equal(locChars.searchParams.get("error"), "invalid_request");
  });

  it("rejects code exchange missing code_verifier with HTTP 400 invalid_request", async () => {
    const pkce = makePkce();
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${pubClientId}&redirect_uri=${encodeURIComponent(pubRedirectUri)}&response_type=code&scope=openid&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=mv_state`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    const loc = new URL(authRes.headers.get("location") || "");
    const code = loc.searchParams.get("code");

    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: pubRedirectUri,
        client_id: pubClientId,
      }).toString(),
    });
    assert.equal(tokenRes.status, 400);
    const body = await tokenRes.json();
    assert.equal(body.error, "invalid_request");
    assert.ok(body.error_description.includes("code_verifier is required"));
  });

  it("rejects confidential client code exchange missing code_verifier with HTTP 400 invalid_request", async () => {
    const pkce = makePkce();
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${confClientId}&redirect_uri=${encodeURIComponent(confRedirectUri)}&response_type=code&scope=openid&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=conf_mv_state`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    const loc = new URL(authRes.headers.get("location") || "");
    const code = loc.searchParams.get("code");

    const basicAuth = Buffer.from(`${confClientId}:${confSecret}`).toString("base64");
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: confRedirectUri,
      }).toString(),
    });
    assert.equal(tokenRes.status, 400);
    const body = await tokenRes.json();
    assert.equal(body.error, "invalid_request");
    assert.ok(body.error_description.includes("code_verifier is required"));
  });

  it("rejects malformed code_verifier syntax at token exchange", async () => {
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "any-code",
        redirect_uri: pubRedirectUri,
        code_verifier: "too-short",
        client_id: pubClientId,
      }).toString(),
    });
    assert.equal(tokenRes.status, 400);
    const body = await tokenRes.json();
    assert.equal(body.error, "invalid_request");
    assert.ok(body.error_description.includes("syntax"));
  });

  it("rejects wrong code_verifier with HTTP 400 invalid_grant", async () => {
    const pkce = makePkce();
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${pubClientId}&redirect_uri=${encodeURIComponent(pubRedirectUri)}&response_type=code&scope=openid&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=wv_state`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    const loc = new URL(authRes.headers.get("location") || "");
    const code = loc.searchParams.get("code");

    const wrongVerifier = crypto.randomBytes(32).toString("base64url");
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: pubRedirectUri,
        code_verifier: wrongVerifier,
        client_id: pubClientId,
      }).toString(),
    });
    assert.equal(tokenRes.status, 400);
    const body = await tokenRes.json();
    assert.equal(body.error, "invalid_grant");
    assert.ok(body.error_description.includes("Invalid code_verifier"));
  });

  it("rejects code replay and revokes token family on reused authorization code", async () => {
    const pkce = makePkce();
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${pubClientId}&redirect_uri=${encodeURIComponent(pubRedirectUri)}&response_type=code&scope=openid+profile+email+offline_access&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=replay_state`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    const loc = new URL(authRes.headers.get("location") || "");
    const code = loc.searchParams.get("code")!;

    // First exchange succeeds
    const firstRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: pubRedirectUri,
        code_verifier: pkce.verifier,
        client_id: pubClientId,
      }).toString(),
    });
    assert.equal(firstRes.status, 200);
    const firstData = await firstRes.json();
    assert.ok(firstData.access_token);

    // Replay exchange with same code
    const replayRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: pubRedirectUri,
        code_verifier: pkce.verifier,
        client_id: pubClientId,
      }).toString(),
    });
    assert.equal(replayRes.status, 400);
    const replayBody = await replayRes.json();
    assert.equal(replayBody.error, "invalid_grant");
    assert.ok(replayBody.error_description.includes("already been consumed"));

    // Verify token family was revoked
    const codeDoc = await db.collection("oauthAuthorizationCode").findOne({ code });
    if (codeDoc?.familyId) {
      const familyDoc = await db.collection("oauth_token_families").findOne({ familyId: codeDoc.familyId });
      assert.equal(familyDoc?.status, "revoked", "Replayed code must cascade-revoke token family");
    }
  });

  it("rejects cross-client substitution: Client B cannot exchange Client A code", async () => {
    const pkce = makePkce();
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${pubClientId}&redirect_uri=${encodeURIComponent(pubRedirectUri)}&response_type=code&scope=openid&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=xclient_state`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    const loc = new URL(authRes.headers.get("location") || "");
    const code = loc.searchParams.get("code")!;

    // Conf client attempts to exchange Public client's code
    const basicAuth = Buffer.from(`${confClientId}:${confSecret}`).toString("base64");
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: pubRedirectUri,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    assert.equal(tokenRes.status, 400);
    const body = await tokenRes.json();
    assert.equal(body.error, "invalid_grant");
  });

  it("rejects redirect_uri mismatch at code exchange", async () => {
    const pkce = makePkce();
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${pubClientId}&redirect_uri=${encodeURIComponent(pubRedirectUri)}&response_type=code&scope=openid&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=mismatch_state`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    const loc = new URL(authRes.headers.get("location") || "");
    const code = loc.searchParams.get("code")!;

    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://pub.example.com/other-callback",
        code_verifier: pkce.verifier,
        client_id: pubClientId,
      }).toString(),
    });
    assert.equal(tokenRes.status, 400);
    const body = await tokenRes.json();
    assert.equal(body.error, "invalid_grant");
  });

  it("rejects public client supplying client credentials with HTTP 400 invalid_client", async () => {
    const pkce = makePkce();
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "dummy-code",
        redirect_uri: pubRedirectUri,
        code_verifier: pkce.verifier,
        client_id: pubClientId,
        client_secret: "unauthorized-secret",
      }).toString(),
    });
    assert.equal(tokenRes.status, 400);
    const body = await tokenRes.json();
    assert.equal(body.error, "invalid_client");
    assert.ok(body.error_description.includes("Public clients must not supply client credentials"));
  });

  it("rejects confidential client missing credentials with HTTP 401 invalid_client", async () => {
    const pkce = makePkce();
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "dummy-code",
        redirect_uri: confRedirectUri,
        code_verifier: pkce.verifier,
        client_id: confClientId,
      }).toString(),
    });
    assert.equal(tokenRes.status, 401);
    const body = await tokenRes.json();
    assert.equal(body.error, "invalid_client");
    assert.ok(body.error_description.includes("Confidential clients must authenticate"));
  });

  it("enforces private app membership: unassigned user denied at authorize despite valid PKCE", async () => {
    const pkce = makePkce();
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${privClientId}&redirect_uri=${encodeURIComponent(privRedirectUri)}&response_type=code&scope=openid&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=unassigned_state`,
      { method: "GET", headers: getTestHeaders({ Cookie: unassignedUserSession }), redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const loc = new URL(authRes.headers.get("location") || "");
    assert.equal(loc.searchParams.get("error"), "access_denied");
  });

  it("enforces private app membership: super-admin unconditionally denied despite valid PKCE", async () => {
    const pkce = makePkce();
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${privClientId}&redirect_uri=${encodeURIComponent(privRedirectUri)}&response_type=code&scope=openid&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=admin_denied_state`,
      { method: "GET", headers: getTestHeaders({ Cookie: superAdminSession }), redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const loc = new URL(authRes.headers.get("location") || "");
    assert.equal(loc.searchParams.get("error"), "access_denied");
  });

  it("preserves PKCE challenge binding through consent acceptance", async () => {
    const pkce = makePkce();
    const state = "consent_pkce_state";
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${consentClientId}&redirect_uri=${encodeURIComponent(consentRedirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=${state}`,
      { method: "GET", headers: getTestHeaders({ Cookie: assignedUserSession }), redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const consentLocation = authRes.headers.get("location") || "";
    assert.ok(consentLocation.includes("/consent"), "Must redirect to consent page when skipConsent is false");

    const consentUrl = new URL(consentLocation, "http://localhost:5174");
    const consentQuery = consentUrl.search.slice(1);
    const authCookies = authRes.headers.get("set-cookie") || "";

    // Accept consent
    const consentRes = await app.request("/api/auth/oauth2/consent", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/json",
        Cookie: `${assignedUserSession}; ${authCookies}`,
      }),
      body: JSON.stringify({
        accept: true,
        oauth_query: consentQuery,
      }),
    });
    if (consentRes.status !== 200 && consentRes.status !== 302) {
      console.log("consentRes status:", consentRes.status, await consentRes.text());
    }
    assert.ok(consentRes.status === 200 || consentRes.status === 302);
    let targetUrl = consentRes.headers.get("location");
    if (!targetUrl && consentRes.status === 200) {
      const consentData = await consentRes.json();
      targetUrl = consentData.redirect_uri || consentData.url;
    }
    assert.ok(targetUrl, "Consent response must contain target redirect URL");

    const parsedTarget = new URL(targetUrl);
    const code = parsedTarget.searchParams.get("code");
    assert.ok(code, "Consent approval must issue authorization code");
    assert.equal(parsedTarget.searchParams.get("state"), state);

    // Verify code in oauthAuthorizationCode carries pkce.challenge
    const codeDoc = await db.collection("oauthAuthorizationCode").findOne({ code });
    assert.ok(codeDoc, "Code must be bound in oauthAuthorizationCode");
    assert.equal(codeDoc.codeChallenge, pkce.challenge);

    // Exchange code with matching verifier
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: consentRedirectUri,
        code_verifier: pkce.verifier,
        client_id: consentClientId,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const tokenData = await tokenRes.json();
    assert.ok(tokenData.access_token);
  });
});
