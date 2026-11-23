import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { importJWK, jwtVerify } from "jose";
import { MongoMemoryServer } from "mongodb-memory-server";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("OAuth V2 P1b: Client Policy Four Classes HTTP Compatibility Suite", () => {
  let mongod: MongoMemoryServer;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let authProvider: any;
  let assignedSessionCookie = "";
  let unassignedSessionCookie = "";
  let assignedUserId = "";

  const dbName = "p1b_http_compatibility";
  const privConfSecret = "priv_conf_secret_value_12345";
  const openConfSecret = "open_conf_secret_value_12345";
  const privConfHash = crypto.createHash("sha256").update(privConfSecret).digest("base64url");
  const openConfHash = crypto.createHash("sha256").update(openConfSecret).digest("base64url");

  function makePkce() {
    const verifier = crypto.randomBytes(32).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    return { verifier, challenge };
  }

  async function verifyJwt(token: string, expectedClientId: string, expectedUserId: string) {
    const jwksRes = await app.request("/.well-known/jwks.json");
    const { keys } = await jwksRes.json();
    assert.ok(keys && keys.length > 0, "JWKS must contain keys");
    const publicKey = await importJWK(keys[0], "RS256");
    const { payload } = await jwtVerify(token, publicKey, { algorithms: ["RS256"] });
    assert.equal(payload.sub, expectedUserId);
    const tokenClientId = (payload.client_id as string) || (payload.azp as string) || (payload.aud as string);
    assert.equal(tokenClientId, expectedClientId);
  }

  before(async () => {
    isolateTestEnvironment();
    mongod = await MongoMemoryServer.create({ binary: { version: "7.0.24" } });
    const mongoUri = mongod.getUri();

    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: mongoUri, DB_NAME: dbName,
      BETTER_AUTH_SECRET: "b".repeat(32), BETTER_AUTH_URL: "http://localhost:3000",
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

    client = new MongoClient(mongoUri);
    await client.connect();
    db = client.db(dbName);
    setTestDbOverride(db);

    // Seed four clean client classes
    await db.collection("oauthClient").insertMany([
      {
        clientId: "compat-open-pub", name: "Open Public", isPublic: true, is_public: true,
        redirectUris: ["https://pub.example.com/cb"], skipConsent: true,
        type: "public", tokenEndpointAuthMethod: "none", token_endpoint_auth_method: "none",
      },
      {
        clientId: "compat-priv-conf", name: "Private Confidential", isPublic: false,
        clientSecret: privConfHash, redirectUris: ["https://priv-conf.example.com/cb"], skipConsent: true,
        type: "confidential", tokenEndpointAuthMethod: "client_secret_basic", token_endpoint_auth_method: "client_secret_basic",
      },
      {
        clientId: "compat-open-conf", name: "Open Confidential", isPublic: true,
        clientSecret: openConfHash, redirectUris: ["https://open-conf.example.com/cb"], skipConsent: true,
        type: "confidential", tokenEndpointAuthMethod: "client_secret_basic", token_endpoint_auth_method: "client_secret_basic",
      },
      {
        clientId: "compat-priv-pub", name: "Private Public", isPublic: false, application_type: "native",
        redirectUris: ["http://127.0.0.1:8080/cb"], skipConsent: true,
        type: "public", tokenEndpointAuthMethod: "none", token_endpoint_auth_method: "none",
      },
    ]);

    // Create assigned user and sign in
    const userRes = await authProvider.api.signUpEmail({
      body: { email: "assigned@example.com", password: "Password@1234!", name: "Assigned User" },
    });
    assignedUserId = userRes.user.id;
    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: "assigned@example.com", password: "Password@1234!" }),
    });
    const setCookie = loginRes.headers.get("set-cookie") || "";
    const match = setCookie.match(/better-auth\.session_token=([^;]+)/);
    assignedSessionCookie = match ? `better-auth.session_token=${match[1]}` : "";

    // Create unassigned user and sign in
    await authProvider.api.signUpEmail({
      body: { email: "unassigned@example.com", password: "Password@1234!", name: "Unassigned User" },
    });
    const unassignedLogin = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: "unassigned@example.com", password: "Password@1234!" }),
    });
    const unassignedCookieHeader = unassignedLogin.headers.get("set-cookie") || "";
    const unassignedMatch = unassignedCookieHeader.match(/better-auth\.session_token=([^;]+)/);
    unassignedSessionCookie = unassignedMatch ? `better-auth.session_token=${unassignedMatch[1]}` : "";

    // Explicitly provision private membership for assigned user
    await db.collection("user_app_registrations").insertMany([
      { userId: assignedUserId, clientId: "compat-priv-conf", status: "active", createdAt: new Date() },
      { userId: assignedUserId, clientId: "compat-priv-pub", status: "active", createdAt: new Date() },
    ]);
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (client) await client.close();
    if (closeDb) await closeDb();
    if (mongod) await mongod.stop();
  });

  it("verifies Class A: Open Public client code flow and token exchange", async () => {
    const pkce = makePkce();
    const state = "state_open_pub_123";
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=compat-open-pub&redirect_uri=https%3A%2F%2Fpub.example.com%2Fcb&response_type=code&scope=openid+profile+email&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=${state}`,
      { method: "GET", headers: { Cookie: assignedSessionCookie }, redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const location = authRes.headers.get("location") || "";
    const parsed = new URL(location);
    const code = parsed.searchParams.get("code");
    assert.ok(code, "Must receive code in redirect location");
    assert.equal(parsed.searchParams.get("state"), state);

    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", code,
        redirect_uri: "https://pub.example.com/cb", code_verifier: pkce.verifier,
        client_id: "compat-open-pub",
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const tokenData = await tokenRes.json();
    assert.ok(tokenData.access_token, "Must receive access token");
    await verifyJwt(tokenData.access_token, "compat-open-pub", assignedUserId);
  });

  it("verifies Class B: Private Confidential client code flow, membership gate, and token exchange", async () => {
    // Unassigned user is denied
    const unassignedAuth = await app.request(
      "/api/auth/oauth2/authorize?client_id=compat-priv-conf&redirect_uri=https%3A%2F%2Fpriv-conf.example.com%2Fcb&response_type=code&scope=openid+profile+email&state=denied_state",
      { method: "GET", headers: { Cookie: unassignedSessionCookie }, redirect: "manual" }
    );
    assert.equal(unassignedAuth.status, 302);
    const deniedLoc = new URL(unassignedAuth.headers.get("location") || "");
    assert.equal(deniedLoc.searchParams.get("error"), "access_denied");

    // Assigned user is authorized
    const pkce = makePkce();
    const state = "state_priv_conf_123";
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=compat-priv-conf&redirect_uri=https%3A%2F%2Fpriv-conf.example.com%2Fcb&response_type=code&scope=openid+profile+email&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=${state}`,
      { method: "GET", headers: { Cookie: assignedSessionCookie }, redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const location = authRes.headers.get("location") || "";
    const parsed = new URL(location);
    const code = parsed.searchParams.get("code");
    assert.ok(code);

    const basicAuth = Buffer.from(`compat-priv-conf:${privConfSecret}`).toString("base64");
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Authorization": `Basic ${basicAuth}` },
      body: new URLSearchParams({
        grant_type: "authorization_code", code,
        redirect_uri: "https://priv-conf.example.com/cb", code_verifier: pkce.verifier,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const tokenData = await tokenRes.json();
    assert.ok(tokenData.access_token);
    await verifyJwt(tokenData.access_token, "compat-priv-conf", assignedUserId);
  });

  it("verifies Class C: Open Confidential client code flow and token exchange", async () => {
    const pkce = makePkce();
    const state = "state_open_conf_123";
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=compat-open-conf&redirect_uri=https%3A%2F%2Fopen-conf.example.com%2Fcb&response_type=code&scope=openid+profile+email&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=${state}`,
      { method: "GET", headers: { Cookie: assignedSessionCookie }, redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const location = authRes.headers.get("location") || "";
    const parsed = new URL(location);
    const code = parsed.searchParams.get("code");
    assert.ok(code);

    const basicAuth = Buffer.from(`compat-open-conf:${openConfSecret}`).toString("base64");
    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Authorization": `Basic ${basicAuth}` },
      body: new URLSearchParams({
        grant_type: "authorization_code", code,
        redirect_uri: "https://open-conf.example.com/cb", code_verifier: pkce.verifier,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const tokenData = await tokenRes.json();
    assert.ok(tokenData.access_token);
    await verifyJwt(tokenData.access_token, "compat-open-conf", assignedUserId);
  });

  it("verifies Class E: Private Public client code flow, membership gate, and token exchange", async () => {
    // Unassigned user is denied
    const unassignedAuth = await app.request(
      "/api/auth/oauth2/authorize?client_id=compat-priv-pub&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcb&response_type=code&scope=openid+profile+email&state=denied_state_pub",
      { method: "GET", headers: { Cookie: unassignedSessionCookie }, redirect: "manual" }
    );
    assert.equal(unassignedAuth.status, 302);
    const deniedLoc = new URL(unassignedAuth.headers.get("location") || "");
    assert.equal(deniedLoc.searchParams.get("error"), "access_denied");

    // Assigned user is authorized
    const pkce = makePkce();
    const state = "state_priv_pub_123";
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=compat-priv-pub&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcb&response_type=code&scope=openid+profile+email&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=${state}`,
      { method: "GET", headers: { Cookie: assignedSessionCookie }, redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const location = authRes.headers.get("location") || "";
    const parsed = new URL(location);
    const code = parsed.searchParams.get("code");
    assert.ok(code);

    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", code,
        redirect_uri: "http://127.0.0.1:8080/cb", code_verifier: pkce.verifier,
        client_id: "compat-priv-pub",
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const tokenData = await tokenRes.json();
    assert.ok(tokenData.access_token);
    await verifyJwt(tokenData.access_token, "compat-priv-pub", assignedUserId);
  });
});
