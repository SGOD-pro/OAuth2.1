import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db, ObjectId } from "mongodb";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("Private Token Access and UserInfo Client Binding Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let privateKey: any;
  const kid = "test-key-priv-access";

  const legacyPrivClientId = "test-legacy-priv-app";
  const explicitPrivClientId = "test-explicit-priv-app";
  const openAppClientId = "test-other-open-app";
  const disabledClientId = "test-disabled-priv-app";
  const ambiguousClientId = "test-ambiguous-app";
  const clientSecret = "test-secret-12345";
  const basicAuth = Buffer.from(`${explicitPrivClientId}:${clientSecret}`).toString("base64");
  const legacyBasicAuth = Buffer.from(`${legacyPrivClientId}:${clientSecret}`).toString("base64");

  let memberUserId = "";
  let adminUserId = "";
  let superAdminUserId = "";
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

  async function createToken(sub: string, clientId: string, familyId?: string) {
    const famId = familyId || `fam_${crypto.randomBytes(4).toString("hex")}`;
    const token = await new SignJWT({ sub, client_id: clientId, aud: clientId, scope: "openid profile email", token_version: 1, family_id: famId })
      .setProtectedHeader({ alg: "RS256", kid })
      .setIssuer("http://localhost:3000")
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);

    const refreshToken = `ref_${crypto.randomBytes(16).toString("hex")}`;
    const refHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    await db.collection("oauthAccessToken").insertOne({
      token,
      clientId,
      userId: sub,
      familyId: famId,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
    });

    await db.collection("oauthRefreshToken").insertOne({
      token: refHash,
      clientId,
      userId: sub,
      familyId: famId,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 86400000),
      tokenVersion: 1,
    });

    await db.collection("oauth_token_families").insertOne({
      familyId: famId,
      clientId,
      userId: sub,
      activeTokenHash: refHash,
      status: "active",
      createdAt: new Date(),
      tokenVersion: 1,
    });

    return { token, refreshToken, familyId: famId };
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("priv_token_gaps");
    Object.assign(process.env, {
      NODE_ENV: "test",
      MONGO_URI: suite.uri,
      DB_NAME: suite.dbName,
      BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000",
      FRONTEND_URL: "http://localhost:5174",
      INTERNAL_GATEWAY_SECRET: "g".repeat(32),
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret",
      OPEN_APP_MEMBERSHIP_BYPASS_ENABLED: "true",
    });

    const keypair = await generateKeyPair("RS256", { extractable: true });
    privateKey = keypair.privateKey;
    const pubJwk: any = await exportJWK(keypair.publicKey);
    pubJwk.kid = kid;
    pubJwk.alg = "RS256";
    pubJwk.use = "sig";
    const privJwk: any = await exportJWK(privateKey);
    privJwk.kid = kid;
    privJwk.alg = "RS256";
    privJwk.use = "sig";

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

    const secretHash = crypto.createHash("sha256").update(clientSecret).digest("base64url");
    await db.collection("oauthClient").insertMany([
      { clientId: legacyPrivClientId, isPublic: false, clientSecret: secretHash, redirectUris: ["https://legacy.example.com/cb"], disabled: false, tokenEndpointAuthMethod: "client_secret_basic", createdAt: new Date() },
      { clientId: explicitPrivClientId, clientType: "confidential", accessPolicy: "private", isPublic: false, clientSecret: secretHash, redirectUris: ["https://priv.example.com/cb"], disabled: false, tokenEndpointAuthMethod: "client_secret_basic", createdAt: new Date() },
      { clientId: openAppClientId, clientType: "confidential", accessPolicy: "open", isPublic: true, clientSecret: secretHash, redirectUris: ["https://open.example.com/cb"], disabled: false, tokenEndpointAuthMethod: "client_secret_basic", createdAt: new Date() },
      { clientId: disabledClientId, clientType: "confidential", accessPolicy: "private", isPublic: false, clientSecret: secretHash, redirectUris: ["https://dis.example.com/cb"], disabled: true, tokenEndpointAuthMethod: "client_secret_basic", createdAt: new Date() },
      { clientId: ambiguousClientId, redirectUris: ["https://amb.example.com/cb"], disabled: false, tokenEndpointAuthMethod: "client_secret_basic", createdAt: new Date() },
    ]);

    memberUserId = new ObjectId().toString();
    await db.collection("user").insertOne({ _id: new ObjectId(memberUserId), id: memberUserId, email: `m-${Date.now()}@example.com`, name: "M", role: "user", emailVerified: true, createdAt: new Date() });
    adminUserId = new ObjectId().toString();
    await db.collection("user").insertOne({ _id: new ObjectId(adminUserId), id: adminUserId, email: `a-${Date.now()}@example.com`, name: "A", role: "user", emailVerified: true, createdAt: new Date() });
    superAdminUserId = new ObjectId().toString();
    await db.collection("user").insertOne({ _id: new ObjectId(superAdminUserId), id: superAdminUserId, email: `s-${Date.now()}@example.com`, name: "S", role: "super-admin", emailVerified: true, createdAt: new Date() });
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("denies access on compatible legacy private client when assignment is deleted", async () => {
    await db.collection("user_app_registrations").insertOne({ userId: memberUserId, clientId: legacyPrivClientId, status: "active", isActive: true, registeredAt: new Date() });
    const { token, refreshToken, familyId } = await createToken(memberUserId, legacyPrivClientId);

    const uInit = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getTestHeaders({ authorization: `Bearer ${token}` }) });
    assert.equal(uInit.status, 200);

    const iInit = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${legacyBasicAuth}` }), body: new URLSearchParams({ token }).toString() });
    assert.equal(iInit.status, 200);
    assert.equal((await iInit.json()).active, true);

    await db.collection("user_app_registrations").deleteOne({ userId: memberUserId, clientId: legacyPrivClientId });

    const uDel = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getTestHeaders({ authorization: `Bearer ${token}` }) });
    assert.equal(uDel.status, 403, "UserInfo must return 403 on deleted legacy assignment before refresh");

    const iDel = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${legacyBasicAuth}` }), body: new URLSearchParams({ token }).toString() });
    assert.equal(iDel.status, 200);
    assert.equal((await iDel.json()).active, false, "Introspection must return active: false on deleted legacy assignment before refresh");

    const fam = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(fam?.status, "active", "Token family must still be unrevoked before refresh attempt");

    const refRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${legacyBasicAuth}` }),
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: legacyPrivClientId }).toString(),
    });
    assert.equal(refRes.status, 401, "Refresh must fail with 401 on deleted assignment");
    const famAfter = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(famAfter?.status, "revoked", "Family must be revoked after denied refresh");
  });

  it("denies access on explicit private client when assignment is explicitly revoked", async () => {
    await db.collection("user_app_registrations").insertOne({ userId: memberUserId, clientId: explicitPrivClientId, status: "active", isActive: true, registeredAt: new Date() });
    const { token, refreshToken, familyId } = await createToken(memberUserId, explicitPrivClientId);

    const uInit = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getTestHeaders({ authorization: `Bearer ${token}` }) });
    assert.equal(uInit.status, 200);

    await db.collection("user_app_registrations").updateOne(
      { userId: memberUserId, clientId: explicitPrivClientId },
      { $set: { status: "revoked", isActive: false, revokedAt: new Date() } }
    );

    const uRev = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getTestHeaders({ authorization: `Bearer ${token}` }) });
    assert.equal(uRev.status, 403, "UserInfo must return 403 on explicitly revoked assignment");

    const iRev = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }), body: new URLSearchParams({ token }).toString() });
    assert.equal((await iRev.json()).active, false, "Introspection must return active false on revoked assignment");

    const famBefore = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(famBefore?.status, "active", "Family must remain active before refresh attempt");

    const refRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }),
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: explicitPrivClientId }).toString(),
    });
    assert.equal(refRes.status, 401, "Refresh must fail with 401 on revoked assignment");
    const famAfter = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(famAfter?.status, "revoked", "Family must be revoked after denied refresh");
    await db.collection("user_app_registrations").deleteOne({ userId: memberUserId, clientId: explicitPrivClientId });
  });

  it("prevents query client_id substitution from overriding token client context in UserInfo", async () => {
    await db.collection("user_app_registrations").insertOne({ userId: memberUserId, clientId: explicitPrivClientId, status: "active", isActive: true, registeredAt: new Date() });
    const { token } = await createToken(memberUserId, explicitPrivClientId);

    const subRes = await app.request(`/api/auth/oauth2/userinfo?client_id=${openAppClientId}`, { method: "GET", headers: getTestHeaders({ authorization: `Bearer ${token}` }) });
    assert.notEqual(subRes.status, 200, "Query client_id substitution must not succeed");

    const validRes = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getTestHeaders({ authorization: `Bearer ${token}` }) });
    assert.equal(validRes.status, 200);
    assert.equal((await validRes.json()).sub, memberUserId);
  });

  it("fails closed when target client is missing, disabled, or ambiguous", async () => {
    const miss = await createToken(memberUserId, "non-existent-client");
    const dis = await createToken(memberUserId, disabledClientId);
    const amb = await createToken(memberUserId, ambiguousClientId);

    for (const [name, tObj, cid] of [["missing", miss, "non-existent-client"], ["disabled", dis, disabledClientId], ["ambiguous", amb, ambiguousClientId]]) {
      const uRes = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getTestHeaders({ authorization: `Bearer ${tObj.token}` }) });
      assert.ok(uRes.status === 401 || uRes.status === 403, `UserInfo must fail closed for ${name}`);

      const bAuth = Buffer.from(`${cid}:${clientSecret}`).toString("base64");
      const iRes = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${bAuth}` }), body: new URLSearchParams({ token: tObj.token }).toString() });
      assert.equal(iRes.status === 200 ? (await iRes.json()).active : false, false, `Introspection must return active false for ${name}`);
    }
  });

  it("authorizes app-admin-only assignment and denies when assignment is removed before refresh", async () => {
    await db.collection("app_admins").insertOne({ userId: adminUserId, clientId: explicitPrivClientId, role: "admin", status: "active", isActive: true, assignedAt: new Date() });
    const { token, refreshToken, familyId } = await createToken(adminUserId, explicitPrivClientId);

    const uInit = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getTestHeaders({ authorization: `Bearer ${token}` }) });
    assert.equal(uInit.status, 200);
    assert.equal((await uInit.json()).role, "admin");

    const iInit = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }), body: new URLSearchParams({ token }).toString() });
    assert.equal((await iInit.json()).active, true);

    await db.collection("app_admins").deleteOne({ userId: adminUserId, clientId: explicitPrivClientId });

    const uDel = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getTestHeaders({ authorization: `Bearer ${token}` }) });
    assert.equal(uDel.status, 403, "UserInfo must return 403 when app admin assignment is removed");

    const iDel = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }), body: new URLSearchParams({ token }).toString() });
    assert.equal((await iDel.json()).active, false, "Introspection must return active: false when app admin assignment removed");

    const fam = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(fam?.status, "active", "Token family must still be unrevoked before refresh attempt");

    const refRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }),
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: explicitPrivClientId }).toString(),
    });
    assert.equal(refRes.status, 401, "Refresh must fail with 401 when app admin assignment is removed");
    const famAfter = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(famAfter?.status, "revoked", "Family must be revoked after denied refresh");
  });

  it("strictly excludes super-admin from private app token access even if assignment exists", async () => {
    await db.collection("user_app_registrations").insertOne({ userId: superAdminUserId, clientId: explicitPrivClientId, status: "active", isActive: true, registeredAt: new Date() });
    const { token } = await createToken(superAdminUserId, explicitPrivClientId);

    const uRes = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: getTestHeaders({ authorization: `Bearer ${token}` }) });
    assert.equal(uRes.status, 403, "Super admin must be strictly denied at UserInfo");

    const iRes = await app.request("/api/auth/oauth2/introspect", { method: "POST", headers: getTestHeaders({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }), body: new URLSearchParams({ token }).toString() });
    assert.equal((await iRes.json()).active, false, "Super admin must introspect as active false");
  });
});
