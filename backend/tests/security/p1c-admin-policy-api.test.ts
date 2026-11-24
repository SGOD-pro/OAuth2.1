import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P1c: Admin Client Policy Registration & Editing API Suite", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let authProvider: any;
  let superCookie = "";
  let scopedCookie = "";
  let scopedClientId = "";
  let ipCounter = 500;
  const gatewaySecret = "g".repeat(32);
  const password = "AdminPassword@1234!";

  const getHeaders = (extra: Record<string, string> = {}) => ({
    "Content-Type": "application/json",
    "x-gateway-secret": gatewaySecret,
    "x-forwarded-for": `198.51.100.${(++ipCounter % 240) + 1}, 10.0.0.1`,
    Origin: "http://localhost:5174",
    "x-csrf-token": "test-csrf",
    ...extra,
  });

  async function enrollAndLogin(email: string): Promise<string> {
    const { createOTP } = await import("@better-auth/utils/otp");
    const { base32 } = await import("@better-auth/utils/base32");
    const r1 = await app.request("/api/auth/sign-in/email", { method: "POST", headers: getHeaders(), body: JSON.stringify({ email, password }) });
    const preCookie = (r1.headers.get("set-cookie") || "").split(";")[0];
    const en = await app.request("/api/auth/two-factor/enable", { method: "POST", headers: getHeaders({ Cookie: preCookie }), body: JSON.stringify({ password }) });
    const b32 = new URL((await en.json()).totpURI).searchParams.get("secret")!;
    const raw = Buffer.from(base32.decode(b32)).toString();
    await app.request("/api/auth/two-factor/verify-totp", { method: "POST", headers: getHeaders({ Cookie: preCookie }), body: JSON.stringify({ code: await createOTP(raw, { digits: 6, period: 30 }).totp() }) });
    const r2 = await app.request("/api/auth/sign-in/email", { method: "POST", headers: getHeaders(), body: JSON.stringify({ email, password }) });
    const challCookie = (r2.headers.get("set-cookie") || "").split(",").find((p: string) => p.trim().startsWith("better-auth.two_factor="))!.trim().split(";")[0];
    const v2 = await app.request("/api/auth/two-factor/verify-totp", { method: "POST", headers: getHeaders({ Cookie: challCookie }), body: JSON.stringify({ code: await createOTP(raw, { digits: 6, period: 30 }).totp() }) });
    return (v2.headers.get("set-cookie") || "").split(",").find((p: string) => p.trim().startsWith("better-auth.session_token="))!.trim().split(";")[0];
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p1c_admin_api");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName, BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000", FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret, TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
    });

    const mongoModule = await import("../../src/db/mongo");
    closeDb = mongoModule.closeDb;
    setTestDbOverride = mongoModule.setTestDbOverride;
    authProvider = (await import("../../src/utils/auth")).authProvider;
    app = (await import("../../src/app")).default;
    client = suite.client;
    db = client.db(suite.dbName);
    setTestDbOverride(db);

    const superEmail = `super_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await authProvider.api.signUpEmail({ body: { email: superEmail, password, name: "Super Admin" } });
    await db.collection("user").updateOne({ email: superEmail }, { $set: { role: "super-admin", scopedClientId: null } });
    superCookie = await enrollAndLogin(superEmail);

    scopedClientId = `scoped-target-${crypto.randomBytes(4).toString("hex")}`;
    await db.collection("oauthClient").insertOne({
      id: scopedClientId, clientId: scopedClientId,
      clientSecret: crypto.createHash("sha256").update("init-secret-123").digest("base64url"),
      name: "Scoped App", redirectUris: ["https://scoped.example.com/cb"], allowedOrigins: ["https://scoped.example.com"],
      clientType: "confidential", accessPolicy: "private", isPublic: false, isDev: false, tokenEndpointAuthMethod: "client_secret_basic", createdAt: new Date(),
    });
    const appAdminEmail = `appadmin_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const createdAppAdmin = await authProvider.api.signUpEmail({ body: { email: appAdminEmail, password, name: "App Admin" } });
    await db.collection("user").updateOne({ email: appAdminEmail }, { $set: { role: "app-admin", scopedClientId } });
    await db.collection("app_admins").insertOne({ userId: String(createdAppAdmin.user.id), clientId: scopedClientId, email: appAdminEmail, isActive: true, createdAt: new Date() });
    scopedCookie = await enrollAndLogin(appAdminEmail);
  });

  after(async () => {
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("defaults registration to Confidential, Private, Production and omits secret hash in GET list", async () => {
    const createRes = await app.request("/api/admin/clients", {
      method: "POST", headers: getHeaders({ Cookie: superCookie }),
      body: JSON.stringify({ name: "Default Policy App", redirect_uris: ["https://default.example.com/cb"] }),
    });
    assert.equal(createRes.status, 201);
    const created = await createRes.json();
    assert.equal(created.clientType, "confidential");
    assert.equal(created.accessPolicy, "private");
    assert.equal(created.isDev, false);
    assert.equal(created.classification, "MIGRATED");
    assert.ok(created.client_secret);

    const listRes = await app.request("/api/admin/clients", { method: "GET", headers: getHeaders({ Cookie: superCookie }) });
    assert.equal(listRes.status, 200);
    const found = (await listRes.json()).find((c: any) => c.client_id === created.client_id);
    assert.ok(found);
    assert.equal(found.clientSecret, undefined);
    assert.equal(found.client_secret, undefined);
    assert.equal(found.hasClientSecret, true);
    assert.equal(found.classification, "MIGRATED");
  });

  it("creates all four combinations cleanly including Confidential Development without ambiguity", async () => {
    const combos = [
      { name: "C-Open-Pub", clientType: "public", accessPolicy: "open", isDev: false, uri: "https://a.example.com/cb", expectSecret: false },
      { name: "C-Priv-Conf", clientType: "confidential", accessPolicy: "private", isDev: false, uri: "https://b.example.com/cb", expectSecret: true },
      { name: "C-Open-Conf", clientType: "confidential", accessPolicy: "open", isDev: true, uri: "http://127.0.0.1:4100/cb", expectSecret: true },
      { name: "C-Priv-Pub", clientType: "public", accessPolicy: "private", isDev: true, uri: "http://localhost:4200/cb", expectSecret: false },
    ] as const;

    for (const c of combos) {
      const res = await app.request("/api/admin/clients", {
        method: "POST", headers: getHeaders({ Cookie: superCookie }),
        body: JSON.stringify({ name: c.name, clientType: c.clientType, accessPolicy: c.accessPolicy, isDev: c.isDev, redirect_uris: [c.uri] }),
      });
      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.clientType, c.clientType);
      assert.equal(body.accessPolicy, c.accessPolicy);
      assert.equal(body.isDev, c.isDev);
      assert.equal(body.classification, "MIGRATED");
      if (c.expectSecret) {
        assert.ok(body.client_secret);
      } else {
        assert.equal(body.client_secret, undefined);
        const dbDoc = await db.collection("oauthClient").findOne({ clientId: body.client_id });
        assert.equal(dbDoc?.clientSecret, undefined);
        assert.equal(dbDoc?.tokenEndpointAuthMethod, "none");
      }
    }
  });

  it("handles Confidential -> Public and Public -> Confidential credential transitions cleanly", async () => {
    const createRes = await app.request("/api/admin/clients", {
      method: "POST", headers: getHeaders({ Cookie: superCookie }),
      body: JSON.stringify({ name: "Transition App", clientType: "confidential", accessPolicy: "private", isDev: false, redirect_uris: ["https://trans.example.com/cb"] }),
    });
    const cid = (await createRes.json()).client_id;

    const toPubRes = await app.request(`/api/admin/clients/${cid}`, {
      method: "PATCH", headers: getHeaders({ Cookie: superCookie }),
      body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: false }),
    });
    assert.equal(toPubRes.status, 200);
    const toPub = await toPubRes.json();
    assert.equal(toPub.clientType, "public");
    assert.equal(toPub.classification, "MIGRATED");
    assert.equal(toPub.client_secret, undefined);
    const pubDoc = await db.collection("oauthClient").findOne({ clientId: cid });
    assert.equal(pubDoc?.clientSecret, undefined);
    assert.equal(pubDoc?.tokenEndpointAuthMethod, "none");

    const toConfRes = await app.request(`/api/admin/clients/${cid}`, {
      method: "PATCH", headers: getHeaders({ Cookie: superCookie }),
      body: JSON.stringify({ clientType: "confidential", accessPolicy: "private", isDev: false }),
    });
    assert.equal(toConfRes.status, 200);
    const toConf = await toConfRes.json();
    assert.equal(toConf.clientType, "confidential");
    assert.ok(toConf.client_secret);

    const creds = Buffer.from(`${cid}:${toConf.client_secret}`).toString("base64");
    const introRes = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${creds}`, "x-gateway-secret": gatewaySecret, "x-forwarded-for": "198.51.100.99, 10.0.0.1" },
      body: "token=probe_sentinel_token",
    });
    assert.equal(introRes.status, 200);
  });

  it("blocks ambiguous client migration until validation passes", async () => {
    const ambigId = `ambig-${crypto.randomBytes(4).toString("hex")}`;
    await db.collection("oauthClient").insertOne({ id: ambigId, clientId: ambigId, name: "Ambiguous Legacy", redirectUris: ["https://ambig.example.com/cb#bad"], createdAt: new Date() });

    const badPatch = await app.request(`/api/admin/clients/${ambigId}`, {
      method: "PATCH", headers: getHeaders({ Cookie: superCookie }),
      body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: false }),
    });
    assert.equal(badPatch.status, 400);

    const goodPatch = await app.request(`/api/admin/clients/${ambigId}`, {
      method: "PATCH", headers: getHeaders({ Cookie: superCookie }),
      body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: false, redirect_uris: ["https://ambig.example.com/cb"] }),
    });
    assert.equal(goodPatch.status, 200);
    const body = await goodPatch.json();
    assert.equal(body.classification, "MIGRATED");
    assert.equal(body.isAmbiguous, false);
  });

  it("BAC-P1C-06 API: rejects scoped App Admin sending policy fields with 403 and preserves stored policy", async () => {
    const patchRes = await app.request(`/api/admin/clients/${scopedClientId}`, {
      method: "PATCH", headers: getHeaders({ Cookie: scopedCookie }),
      body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: true }),
    });
    assert.equal(patchRes.status, 403);
    assert.equal((await patchRes.json()).error, "forbidden");

    const appConfigPatch = await app.request(`/api/admin/app/${scopedClientId}/config`, {
      method: "PATCH", headers: getHeaders({ Cookie: scopedCookie }),
      body: JSON.stringify({ clientType: "public", accessPolicy: "open" }),
    });
    assert.equal(appConfigPatch.status, 403);

    const dbDoc = await db.collection("oauthClient").findOne({ clientId: scopedClientId });
    assert.equal(dbDoc?.clientType, "confidential");
    assert.equal(dbDoc?.accessPolicy, "private");
    assert.equal(dbDoc?.isDev, false);
  });
});
