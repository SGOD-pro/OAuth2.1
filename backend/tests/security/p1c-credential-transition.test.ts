import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P1c: Confidential to Public Credential Transition & Commit Guards", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let setTokenBarrierHookForTesting: any;
  let authProvider: any;
  let superCookie = "";
  let userCookie = "";
  let userId = "";
  let ipCounter = 700;
  const gatewaySecret = "g".repeat(32);
  const password = "UserPassword@1234!";

  const hdrs = (extra: Record<string, string> = {}) => ({
    "Content-Type": "application/json",
    "x-gateway-secret": gatewaySecret,
    "x-forwarded-for": `198.51.101.${(++ipCounter % 240) + 1}, 10.0.0.1`,
    Origin: "http://localhost:5174",
    "x-csrf-token": "test-csrf",
    ...extra,
  });

  function makePkce() {
    const verifier = crypto.randomBytes(32).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    return { verifier, challenge };
  }

  async function enrollSuperAdmin(email: string): Promise<string> {
    const { createOTP } = await import("@better-auth/utils/otp");
    const { base32 } = await import("@better-auth/utils/base32");
    const r1 = await app.request("/api/auth/sign-in/email", { method: "POST", headers: hdrs(), body: JSON.stringify({ email, password }) });
    const pre = (r1.headers.get("set-cookie") || "").split(";")[0];
    const en = await app.request("/api/auth/two-factor/enable", { method: "POST", headers: hdrs({ Cookie: pre }), body: JSON.stringify({ password }) });
    const b32 = new URL((await en.json()).totpURI).searchParams.get("secret")!;
    const raw = Buffer.from(base32.decode(b32)).toString();
    await app.request("/api/auth/two-factor/verify-totp", { method: "POST", headers: hdrs({ Cookie: pre }), body: JSON.stringify({ code: await createOTP(raw, { digits: 6, period: 30 }).totp() }) });
    const r2 = await app.request("/api/auth/sign-in/email", { method: "POST", headers: hdrs(), body: JSON.stringify({ email, password }) });
    const chall = (r2.headers.get("set-cookie") || "").split(",").find((p: string) => p.trim().startsWith("better-auth.two_factor="))!.trim().split(";")[0];
    const v2 = await app.request("/api/auth/two-factor/verify-totp", { method: "POST", headers: hdrs({ Cookie: chall }), body: JSON.stringify({ code: await createOTP(raw, { digits: 6, period: 30 }).totp() }) });
    return (v2.headers.get("set-cookie") || "").split(",").find((p: string) => p.trim().startsWith("better-auth.session_token="))!.trim().split(";")[0];
  }

  async function createConfidentialOpenClient(label: string) {
    const res = await app.request("/api/admin/clients", {
      method: "POST",
      headers: hdrs({ Cookie: superCookie }),
      body: JSON.stringify({ name: label, redirect_uris: ["https://app.example.com/cb"], clientType: "confidential", accessPolicy: "open", isDev: false, skip_consent: true }),
    });
    assert.equal(res.status, 201);
    const body = await res.json();
    return { clientId: body.client_id as string, clientSecret: body.client_secret as string };
  }

  async function authorizeCode(clientId: string) {
    const pkce = makePkce();
    const res = await app.request(
      `/api/auth/oauth2/authorize?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent("https://app.example.com/cb")}&scope=openid%20profile%20email%20offline_access&state=${crypto.randomBytes(8).toString("hex")}&code_challenge=${pkce.challenge}&code_challenge_method=S256`,
      { method: "GET", headers: hdrs({ Cookie: userCookie }) }
    );
    return { res, verifier: pkce.verifier };
  }

  async function exchangeCode(clientId: string, clientSecret: string | null, code: string, verifier: string) {
    const auth = clientSecret ? { Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}` } : {};
    return app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/x-www-form-urlencoded", ...auth }),
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: "https://app.example.com/cb", code_verifier: verifier, ...(!clientSecret ? { client_id: clientId } : {}) }).toString(),
    });
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p1c_cred_transition");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName, BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000", FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret, TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
    });
    const mongoMod = await import("../../src/db/mongo");
    closeDb = mongoMod.closeDb; setTestDbOverride = mongoMod.setTestDbOverride;
    setTokenBarrierHookForTesting = (await import("../../src/routes/auth-keys")).setTokenBarrierHookForTesting;
    authProvider = (await import("../../src/utils/auth")).authProvider;
    app = (await import("../../src/app")).default;
    client = suite.client; db = client.db(suite.dbName); setTestDbOverride(db);

    const superEmail = `super_tr_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await authProvider.api.signUpEmail({ body: { email: superEmail, password, name: "Super Admin" } });
    await db.collection("user").updateOne({ email: superEmail }, { $set: { role: "super-admin", scopedClientId: null } });
    superCookie = await enrollSuperAdmin(superEmail);

    const uEmail = `usr_tr_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const uRes = await authProvider.api.signUpEmail({ body: { email: uEmail, password, name: "Standard User" } });
    userId = String(uRes.user.id);
    const login = await app.request("/api/auth/sign-in/email", { method: "POST", headers: hdrs(), body: JSON.stringify({ email: uEmail, password }) });
    userCookie = (login.headers.get("set-cookie") || "").split(",").find((p: string) => p.trim().startsWith("better-auth.session_token="))!.trim().split(";")[0];
  });

  after(async () => {
    if (setTokenBarrierHookForTesting) setTokenBarrierHookForTesting(null);
    if (setTestDbOverride) setTestDbOverride(null);
    if (closeDb) await closeDb();
    if (suite) await suite.cleanup();
  });

  it("rolls back Confidential -> Public on cleanup failure and completes safely on retry", async () => {
    const { clientId, clientSecret } = await createConfidentialOpenClient("Rollback Retry App");
    const a1 = await authorizeCode(clientId);
    assert.equal(a1.res.status, 302);
    const code1 = new URL(a1.res.headers.get("location")!).searchParams.get("code")!;
    const tok1Res = await exchangeCode(clientId, clientSecret, code1, a1.verifier);
    assert.equal(tok1Res.status, 200);
    const tok1 = await tok1Res.json();

    const a2 = await authorizeCode(clientId);
    assert.equal(a2.res.status, 302);
    const unusedCode = new URL(a2.res.headers.get("location")!).searchParams.get("code")!;

    const origBefore = await db.collection("oauthClient").findOne({ clientId });
    assert.equal(origBefore?.clientType, "confidential");
    assert.ok(origBefore?.clientSecret);

    const failProxyDb = new Proxy(db, {
      get(target, prop) {
        if (prop === "collection") {
          return (name: string) => {
            const col = target.collection(name);
            if (name !== "oauthRefreshToken") return col;
            return new Proxy(col, {
              get(cTarget, cProp) {
                if (cProp === "deleteMany") return async () => { throw new Error("Simulated cleanup write failure"); };
                const v = (cTarget as any)[cProp];
                return typeof v === "function" ? v.bind(cTarget) : v;
              },
            });
          };
        }
        const v = (target as any)[prop];
        return typeof v === "function" ? v.bind(target) : v;
      },
    });

    setTestDbOverride(failProxyDb);
    try {
      const failPatch = await app.request(`/api/admin/clients/${clientId}`, {
        method: "PATCH", headers: hdrs({ Cookie: superCookie }),
        body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: false }),
      });
      assert.equal(failPatch.status, 500);
    } finally {
      setTestDbOverride(db);
    }

    const afterFailDoc = await db.collection("oauthClient").findOne({ clientId });
    assert.equal(afterFailDoc?.clientType, "confidential", "Failed transition must preserve original Confidential policy");
    assert.equal(afterFailDoc?.clientSecret, origBefore?.clientSecret, "Failed transition must preserve original secret hash");
    const uiBeforeRetry = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: hdrs({ Authorization: `Bearer ${tok1.access_token}` }) });
    assert.equal(uiBeforeRetry.status, 200, "Failed transition must keep existing credentials usable until conversion completes");

    const retryPatch = await app.request(`/api/admin/clients/${clientId}`, {
      method: "PATCH", headers: hdrs({ Cookie: superCookie }),
      body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: false }),
    });
    assert.equal(retryPatch.status, 200);
    const retried = await retryPatch.json();
    assert.equal(retried.clientType, "public");

    const afterSuccessDoc = await db.collection("oauthClient").findOne({ clientId });
    assert.equal(afterSuccessDoc?.clientType, "public");
    assert.equal(afterSuccessDoc?.clientSecret, undefined);
    assert.equal(await db.collection("oauthAccessToken").countDocuments({ clientId }), 0);
    assert.equal(await db.collection("oauthRefreshToken").countDocuments({ clientId }), 0);
    assert.equal(await db.collection("oauthAuthorizationCode").countDocuments({ clientId }), 0);
    assert.equal(await db.collection("oauth_token_families").countDocuments({ clientId }), 0);

    const replayCode = await exchangeCode(clientId, null, unusedCode, a2.verifier);
    assert.notEqual(replayCode.status, 200, "Pre-transition code must be unusable after conversion retry");

    const replayRefresh = await app.request("/api/auth/oauth2/token", {
      method: "POST", headers: hdrs({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token: tok1.refresh_token }).toString(),
    });
    assert.notEqual(replayRefresh.status, 200, "Pre-transition refresh token must be unusable after conversion retry");

    const uiOld = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: hdrs({ Authorization: `Bearer ${tok1.access_token}` }) });
    assert.notEqual(uiOld.status, 200, "Pre-transition access token must be rejected at UserInfo");

    const idempRetry = await app.request(`/api/admin/clients/${clientId}`, {
      method: "PATCH", headers: hdrs({ Cookie: superCookie }),
      body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: false }),
    });
    assert.equal(idempRetry.status, 200, "Idempotent retry after completion must remain safe");
  });

  it("aborts in-flight code exchange when Confidential -> Public commits before issuance fence", async () => {
    const { clientId, clientSecret } = await createConfidentialOpenClient("Inflight Code Guard App");
    const a1 = await authorizeCode(clientId);
    assert.equal(a1.res.status, 302);
    const code = new URL(a1.res.headers.get("location")!).searchParams.get("code")!;

    let fired = false;
    setTokenBarrierHookForTesting(async (stage: string, uid?: string) => {
      if (stage === "before_fence_code" && uid === userId) {
        fired = true;
        const p = await app.request(`/api/admin/clients/${clientId}`, {
          method: "PATCH", headers: hdrs({ Cookie: superCookie }),
          body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: false }),
        });
        assert.equal(p.status, 200);
      }
    });
    try {
      const ex = await exchangeCode(clientId, clientSecret, code, a1.verifier);
      assert.equal(fired, true);
      assert.notEqual(ex.status, 200, "In-flight confidential code exchange must fail closed after conversion");
      assert.equal(await db.collection("oauthAccessToken").countDocuments({ clientId }), 0);
      assert.equal(await db.collection("oauthRefreshToken").countDocuments({ clientId }), 0);
      assert.equal(await db.collection("oauth_token_families").countDocuments({ clientId }), 0);
    } finally {
      setTokenBarrierHookForTesting(null);
    }
  });

  it("aborts in-flight refresh rotation when Confidential -> Public commits before issuance fence", async () => {
    const { clientId, clientSecret } = await createConfidentialOpenClient("Inflight Refresh Guard App");
    const a1 = await authorizeCode(clientId);
    assert.equal(a1.res.status, 302);
    const code = new URL(a1.res.headers.get("location")!).searchParams.get("code")!;
    const tokRes = await exchangeCode(clientId, clientSecret, code, a1.verifier);
    assert.equal(tokRes.status, 200);
    const tok = await tokRes.json();

    let fired = false;
    setTokenBarrierHookForTesting(async (stage: string, uid?: string) => {
      if (stage === "before_fence_refresh" && uid === userId) {
        fired = true;
        const p = await app.request(`/api/admin/clients/${clientId}`, {
          method: "PATCH", headers: hdrs({ Cookie: superCookie }),
          body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: false }),
        });
        assert.equal(p.status, 200);
      }
    });
    try {
      const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
      const refRes = await app.request("/api/auth/oauth2/token", {
        method: "POST",
        headers: hdrs({ "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basic}` }),
        body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tok.refresh_token }).toString(),
      });
      assert.equal(fired, true);
      assert.notEqual(refRes.status, 200, "In-flight confidential refresh rotation must fail closed after conversion");
      assert.equal(await db.collection("oauthAccessToken").countDocuments({ clientId }), 0);
      assert.equal(await db.collection("oauthRefreshToken").countDocuments({ clientId }), 0);
      assert.equal(await db.collection("oauth_token_families").countDocuments({ clientId, status: "active" }), 0);
    } finally {
      setTokenBarrierHookForTesting(null);
    }
  });

  it("aborts in-flight /oauth2/authorize code issuance when Confidential -> Public commits mid-flow", async () => {
    const { clientId } = await createConfidentialOpenClient("Inflight Authorize Guard App");
    let fired = false;
    setTokenBarrierHookForTesting(async (stage: string, targetCid?: string) => {
      if (stage === "before_authorize_commit" && targetCid === clientId) {
        fired = true;
        const p = await app.request(`/api/admin/clients/${clientId}`, {
          method: "PATCH", headers: hdrs({ Cookie: superCookie }),
          body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: false }),
        });
        assert.equal(p.status, 200);
      }
    });
    try {
      const a = await authorizeCode(clientId);
      assert.equal(fired, true);
      const loc = a.res.headers.get("location") || "";
      assert.ok(!loc.includes("code="), "In-flight authorize must never return a usable code after credential transition");
      assert.equal(await db.collection("oauthAuthorizationCode").countDocuments({ clientId }), 0);
    } finally {
      setTokenBarrierHookForTesting(null);
    }
  });
});
