import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P2b: Provisioning Bypass Closure in Verified Mode", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let authProvider: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let getTestMailSinkMessages: any;
  let clearTestMailSink: any;
  let ipCounter = 30;
  const gatewaySecret = "g".repeat(32);
  const strongPassword = "Bypass!Guard#Password99";

  const hdrs = (extra: Record<string, string> = {}) => ({
    "Content-Type": "application/json",
    "x-gateway-secret": gatewaySecret,
    "x-forwarded-for": `198.51.111.${(++ipCounter % 240) + 1}, 10.0.0.1`,
    Origin: "http://localhost:5174",
    "x-csrf-token": "test-csrf",
    ...extra,
  });

  function extractCookie(res: Response, name: string): string {
    const raw = res.headers.get("set-cookie") || "";
    for (const part of raw.split(/,(?=[^;]+=)/)) {
      const kv = part.trim().split(";")[0];
      if (kv.startsWith(`${name}=`)) return kv;
    }
    return "";
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p2b_bypasses");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName,
      BETTER_AUTH_SECRET: "a".repeat(32), BETTER_AUTH_URL: "http://localhost:3000",
      FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret,
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      AUTH_PUBLIC_SIGNUP_ENABLED: "true",
      IDENTITY_REGISTRATION_MODE: "disabled",
      IDENTITY_OTP_VERIFIER_KEY_REF: "p2b-otp-key-ref-0000000000000001",
      IDENTITY_LOOKUP_KEY_REF: "p2b-lookup-key-ref-0000000000002",
      IDENTITY_MAIL_PAYLOAD_KEY_REF: "p2b-aead-key-ref-000000000000003",
      IDENTITY_MAIL_WEBHOOK_KEY_REF: "p2b-hook-key-ref-000000000000004",
      IDENTITY_MAIL_TRANSPORT: "test_sink",
    });
    const mongoMod = await import("../../src/db/mongo");
    closeDb = mongoMod.closeDb; setTestDbOverride = mongoMod.setTestDbOverride;
    const mailMod = await import("../../src/identity/mail-service");
    getTestMailSinkMessages = mailMod.getTestMailSinkMessages;
    clearTestMailSink = mailMod.clearTestMailSink;
    authProvider = (await import("../../src/utils/auth")).authProvider;
    app = (await import("../../src/app")).default;
    client = suite.client; db = client.db(suite.dbName); setTestDbOverride(db);
  });

  after(async () => {
    await closeDb();
    await suite.cleanup();
  });

  beforeEach(async () => {
    process.env.IDENTITY_REGISTRATION_MODE = "disabled";
    clearTestMailSink();
    for (const col of await db.listCollections().toArray()) {
      await db.collection(col.name).deleteMany({});
    }
  });

  it("preserves legacy compatibility in disabled mode and blocks /complete", async () => {
    const legacySignup = await app.request("/api/auth/sign-up/email", {
      method: "POST", headers: hdrs(),
      body: JSON.stringify({ email: "legacy@example.com", password: strongPassword, name: "Legacy" }),
    });
    assert.equal(legacySignup.status, 200);

    const p2bBlocked = await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs(),
      body: JSON.stringify({ username: "blocked", password: strongPassword, acceptedTermsVersion: "v1" }),
    });
    assert.equal(p2bBlocked.status, 403);
  });

  it("blocks public signup, direct engine signup/social creation, engine admin create-user, and unverified invitation privilege grants in verified mode while preserving existing sign-in", async () => {
    // Seed existing verified user while disabled (or via verified flow)
    await authProvider.api.signUpEmail({
      body: { email: "existing@example.com", password: strongPassword, name: "Existing" },
    });
    const adminCreated = await authProvider.api.signUpEmail({
      body: { email: "superadmin@example.com", password: strongPassword, name: "Super" },
    });
    const adminLogin = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs(),
      body: JSON.stringify({ email: "superadmin@example.com", password: strongPassword }),
    });
    assert.equal(adminLogin.status, 200);
    const adminSession = extractCookie(adminLogin, "better-auth.session_token");
    assert.ok(adminSession, "Expected super-admin session cookie");
    await db.collection("user").updateOne(
      { email: "superadmin@example.com" },
      { $set: { role: "super-admin", emailVerified: true, twoFactorEnabled: true } }
    );
    await db.collection("session").updateMany({ userId: adminCreated.user.id }, { $set: { mfaVerifiedAt: new Date() } });

    // Switch to verified mode
    process.env.IDENTITY_REGISTRATION_MODE = "verified";

    // 1. Legacy HTTP email signup blocked even with AUTH_PUBLIC_SIGNUP_ENABLED=true
    const rLegacy = await app.request("/api/auth/sign-up/email", {
      method: "POST", headers: hdrs(),
      body: JSON.stringify({ email: "bypass-http@example.com", password: strongPassword, name: "Bypass" }),
    });
    assert.equal(rLegacy.status, 403);
    assert.equal(await db.collection("user").findOne({ email: "bypass-http@example.com" }), null);

    // 2. Direct Better Auth engine email signup blocked by databaseHook
    await assert.rejects(
      authProvider.api.signUpEmail({ body: { email: "bypass-engine@example.com", password: strongPassword, name: "BypassEngine" } })
    );
    assert.equal(await db.collection("user").findOne({ email: "bypass-engine@example.com" }), null);

    // 3. Direct engine admin create-user route blocked
    const rAdminCreate = await app.request("/api/auth/admin/create-user", {
      method: "POST", headers: hdrs({ Cookie: adminSession }),
      body: JSON.stringify({ email: "bypass-admin@example.com", password: strongPassword, name: "AdminBypass", role: "user" }),
    });
    assert.equal(rAdminCreate.status, 403);
    assert.equal(await db.collection("user").findOne({ email: "bypass-admin@example.com" }), null);

    // 4. Simulated social auto-provisioning creating a new unverified identity is blocked
    const ctx = await authProvider.$context;
    await assert.rejects(
      ctx.internalAdapter.createUser({ email: "google-new@example.com", emailVerified: true, name: "Google User" } as any, { method: "social:google" })
    );
    assert.equal(await db.collection("user").findOne({ email: "google-new@example.com" }), null);

    // 5. Invitation acceptance / arbitrary invitationHandle on verified registration cannot escalate or grant private membership
    await db.collection("oauthClient").insertOne({ clientId: "private-app-1", accessPolicy: "private", isPublic: false, disabled: false });
    const startRes = await app.request("/api/identity/registration/start", {
      method: "POST", headers: hdrs({ "Idempotency-Key": `inv-${crypto.randomUUID()}` }),
      body: JSON.stringify({ email: "invitee@example.com", acceptedTermsVersion: "v1", invitationHandle: "forged-admin-invite:private-app-1" }),
    });
    assert.equal(startRes.status, 202);
    const { intentId } = (await startRes.json()) as any;
    const bCookie = extractCookie(startRes, "swyra_reg_browser");
    let msg: any = null;
    for (let i = 0; i < 30 && !msg; i++) {
      msg = getTestMailSinkMessages().find((m: any) => m.to === "invitee@example.com");
      if (!msg) await new Promise((r) => setTimeout(r, 30));
    }
    assert.ok(msg, "Expected OTP delivered for invitee@example.com");
    const code = msg.text.match(/\b(\d{6})\b/)[1];
    const vRes = await app.request("/api/identity/registration/verify", {
      method: "POST", headers: hdrs({ Cookie: bCookie }),
      body: JSON.stringify({ intentId, code }),
    });
    const pCookie = extractCookie(vRes, "swyra_reg_proof");
    const cRes = await app.request("/api/identity/registration/complete", {
      method: "POST", headers: hdrs({ Cookie: `${bCookie}; ${pCookie}` }),
      body: JSON.stringify({ username: "invitee_user", password: strongPassword, acceptedTermsVersion: "v1" }),
    });
    assert.equal(cRes.status, 201);
    const invitee = await db.collection("user").findOne({ email: "invitee@example.com" });
    assert.equal(invitee?.role, "user");
    assert.equal(await db.collection("user_app_registrations").countDocuments(), 0);
    assert.equal(await db.collection("app_admins").countDocuments(), 0);

    // 6. Existing account password sign-in continues working
    const existingLogin = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs(),
      body: JSON.stringify({ email: "existing@example.com", password: strongPassword }),
    });
    assert.equal(existingLogin.status, 200);
  });
});
