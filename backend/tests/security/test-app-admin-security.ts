import assert from "node:assert/strict";
import crypto from "crypto";
import { MongoClient, ObjectId } from "mongodb";
import { hashPassword } from "better-auth/crypto";
import { generateTotpCode } from "../../src/utils/totp";

// Load test environment
process.env.NODE_ENV = "test";
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.TRUSTED_PROXY_CIDRS = "10.0.0.0/8,172.16.0.0/12";

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");

console.log("================================================================");
console.log("  SWYRA AUTH -- APPLICATION ADMIN & ISOLATION SECURITY TESTS");
console.log("================================================================");

let passed = 0;
let failed = 0;

async function runTest(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`[FAIL] ${name}:`, err.message || err);
    failed++;
  }
}

// Test fixtures
const clientA_id = "test-app-a-" + crypto.randomBytes(4).toString("hex");
const clientA_secret = "secret-a-" + crypto.randomBytes(8).toString("hex");
const clientA_secretHash = crypto.createHash("sha256").update(clientA_secret).digest("base64url");

const clientB_id = "test-app-b-" + crypto.randomBytes(4).toString("hex");
const clientB_secret = "secret-b-" + crypto.randomBytes(8).toString("hex");
const clientB_secretHash = crypto.createHash("sha256").update(clientB_secret).digest("base64url");

const adminEmail = `admin-${crypto.randomBytes(4).toString("hex")}@example.com`;
const adminPassword = "AdminPassword@1234!";

let db: any;

try {
  db = await getDb();
} catch (e) {
  console.warn("[SKIP] MongoDB not available for in-memory integration tests:", e);
  process.exit(0);
}

// Setup test fixtures in DB
const passwordHash = await hashPassword(adminPassword);
await db.collection("oauthClient").insertMany([
  {
    clientId: clientA_id,
    clientSecret: clientA_secretHash,
    name: "Test Application A",
    redirectUris: ["http://localhost:3000/callback"],
    allowedOrigins: ["http://localhost:3000"],
    disabled: false,
    isPublic: true,
    createdAt: new Date(),
  },
  {
    clientId: clientB_id,
    clientSecret: clientB_secretHash,
    name: "Test Application B (Private)",
    redirectUris: ["http://localhost:3001/callback"],
    allowedOrigins: ["http://localhost:3001"],
    disabled: false,
    isPublic: false, // Private app mode
    createdAt: new Date(),
  },
]);

const adminInsert = await db.collection("app_admins").insertOne({
  clientId: clientA_id,
  email: adminEmail,
  name: "Lead Admin A",
  password: passwordHash,
  redirectUrl: "http://localhost:3000/admin",
  isActive: true,
  loginCount: 0,
  createdAt: new Date(),
});
const adminA_id = adminInsert.insertedId.toString();

// Cleanup hook
async function cleanup() {
  await db.collection("oauthClient").deleteMany({ clientId: { $in: [clientA_id, clientB_id] } });
  await db.collection("app_admins").deleteMany({ clientId: { $in: [clientA_id, clientB_id] } });
  await db.collection("app_admin_revoked_tokens").deleteMany({ clientId: { $in: [clientA_id, clientB_id] } });
  await db.collection("user_app_registrations").deleteMany({ clientId: { $in: [clientA_id, clientB_id] } });
}

try {
  // Test 1: Invalid client credentials rejected
  await runTest("SEC-1: Rejects login when client_secret is invalid", async () => {
    const res = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: "wrong-secret",
        email: adminEmail,
        password: adminPassword,
      }),
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");
  });

  // Test 2: Invalid admin password rejected
  await runTest("SEC-2: Rejects login when administrator password is wrong", async () => {
    const res = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        email: adminEmail,
        password: "WrongPassword@999!",
      }),
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_credentials");
  });

  // Test 3: Successful login issues JWT with correct claims
  let activeToken = "";
  await runTest("SEC-3: Successful login issues JWT with iss, aud, role, sub", async () => {
    const res = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        email: adminEmail,
        password: adminPassword,
      }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(body.token);
    activeToken = body.token;

    // Decode token claims
    const payload = JSON.parse(Buffer.from(activeToken.split(".")[1], "base64url").toString());
    assert.equal(payload.sub, adminA_id);
    assert.equal(payload.email, adminEmail);
    assert.equal(payload.clientId, clientA_id);
    assert.equal(payload.aud, clientA_id);
    assert.equal(payload.role, "app_admin");
    assert.ok(payload.iss);
  });

  // Test 4: Verify endpoint validates token
  await runTest("SEC-4: /verify endpoint confirms token validity", async () => {
    const res = await app.request("/api/auth/app-admin/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        token: activeToken,
      }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.valid, true);
    assert.equal(body.admin.email, adminEmail);
    assert.equal(body.admin.clientId, clientA_id);
  });

  // Test 5: Cross-App isolation — App A's token presented to App B is strictly rejected
  await runTest("SEC-5: Cross-app token presentation rejected (App A token -> App B)", async () => {
    const res = await app.request("/api/auth/app-admin/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientB_id,
        client_secret: clientB_secret,
        token: activeToken, // Token issued for App A
      }),
    });
    assert.equal(res.status, 401); // Audience verification fails
    const body = await res.json();
    assert.equal(body.valid, false);
  });

  // Test 6: Logout revokes token
  await runTest("SEC-6: Logout revokes session token", async () => {
    const logoutRes = await app.request("/api/auth/app-admin/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        token: activeToken,
      }),
    });
    assert.equal(logoutRes.status, 200);

    // Now verify must return token_revoked
    const verifyRes = await app.request("/api/auth/app-admin/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        token: activeToken,
      }),
    });
    assert.equal(verifyRes.status, 401);
    const verifyBody = await verifyRes.json();
    assert.equal(verifyBody.error, "token_revoked");
  });

  // Test 7: TOTP MFA Flow
  await runTest("SEC-7: TOTP MFA Setup, Confirm, Challenge, and Verify-Login", async () => {
    // 1. Log in again to get fresh token
    const loginRes = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        email: adminEmail,
        password: adminPassword,
      }),
    });
    const { token: sessionToken } = await loginRes.json();

    // 2. Setup MFA
    const setupRes = await app.request("/api/auth/app-admin/mfa/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        token: sessionToken,
      }),
    });
    assert.equal(setupRes.status, 200);
    const setupData = await setupRes.json();
    assert.ok(setupData.secret);
    assert.ok(setupData.otpauth_url);
    assert.equal(setupData.backup_codes.length, 8);

    // 3. Confirm with invalid code fails
    const badConfirmRes = await app.request("/api/auth/app-admin/mfa/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        token: sessionToken,
        code: "000000",
      }),
    });
    assert.equal(badConfirmRes.status, 400);

    // 4. Confirm with valid code succeeds
    const validCode = generateTotpCode(setupData.secret);
    const confirmRes = await app.request("/api/auth/app-admin/mfa/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        token: sessionToken,
        code: validCode,
      }),
    });
    assert.equal(confirmRes.status, 200);

    // 5. Subsequent login must return mfa_required: true and mfa_token
    const mfaLoginRes = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        email: adminEmail,
        password: adminPassword,
      }),
    });
    assert.equal(mfaLoginRes.status, 200);
    const mfaLoginBody = await mfaLoginRes.json();
    assert.equal(mfaLoginBody.mfa_required, true);
    assert.ok(mfaLoginBody.mfa_token);
    assert.equal(mfaLoginBody.token, undefined); // NO full JWT issued yet!

    // 6. Complete login with TOTP code via /mfa/verify-login
    const currentCode = generateTotpCode(setupData.secret);
    const verifyLoginRes = await app.request("/api/auth/app-admin/mfa/verify-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        mfa_token: mfaLoginBody.mfa_token,
        code: currentCode,
      }),
    });
    assert.equal(verifyLoginRes.status, 200);
    const verifyLoginBody = await verifyLoginRes.json();
    assert.equal(verifyLoginBody.success, true);
    assert.ok(verifyLoginBody.token);
    assert.equal(verifyLoginBody.admin.mfa_enabled, true);

    // 7. Test backup code verification
    const backupCode = setupData.backup_codes[0];
    const backupLoginRes = await app.request("/api/auth/app-admin/mfa/verify-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        mfa_token: mfaLoginBody.mfa_token,
        code: backupCode,
      }),
    });
    assert.equal(backupLoginRes.status, 200);
    assert.equal((await backupLoginRes.json()).usedBackupCode, true);

    // 8. Disable MFA
    const disableRes = await app.request("/api/auth/app-admin/mfa/disable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        token: verifyLoginBody.token,
        password: adminPassword,
        code: generateTotpCode(setupData.secret),
      }),
    });
    assert.equal(disableRes.status, 200);
  });

  // Test 8: Private Application Isolation
  await runTest("SEC-8: Private application blocks unauthorized users on sign-in & sign-up", async () => {
    // 1. Attempt sign-up on private app clientB_id should be rejected
    const signupRes = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": process.env.FRONTEND_URL || "http://localhost:5174",
      },
      body: JSON.stringify({
        email: "intruder@example.com",
        password: "ValidPassword@1234!",
        name: "Intruder",
        clientId: clientB_id,
      }),
    });
    assert.equal(signupRes.status, 403);
    const signupBody = await signupRes.json();
    assert.equal(signupBody.error, "registration_disabled");
  });

} finally {
  await cleanup();
}

console.log("================================================================");
console.log(`  SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

if (failed > 0) {
  process.exit(1);
}
