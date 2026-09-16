import assert from "node:assert/strict";
import crypto from "crypto";
import { ObjectId } from "mongodb";
import { hashPassword } from "better-auth/crypto";
import { generateTotpCode } from "../../src/utils/totp";
import { envSchema } from "../../src/config/schema";

// Load test environment
process.env.NODE_ENV = "test";
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32";

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");

console.log("================================================================");
console.log("  SWYRA AUTH -- APPLICATION ADMIN & ISOLATION SECURITY TESTS");
console.log("================================================================");

let passed = 0;
let failed = 0;
let ipCounter = 1;

function getTestHeaders(extra: Record<string, string> = {}) {
  const ip = `198.51.100.${++ipCounter % 250 + 1}`;
  return {
    "Content-Type": "application/json",
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    ...extra,
  };
}

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

const clientDisabled_id = "test-app-disabled-" + crypto.randomBytes(4).toString("hex");

const adminEmail = `admin-${crypto.randomBytes(4).toString("hex")}@example.com`;
const adminPassword = "AdminPassword@1234!";

const regularUserEmail = `user-${crypto.randomBytes(4).toString("hex")}@example.com`;
const regularUserPassword = "RegularUserPassword@1234!";

let db: any;

try {
  db = await getDb();
  if (!db) throw new Error("Database handle is null");
} catch (e) {
  console.error("[FATAL] MongoDB not available for security test suite:", e);
  process.exit(1);
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
  {
    clientId: clientDisabled_id,
    clientSecret: clientA_secretHash,
    name: "Disabled Application",
    redirectUris: ["http://localhost:3002/callback"],
    allowedOrigins: ["http://localhost:3002"],
    disabled: true,
    isPublic: true,
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

// Create regular user & session via Better-Auth
let regularUserId = "";
let regularSessionCookie = "";

try {
  const signUpRes = await authProvider.api.signUpEmail({
    body: {
      email: regularUserEmail,
      password: regularUserPassword,
      name: "Regular User",
    },
    asResponse: true,
  });
  const setCookie = signUpRes.headers.get("set-cookie");
  if (setCookie) {
    regularSessionCookie = setCookie.split(";")[0];
  }
  const u = await db.collection("user").findOne({ email: regularUserEmail });
  regularUserId = u ? String(u.id || u._id) : "";
} catch (err) {
  console.warn("Could not pre-create user via Better-Auth, creating directly in DB:", err);
  const uId = new ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new ObjectId(uId),
    id: uId,
    email: regularUserEmail,
    name: "Regular User",
    emailVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  const token = "mock-session-token-" + crypto.randomBytes(8).toString("hex");
  await db.collection("session").insertOne({
    _id: new ObjectId(),
    id: crypto.randomUUID(),
    userId: uId,
    token,
    expiresAt: new Date(Date.now() + 24 * 3600 * 1000),
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  regularUserId = uId;
  regularSessionCookie = `better-auth.session_token=${token}`;
}

// Cleanup hook
async function cleanup() {
  try {
    await db.collection("oauthClient").deleteMany({ clientId: { $in: [clientA_id, clientB_id, clientDisabled_id] } });
    await db.collection("app_admins").deleteMany({ clientId: { $in: [clientA_id, clientB_id] } });
    await db.collection("app_admin_revoked_tokens").deleteMany({ clientId: { $in: [clientA_id, clientB_id] } });
    await db.collection("user_app_registrations").deleteMany({ clientId: { $in: [clientA_id, clientB_id] } });
    if (regularUserId) {
      await db.collection("user").deleteMany({ $or: [{ id: regularUserId }, { email: regularUserEmail }] });
      await db.collection("session").deleteMany({ userId: regularUserId });
    }
  } catch (err) {
    console.error("Cleanup error:", err);
  }
}

try {
  // Test 1: Invalid client credentials rejected
  await runTest("SEC-1: Rejects login when client_secret is invalid", async () => {
    const res = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: getTestHeaders(),
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
      headers: getTestHeaders(),
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

  // Test 3: Successful login issues JWT with correct claims including token_use
  let activeToken = "";
  await runTest("SEC-3: Successful login issues JWT with iss, aud, role, sub, token_use", async () => {
    const res = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: getTestHeaders(),
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
    assert.equal(payload.token_use, "app_admin");
    assert.ok(payload.iss);
  });

  // Test 4: Verify endpoint validates token
  await runTest("SEC-4: /verify endpoint confirms token validity and token_use", async () => {
    const res = await app.request("/api/auth/app-admin/verify", {
      method: "POST",
      headers: getTestHeaders(),
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
      headers: getTestHeaders(),
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
      headers: getTestHeaders(),
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
      headers: getTestHeaders(),
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

  // Test 7: TOTP MFA Flow, Token Purpose Enforcement & Atomic Backup Code Invalidation
  await runTest("SEC-7: TOTP MFA Setup, Token Purpose Enforcement & Atomic Backup Codes", async () => {
    // 1. Log in again to get fresh session token
    const loginRes = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: getTestHeaders(),
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
      headers: getTestHeaders(),
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
      headers: getTestHeaders(),
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
      headers: getTestHeaders(),
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        token: sessionToken,
        code: validCode,
      }),
    });
    assert.equal(confirmRes.status, 200);

    // 5. Subsequent login must return mfa_required: true and mfa_token with token_use: app_admin_mfa_pending
    const mfaLoginRes = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: getTestHeaders(),
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

    // Verify mfa_token has token_use: app_admin_mfa_pending
    const mfaPayload = JSON.parse(Buffer.from(mfaLoginBody.mfa_token.split(".")[1], "base64url").toString());
    assert.equal(mfaPayload.token_use, "app_admin_mfa_pending");

    // 6. Security Check: Token Purpose Confusion Attack Prevention
    // Presenting mfa_token (app_admin_mfa_pending) to /verify must fail
    const confuseVerifyRes = await app.request("/api/auth/app-admin/verify", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        token: mfaLoginBody.mfa_token,
      }),
    });
    assert.equal(confuseVerifyRes.status, 401);
    const confuseVerifyBody = await confuseVerifyRes.json();
    assert.equal(confuseVerifyBody.error, "invalid_token_purpose");

    // Presenting full session token to /mfa/verify-login must fail
    const confuseMfaRes = await app.request("/api/auth/app-admin/mfa/verify-login", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        mfa_token: sessionToken,
        code: "123456",
      }),
    });
    assert.equal(confuseMfaRes.status, 401);
    const confuseMfaBody = await confuseMfaRes.json();
    assert.equal(confuseMfaBody.error, "invalid_token_purpose");

    // 7. Complete login with TOTP code via /mfa/verify-login
    const currentCode = generateTotpCode(setupData.secret);
    const verifyLoginRes = await app.request("/api/auth/app-admin/mfa/verify-login", {
      method: "POST",
      headers: getTestHeaders(),
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

    // 8. Test Atomic One-Time Backup Code Consumption
    const backupCode = setupData.backup_codes[0];

    // Trigger another login challenge to get fresh mfa_token
    const mfaLoginRes2 = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        email: adminEmail,
        password: adminPassword,
      }),
    });
    const { mfa_token: mfaToken2 } = await mfaLoginRes2.json();

    // First use of backup code must succeed
    const backupLoginRes = await app.request("/api/auth/app-admin/mfa/verify-login", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        mfa_token: mfaToken2,
        code: backupCode,
      }),
    });
    assert.equal(backupLoginRes.status, 200);
    assert.equal((await backupLoginRes.json()).usedBackupCode, true);

    // Immediate replay/reuse of consumed backup code MUST fail
    const mfaLoginRes3 = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        email: adminEmail,
        password: adminPassword,
      }),
    });
    const { mfa_token: mfaToken3 } = await mfaLoginRes3.json();

    const backupReuseRes = await app.request("/api/auth/app-admin/mfa/verify-login", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        mfa_token: mfaToken3,
        code: backupCode, // Reusing consumed backup code
      }),
    });
    assert.equal(backupReuseRes.status, 401);
    const backupReuseBody = await backupReuseRes.json();
    assert.equal(backupReuseBody.error, "invalid_code");

    // 9. Disable MFA
    const disableRes = await app.request("/api/auth/app-admin/mfa/disable", {
      method: "POST",
      headers: getTestHeaders(),
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

  // Test 8: Private Application Isolation on Sign-Up
  await runTest("SEC-8: Private application blocks unauthorized public sign-up", async () => {
    const signupRes = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: getTestHeaders({
        Origin: process.env.FRONTEND_URL || "http://localhost:5174",
      }),
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

  // Test 9: OAuth 2.1 Boundary Private-App Enforcement (Session Bypass Vector Prevention)
  await runTest("SEC-9: OAuth boundary blocks pre-authenticated global session on private app", async () => {
    // 1. User has valid session cookie but NO registration for private app clientB_id
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${clientB_id}&redirect_uri=http://localhost:3001/callback&response_type=code&scope=openid&state=state_xyz123`,
      {
        method: "GET",
        headers: getTestHeaders({
          Cookie: regularSessionCookie,
        }),
      }
    );

    // Must be redirected to redirect_uri with error=access_denied
    assert.equal(authRes.status, 302);
    const location = authRes.headers.get("location") || "";
    assert.ok(location.startsWith("http://localhost:3001/callback"));
    assert.ok(location.includes("error=access_denied"));
    assert.ok(location.includes("state=state_xyz123"));

    // 2. Now register user to private app
    await db.collection("user_app_registrations").insertOne({
      clientId: clientB_id,
      userId: regularUserId,
      registeredAt: new Date(),
    });

    // 3. Re-request authorization with registration in place
    const authorizedRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${clientB_id}&redirect_uri=http://localhost:3001/callback&response_type=code&scope=openid&state=state_xyz123`,
      {
        method: "GET",
        headers: getTestHeaders({
          Cookie: regularSessionCookie,
        }),
      }
    );

    // Must NOT be redirected with access_denied
    const authLocation = authorizedRes.headers.get("location") || "";
    assert.ok(!authLocation.includes("error=access_denied"));
  });

  // Test 10: OAuth Boundary Redirect URI & Client Status Enforcement
  await runTest("SEC-10: OAuth boundary rejects unregistered redirect URIs and disabled clients", async () => {
    // 1. Unregistered redirect_uri rejected with 400
    const badUriRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${clientA_id}&redirect_uri=http://malicious.example.com/callback&response_type=code&state=state_test`,
      {
        method: "GET",
        headers: getTestHeaders(),
      }
    );
    assert.equal(badUriRes.status, 400);

    // 2. Disabled client rejected with 403
    const disabledRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${clientDisabled_id}&redirect_uri=http://localhost:3002/callback&response_type=code&state=state_test`,
      {
        method: "GET",
        headers: getTestHeaders(),
      }
    );
    assert.equal(disabledRes.status, 403);
    const disabledBody = await disabledRes.json();
    assert.equal(disabledBody.error, "unauthorized_client");

    // 3. Nonexistent client rejected with 401
    const missingRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=nonexistent-client-id&redirect_uri=http://localhost:3000/callback&response_type=code&state=state_test`,
      {
        method: "GET",
        headers: getTestHeaders(),
      }
    );
    assert.equal(missingRes.status, 401);
    const missingBody = await missingRes.json();
    assert.equal(missingBody.error, "invalid_client");
  });

  // Test 11: Production Fail-Fast Environment Validation
  await runTest("SEC-11: Environment schema requires APP_ADMIN secrets in production", async () => {
    const baseProdEnv = {
      NODE_ENV: "production",
      PORT: 3000,
      MONGO_URI: "mongodb://127.0.0.1:27017/test_db",
      BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "https://auth.example.com",
      GOOGLE_CLIENT_ID: "google-id",
      GOOGLE_CLIENT_SECRET: "google-secret",
      FRONTEND_URL: "https://auth.example.com",
    };

    // Missing APP_ADMIN_JWT_SECRET in production fails
    const failMissingJwt = envSchema.safeParse({
      ...baseProdEnv,
      APP_ADMIN_TOTP_KEY: "b".repeat(32),
    });
    assert.equal(failMissingJwt.success, false);

    // Short APP_ADMIN_JWT_SECRET (< 32 chars) fails
    const failShortJwt = envSchema.safeParse({
      ...baseProdEnv,
      APP_ADMIN_JWT_SECRET: "too-short",
      APP_ADMIN_TOTP_KEY: "b".repeat(32),
    });
    assert.equal(failShortJwt.success, false);

    // Missing APP_ADMIN_TOTP_KEY in production fails
    const failMissingTotp = envSchema.safeParse({
      ...baseProdEnv,
      APP_ADMIN_JWT_SECRET: "a".repeat(32),
    });
    assert.equal(failMissingTotp.success, false);

    // Valid production configuration passes
    const passProd = envSchema.safeParse({
      ...baseProdEnv,
      APP_ADMIN_JWT_SECRET: "a".repeat(32),
      APP_ADMIN_TOTP_KEY: "b".repeat(32),
    });
    assert.equal(passProd.success, true);
  });

} finally {
  await cleanup();
}

console.log("================================================================");
console.log(`  SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
