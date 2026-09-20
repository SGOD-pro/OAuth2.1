import assert from "node:assert/strict";
import crypto from "crypto";
import { ObjectId } from "mongodb";

// Load test environment
process.env.NODE_ENV = "test";
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;
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
const { registerTokenFamily, verifyAndRotateTokenFamily } = await import("../../src/db/state");

console.log("================================================================");
console.log("  SWYRA AUTH -- PHASE 25 ADVERSARIAL SECURITY GATE SUITE");
console.log("================================================================");

let passed = 0;
let failed = 0;
let ipCounter = 100;

function getTestHeaders(extra: Record<string, string> = {}) {
  const ip = `198.51.100.${++ipCounter % 250 + 1}`;
  return {
    "Content-Type": "application/json",
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    Origin: process.env.FRONTEND_URL || "http://localhost:5174",
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

async function main() {
  const db = await getDb();

  // Test Fixtures
  const appA_id = "phase25-app-a-" + crypto.randomBytes(4).toString("hex");
  const appB_id = "phase25-app-b-" + crypto.randomBytes(4).toString("hex");
  const disabledApp_id = "phase25-disabled-" + crypto.randomBytes(4).toString("hex");

  // Provision test apps in MongoDB
  await db.collection("oauthClient").insertMany([
    {
      clientId: appA_id,
      name: "Private App A",
      redirectUris: ["http://localhost:3000/callback"],
      isPublic: false,
      disabled: false,
      createdAt: new Date(),
    },
    {
      clientId: appB_id,
      name: "Private App B",
      redirectUris: ["http://localhost:3000/callback"],
      isPublic: false,
      disabled: false,
      createdAt: new Date(),
    },
    {
      clientId: disabledApp_id,
      name: "Disabled App",
      redirectUris: ["http://localhost:3000/callback"],
      isPublic: false,
      disabled: true,
      createdAt: new Date(),
    },
  ]);

  // Provision Scoped Admin for App A
  const scopedAdminEmail = `scoped-admin-${crypto.randomBytes(4).toString("hex")}@example.com`;
  const scopedAdminPass = "ScopedAdminPass@1234!";
  const scopedAdminRes = await authProvider.api.signUpEmail({
    body: { email: scopedAdminEmail, password: scopedAdminPass, name: "Scoped Admin App A" },
    asResponse: true,
  });
  const scopedAdminCookie = (scopedAdminRes.headers.get("set-cookie") || "").split(";")[0];
  const scopedAdminUserDoc = await db.collection("user").findOne({ email: scopedAdminEmail });
  const scopedAdminId = String(scopedAdminUserDoc?.id || scopedAdminUserDoc?._id);

  await db.collection("user").updateOne(
    { email: scopedAdminEmail },
    { $set: { role: "admin", scopedClientId: appA_id, emailVerified: true } }
  );

  // Provision Super Admin (global, scopedClientId = null)
  const superAdminEmail = `super-admin-${crypto.randomBytes(4).toString("hex")}@example.com`;
  const superAdminPass = "SuperAdminPass@1234!";
  const superAdminRes = await authProvider.api.signUpEmail({
    body: { email: superAdminEmail, password: superAdminPass, name: "Global Super Admin" },
    asResponse: true,
  });
  const superAdminCookie = (superAdminRes.headers.get("set-cookie") || "").split(";")[0];

  await db.collection("user").updateOne(
    { email: superAdminEmail },
    { $set: { role: "admin", scopedClientId: null, emailVerified: true } }
  );

  // Provision Regular User
  const regularEmail = `regular-${crypto.randomBytes(4).toString("hex")}@example.com`;
  const regularPass = "RegularPass@1234!";
  const regularRes = await authProvider.api.signUpEmail({
    body: { email: regularEmail, password: regularPass, name: "Regular User" },
    asResponse: true,
  });
  const regularCookie = (regularRes.headers.get("set-cookie") || "").split(";")[0];
  const regularUserDoc = await db.collection("user").findOne({ email: regularEmail });
  const regularUserId = String(regularUserDoc?.id || regularUserDoc?._id);

  // -------------------------------------------------------------
  // TEST 1: Scoped Admin OAuth Boundary Isolation (App A admin -> App B)
  // -------------------------------------------------------------
  await runTest(
    "GATE-1: Scoped-Admin (App A) is denied authorization on private App B",
    async () => {
      const res = await app.request(
        `/api/auth/oauth2/authorize?client_id=${appB_id}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code&scope=openid&state=teststate1&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256`,
        {
          method: "GET",
          headers: getTestHeaders({ Cookie: scopedAdminCookie }),
        }
      );

      // Must redirect to redirect_uri with error=access_denied, NOT proceed or issue code!
      assert.equal(res.status, 302, "Expected 302 redirect on access denied");
      const location = res.headers.get("location") || "";
      assert.ok(location.includes("error=access_denied"), `Expected access_denied in redirect location: ${location}`);
    }
  );

  // -------------------------------------------------------------
  // TEST 2: Scoped Admin Authorizing for Own App (App A admin -> App A)
  // -------------------------------------------------------------
  await runTest(
    "GATE-2: Scoped-Admin (App A) is allowed authorization for own assigned App A",
    async () => {
      const res = await app.request(
        `/api/auth/oauth2/authorize?client_id=${appA_id}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code&scope=openid&state=teststate2&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256`,
        {
          method: "GET",
          headers: getTestHeaders({ Cookie: scopedAdminCookie }),
        }
      );

      const location = res.headers.get("location") || "";
      assert.ok(!location.includes("error=access_denied"), `Expected no access_denied for own app: ${location}`);
    }
  );

  // -------------------------------------------------------------
  // TEST 3: Super Admin Can Authorize for Any App
  // -------------------------------------------------------------
  await runTest(
    "GATE-3: Global Super-Admin bypasses private app membership check globally",
    async () => {
      const res = await app.request(
        `/api/auth/oauth2/authorize?client_id=${appB_id}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code&scope=openid&state=teststate3&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256`,
        {
          method: "GET",
          headers: getTestHeaders({ Cookie: superAdminCookie }),
        }
      );

      const location = res.headers.get("location") || "";
      assert.ok(!location.includes("error=access_denied"), `Super admin should not be denied: ${location}`);
    }
  );

  // -------------------------------------------------------------
  // TEST 4: Scoped Admin Sign-In Isolation for Other Apps
  // -------------------------------------------------------------
  await runTest(
    "GATE-4: Scoped-Admin (App A) cannot sign in to private App B via /sign-in/email",
    async () => {
      const res = await app.request("/api/auth/sign-in/email", {
        method: "POST",
        headers: getTestHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          email: scopedAdminEmail,
          password: scopedAdminPass,
          client_id: appB_id,
        }),
      });

      assert.equal(res.status, 403, "Expected 403 access_denied for scoped admin accessing unassigned private app");
      const body = await res.json();
      assert.equal(body.error, "access_denied");
    }
  );

  // -------------------------------------------------------------
  // TEST 5: /oauth/initiate Validates Client Existence & Status
  // -------------------------------------------------------------
  await runTest(
    "GATE-5: /oauth/initiate rejects non-existent and disabled clients",
    async () => {
      // Non-existent client
      const resNonExistent = await app.request("/api/auth/oauth/initiate?client_id=non-existent-app-xyz", {
        method: "GET",
        headers: getTestHeaders(),
      });
      assert.equal(resNonExistent.status, 400, "Non-existent client must return 400");
      const bodyNonExistent = await resNonExistent.json();
      assert.equal(bodyNonExistent.error, "invalid_client");

      // Disabled client
      const resDisabled = await app.request(`/api/auth/oauth/initiate?client_id=${disabledApp_id}`, {
        method: "GET",
        headers: getTestHeaders(),
      });
      assert.equal(resDisabled.status, 400, "Disabled client must return 400");
      const bodyDisabled = await resDisabled.json();
      assert.equal(bodyDisabled.error, "invalid_client");

      // Valid client sets current_client_id cookie
      const resValid = await app.request(`/api/auth/oauth/initiate?client_id=${appA_id}`, {
        method: "GET",
        headers: getTestHeaders(),
      });
      assert.equal(resValid.status, 200);
      const setCookie = resValid.headers.get("set-cookie") || "";
      assert.ok(setCookie.includes("current_client_id="), "Expected current_client_id cookie to be set");
    }
  );

  // -------------------------------------------------------------
  // TEST 6: /sign-in/email Rejects Non-Existent Client ID (Fail Closed)
  // -------------------------------------------------------------
  await runTest(
    "GATE-6: /sign-in/email rejects non-existent client ID instead of defaulting to public",
    async () => {
      const res = await app.request("/api/auth/sign-in/email", {
        method: "POST",
        headers: getTestHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          email: regularEmail,
          password: regularPass,
          client_id: "fake-bogus-client-999",
        }),
      });

      assert.equal(res.status, 400, "Unknown client_id must be rejected with 400 invalid_client");
      const body = await res.json();
      assert.equal(body.error, "invalid_client");
    }
  );

  // -------------------------------------------------------------
  // TEST 7: /sign-up/email Rejects Non-Existent Client ID
  // -------------------------------------------------------------
  await runTest(
    "GATE-7: /sign-up/email rejects non-existent client ID",
    async () => {
      const res = await app.request("/api/auth/sign-up/email", {
        method: "POST",
        headers: getTestHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          email: `new-${Date.now()}@example.com`,
          password: "SecurePass@1234!",
          name: "Test User",
          client_id: "fake-bogus-client-999",
        }),
      });

      assert.equal(res.status, 400, "Unknown client_id in sign-up must be rejected with 400 invalid_client");
      const body = await res.json();
      assert.equal(body.error, "invalid_client");
    }
  );

  // -------------------------------------------------------------
  // TEST 8: Token Family Replay Revocation is User-Scoped (No Cross-User DoS)
  // -------------------------------------------------------------
  await runTest(
    "GATE-8: Token family replay revocation does not destroy other users' tokens (No DoS)",
    async () => {
      const sharedClientId = "shared-client-" + crypto.randomBytes(4).toString("hex");
      const user1Id = "user-1-" + crypto.randomBytes(4).toString("hex");
      const user2Id = "user-2-" + crypto.randomBytes(4).toString("hex");

      const u1RawToken1 = "u1-token-1-" + crypto.randomUUID();
      const u1RawToken2 = "u1-token-2-" + crypto.randomUUID();
      const u2RawToken1 = "u2-token-1-" + crypto.randomUUID();

      const user1TokenHash1 = crypto.createHash("sha256").update(u1RawToken1).digest("hex");
      const user1TokenHash2 = crypto.createHash("sha256").update(u1RawToken2).digest("hex");
      const user2TokenHash1 = crypto.createHash("sha256").update(u2RawToken1).digest("hex");

      // Register families for User 1 and User 2 on the same client
      const fam1Id = crypto.randomUUID();
      const fam2Id = crypto.randomUUID();
      await registerTokenFamily(fam1Id, sharedClientId, user1Id, user1TokenHash1);
      await registerTokenFamily(fam2Id, sharedClientId, user2Id, user2TokenHash1);

      // Seed tokens in oauthAccessToken and oauthRefreshToken
      await db.collection("oauthAccessToken").insertMany([
        { token: "u1-access", clientId: sharedClientId, userId: user1Id },
        { token: "u2-access", clientId: sharedClientId, userId: user2Id },
      ]);
      await db.collection("oauthRefreshToken").insertMany([
        { token: "u1-refresh", clientId: sharedClientId, userId: user1Id },
        { token: "u2-refresh", clientId: sharedClientId, userId: user2Id },
      ]);

      // Legitimate rotation for User 1: token 1 -> token 2
      const rot = await verifyAndRotateTokenFamily(user1TokenHash1, user1TokenHash2);
      assert.equal(rot.valid, true, "Legitimate rotation should succeed");

      // Replay attack with User 1's consumed token 1!
      const replay = await verifyAndRotateTokenFamily(user1TokenHash1, "attacker-new-hash");
      assert.equal(replay.replayed, true, "Replay must be detected");

      // Verify User 1 tokens were deleted
      const u1Access = await db.collection("oauthAccessToken").findOne({ clientId: sharedClientId, userId: user1Id });
      const u1Refresh = await db.collection("oauthRefreshToken").findOne({ clientId: sharedClientId, userId: user1Id });
      assert.equal(u1Access, null, "User 1 access token must be revoked");
      assert.equal(u1Refresh, null, "User 1 refresh token must be revoked");

      // Verify User 2 tokens are STILL INTACT!
      const u2Access = await db.collection("oauthAccessToken").findOne({ clientId: sharedClientId, userId: user2Id });
      const u2Refresh = await db.collection("oauthRefreshToken").findOne({ clientId: sharedClientId, userId: user2Id });
      assert.ok(u2Access !== null, "User 2 access token MUST NOT be revoked by User 1 replay");
      assert.ok(u2Refresh !== null, "User 2 refresh token MUST NOT be revoked by User 1 replay");
    }
  );

  // -------------------------------------------------------------
  // TEST 9: Atomic Compare-and-Swap Token Rotation Race Test
  // -------------------------------------------------------------
  await runTest(
    "GATE-9: Atomic Compare-and-Swap token rotation prevents concurrent double-rotation",
    async () => {
      const testClientId = "cas-client-" + crypto.randomBytes(4).toString("hex");
      const testUserId = "cas-user-" + crypto.randomBytes(4).toString("hex");
      const activeHash = crypto.createHash("sha256").update("race-token-active-" + crypto.randomUUID()).digest("hex");
      const nextHashA = crypto.createHash("sha256").update("race-token-next-a-" + crypto.randomUUID()).digest("hex");
      const nextHashB = crypto.createHash("sha256").update("race-token-next-b-" + crypto.randomUUID()).digest("hex");

      await registerTokenFamily(crypto.randomUUID(), testClientId, testUserId, activeHash);

      // Run two simultaneous rotations on the same activeHash
      const [resA, resB] = await Promise.all([
        verifyAndRotateTokenFamily(activeHash, nextHashA),
        verifyAndRotateTokenFamily(activeHash, nextHashB),
      ]);

      // Exactly one must succeed with valid: true
      const successCount = (resA.valid ? 1 : 0) + (resB.valid ? 1 : 0);
      assert.equal(successCount, 1, `Exactly one concurrent rotation should succeed. Got A=${resA.valid}, B=${resB.valid}`);
    }
  );

  // -------------------------------------------------------------
  // TEST 10: Direct Better-Auth OAuth Endpoints are Blocked
  // -------------------------------------------------------------
  await runTest(
    "GATE-10: Direct Better-Auth OAuth endpoints are strictly blocked with 403",
    async () => {
      const endpoints = [
        "/api/auth/oauth2/register",
        "/api/auth/oauth2/create-client",
        "/api/auth/oauth2/update-client",
        "/api/auth/oauth2/delete-client",
        "/api/auth/oauth2/client/rotate-secret",
      ];

      for (const endpoint of endpoints) {
        const res = await app.request(endpoint, {
          method: "POST",
          headers: getTestHeaders({ Cookie: regularCookie }),
          body: JSON.stringify({ client_id: appA_id }),
        });
        assert.equal(res.status, 403, `Endpoint ${endpoint} must be blocked with 403`);
        const body = await res.json();
        assert.equal(body.error, "access_denied");
      }
    }
  );

  // -------------------------------------------------------------
  // TEST 11: Better-Auth Internal Admin Routes Block Non-Super-Admins
  // -------------------------------------------------------------
  await runTest(
    "GATE-11: Better-Auth internal admin routes (/admin/*) block regular and scoped admins",
    async () => {
      // Anonymous
      const resAnon = await app.request("/api/auth/admin/set-role", {
        method: "POST",
        headers: getTestHeaders(),
        body: JSON.stringify({ userId: regularUserId, role: "admin" }),
      });
      assert.equal(resAnon.status, 403, "Anonymous request to /admin/set-role must be forbidden");

      // Regular User
      const resUser = await app.request("/api/auth/admin/set-role", {
        method: "POST",
        headers: getTestHeaders({ Cookie: regularCookie }),
        body: JSON.stringify({ userId: regularUserId, role: "admin" }),
      });
      assert.equal(resUser.status, 403, "Regular user request to /admin/set-role must be forbidden");

      // Scoped Admin (must NOT be able to change roles or ban users!)
      const resScoped = await app.request("/api/auth/admin/set-role", {
        method: "POST",
        headers: getTestHeaders({ Cookie: scopedAdminCookie }),
        body: JSON.stringify({ userId: regularUserId, role: "admin" }),
      });
      assert.equal(resScoped.status, 403, "Scoped admin request to /admin/set-role must be forbidden");
    }
  );

  console.log("================================================================");
  console.log(`  PHASE 25 GATE RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log("================================================================");

  if (failed > 0) {
    process.exit(1);
  }
  process.exit(0);
}

main().catch((err) => {
  console.error("Test execution fatal error:", err);
  process.exit(1);
});
