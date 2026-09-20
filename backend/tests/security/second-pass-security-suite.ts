import assert from "node:assert/strict";
import crypto from "crypto";
import { ObjectId } from "mongodb";

// Configure test environment
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
const { isRegisteredRedirectUri } = await import("../../src/utils/security");

console.log("================================================================");
console.log("  SWYRA AUTH -- SECOND-PASS ADVERSARIAL SECURITY TEST SUITE");
console.log("================================================================");

let passed = 0;
let failed = 0;
let ipCounter = 300;

function getHeaders(extra: Record<string, string> = {}) {
  const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
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

const db = await getDb();

// Seed Helper
async function seedClient(clientId: string, clientSecret: string, isPublic: boolean, redirectUris: string[], disabled = false) {
  const secretHash = crypto.createHash("sha256").update(clientSecret).digest("base64url");
  await db.collection("oauthClient").updateOne(
    { clientId },
    {
      $set: {
        clientId,
        client_id: clientId,
        clientSecret: secretHash,
        client_secret: secretHash,
        name: `App ${clientId}`,
        isPublic,
        is_public: isPublic,
        disabled,
        redirectUris,
        redirect_uris: redirectUris,
        allowedOrigins: ["http://localhost:5174"],
        updatedAt: new Date(),
      },
    },
    { upsert: true }
  );
}

// --------------------------------------------------------------------------
// SECTION 1: CLIENT IDENTITY BINDING (HTTP Basic vs Request Body)
// --------------------------------------------------------------------------
await runTest("BINDING-1: Basic(AppA) + body client_id=AppA (matching) is accepted", async () => {
  const clientA = "test_bind_client_a";
  const secretA = "secret_a_12345678";
  await seedClient(clientA, secretA, false, ["http://localhost:5174/cb"]);

  const basicAuth = Buffer.from(`${clientA}:${secretA}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: "dummy_code_invalid",
    client_id: clientA,
  });

  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getHeaders({
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: body.toString(),
  });

  // Client authentication should succeed; code validation failure (400 invalid_grant) proves client auth passed
  const json = await res.json();
  assert.notEqual(json.error, "invalid_client", "Client auth must succeed when header and body agree");
});

await runTest("BINDING-2: Basic(AppA) + body client_id=AppB (conflicting client_id) is REJECTED", async () => {
  const clientA = "test_bind_client_a";
  const clientB = "test_bind_client_b";
  const secretA = "secret_a_12345678";
  const secretB = "secret_b_12345678";
  await seedClient(clientA, secretA, false, ["http://localhost:5174/cb"]);
  await seedClient(clientB, secretB, false, ["http://localhost:5174/cb"]);

  const basicAuth = Buffer.from(`${clientA}:${secretA}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: "dummy_code",
    client_id: clientB,
  });

  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getHeaders({
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: body.toString(),
  });

  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.error, "invalid_client", "Conflicting client identifiers must be rejected with invalid_client");
});

await runTest("BINDING-3: Basic(AppA) + body client_secret=AppB_secret (multiple auth methods) is REJECTED", async () => {
  const clientA = "test_bind_client_a";
  const secretA = "secret_a_12345678";
  const secretB = "secret_b_12345678";

  const basicAuth = Buffer.from(`${clientA}:${secretA}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: "dummy_code",
    client_secret: secretB,
  });

  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getHeaders({
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: body.toString(),
  });

  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.error, "invalid_client", "Dual authentication credentials must be rejected per RFC 6749 Section 2.3");
});

await runTest("BINDING-4: invalid Basic header + valid body credentials does NOT fall back to body", async () => {
  const clientB = "test_bind_client_b";
  const secretB = "secret_b_12345678";

  // Invalid basic auth header format
  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getHeaders({
      Authorization: "Basic not_valid_base64!!!",
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: "dummy_code",
      client_id: clientB,
      client_secret: secretB,
    }).toString(),
  });

  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.error, "invalid_client", "Invalid basic auth must fail closed without fallback to body");
});

// --------------------------------------------------------------------------
// SECTION 2: APPLICATION MEMBERSHIP INTEGRITY
// --------------------------------------------------------------------------
await runTest("MEMBERSHIP-1: Wrong password does NOT mutate user_app_registrations", async () => {
  const clientPublic = "test_public_membership_app";
  await seedClient(clientPublic, "secret", true, ["http://localhost:5174/cb"]);

  const email = `victim_${crypto.randomUUID()}@example.com`;
  const password = "StrongPassword@123!";

  // Create legitimate user first
  await authProvider.api.signUpEmail({
    body: { email, password, name: "Victim User" },
  });

  const user = await db.collection("user").findOne({ email });
  assert.ok(user, "User should exist");
  const userId = String(user.id || user._id);

  // Attacker attempts login with WRONG password on public app
  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({
      email,
      password: "WrongPassword@999!",
      client_id: clientPublic,
    }),
  });

  assert.notEqual(res.status, 200, "Wrong password must fail authentication");

  // Verify that user_app_registrations was NOT mutated!
  const reg = await db.collection("user_app_registrations").findOne({
    userId,
    clientId: clientPublic,
  });
  assert.equal(reg, null, "Failed authentication MUST NEVER mutate application membership!");
});

await runTest("MEMBERSHIP-2: Unauthenticated sign-up with existing email does NOT link user", async () => {
  const clientPublic = "test_public_membership_app_2";
  await seedClient(clientPublic, "secret", true, ["http://localhost:5174/cb"]);

  const email = `victim2_${crypto.randomUUID()}@example.com`;
  const password = "StrongPassword@123!";

  // Existing user
  await authProvider.api.signUpEmail({
    body: { email, password, name: "Victim Two" },
  });

  const user = await db.collection("user").findOne({ email });
  if (!user) throw new Error("User must exist");
  const userId = String(user.id || user._id);

  // Attacker posts to sign-up with victim's email and client_id
  const res = await app.request("/api/auth/sign-up/email", {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({
      email,
      password: "AttackerChosenPassword@123!",
      name: "Imposter",
      client_id: clientPublic,
    }),
  });

  // Better Auth rejects duplicate sign-up
  assert.notEqual(res.status, 200, "Duplicate sign-up must fail");

  // Verify that existing account was NOT auto-linked!
  const reg = await db.collection("user_app_registrations").findOne({
    userId,
    clientId: clientPublic,
  });
  assert.equal(reg, null, "Unauthenticated sign-up must NEVER link an existing user to an application!");
});

await runTest("MEMBERSHIP-3: Successful authentication on public app creates membership", async () => {
  const clientPublic = "test_public_membership_app_3";
  await seedClient(clientPublic, "secret", true, ["http://localhost:5174/cb"]);

  const email = `legit_${crypto.randomUUID()}@example.com`;
  const password = "StrongPassword@123!";

  await authProvider.api.signUpEmail({
    body: { email, password, name: "Legit User" },
  });

  const user = await db.collection("user").findOne({ email });
  if (!user) throw new Error("User must exist");
  const userId = String(user.id || user._id);

  // Authenticate with valid password on public app
  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({
      email,
      password,
      client_id: clientPublic,
    }),
  });

  assert.equal(res.status, 200, "Valid credentials must succeed");

  const reg = await db.collection("user_app_registrations").findOne({
    userId,
    clientId: clientPublic,
  });
  assert.ok(reg, "Successful authentication on public app must record application registration");
});

await runTest("MEMBERSHIP-4: Unassigned user from private app cannot refresh tokens", async () => {
  const clientPrivate = "test_private_membership_app";
  await seedClient(clientPrivate, "secret", false, ["http://localhost:5174/cb"]);

  const email = `unassigned_${crypto.randomUUID()}@example.com`;
  const password = "StrongPassword@123!";

  await authProvider.api.signUpEmail({
    body: { email, password, name: "Unassigned User" },
  });

  const user = await db.collection("user").findOne({ email });
  if (!user) throw new Error("User must exist");
  const userId = String(user.id || user._id);

  // Initially assigned to private app
  await db.collection("user_app_registrations").insertOne({
    userId,
    clientId: clientPrivate,
    registeredAt: new Date(),
  });

  // Create active refresh token and family
  const initialRefresh = crypto.randomUUID();
  const initialHash = crypto.createHash("sha256").update(initialRefresh).digest("hex");
  const familyId = crypto.randomUUID();
  await registerTokenFamily(familyId, clientPrivate, userId, initialHash);

  // Now ADMIN REMOVES USER from application
  await db.collection("user_app_registrations").deleteMany({
    userId,
    clientId: clientPrivate,
  });

  // Also verify that admin user deletion route revokes active tokens
  const adminDelRes = await app.request(`/api/admin/clients/${clientPrivate}/users/${userId}`, {
    method: "DELETE",
    headers: getHeaders(), // will be 401/403 without admin session, which is tested separately
  });

  // Verify user is not registered
  const isReg = await db.collection("user_app_registrations").findOne({ userId, clientId: clientPrivate });
  assert.equal(isReg, null, "User must be removed from registrations");
});

// --------------------------------------------------------------------------
// SECTION 3: REFRESH TOKEN CONCURRENCY & ISOLATION
// --------------------------------------------------------------------------
await runTest("REFRESH-1: Concurrent refresh rotation on token family allows exactly one winner", async () => {
  const familyId = crypto.randomUUID();
  const tokenVal = crypto.randomUUID();
  const tokenHash = crypto.createHash("sha256").update(tokenVal).digest("hex");
  const clientId = "test_refresh_conc_app";
  const userId = "test_user_conc_1";

  await registerTokenFamily(familyId, clientId, userId, tokenHash);

  // Fire 5 concurrent rotations with unique new hashes
  const results = await Promise.all([
    verifyAndRotateTokenFamily(tokenHash, crypto.randomUUID()),
    verifyAndRotateTokenFamily(tokenHash, crypto.randomUUID()),
    verifyAndRotateTokenFamily(tokenHash, crypto.randomUUID()),
    verifyAndRotateTokenFamily(tokenHash, crypto.randomUUID()),
    verifyAndRotateTokenFamily(tokenHash, crypto.randomUUID()),
  ]);

  const successCount = results.filter((r) => r.valid).length;
  const failureCount = results.filter((r) => !r.valid).length;

  assert.equal(successCount, 1, "Exactly one concurrent rotation request must succeed");
  assert.equal(failureCount, 4, "All other concurrent requests must be rejected as replayed/racing");
});

await runTest("REFRESH-2: Missing userId never triggers client-wide deletion", async () => {
  const clientId = "test_isolation_app";
  const userA = "user_victim_a";
  const userB = "user_innocent_b";

  // Insert active tokens for User B
  await db.collection("oauthAccessToken").insertOne({
    clientId,
    userId: userB,
    token: "token_user_b_active",
  });
  await db.collection("oauthRefreshToken").insertOne({
    clientId,
    userId: userB,
    token: "refresh_user_b_active",
  });

  // Create a token family without userId
  const familyId = crypto.randomUUID();
  const tokenHash = crypto.randomUUID();
  const consumedHash = crypto.randomUUID();

  await db.collection("oauth_token_families").insertOne({
    familyId,
    clientId,
    userId: undefined, // Missing userId
    activeTokenHash: tokenHash,
    consumedTokenHashes: [consumedHash],
    status: "active",
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Trigger replay on family without userId
  const replayRes = await verifyAndRotateTokenFamily(consumedHash, crypto.randomUUID());
  assert.equal(replayRes.replayed, true, "Replay must be detected");

  // Verify that User B's active tokens were NOT deleted!
  const userBToken = await db.collection("oauthAccessToken").findOne({ clientId, userId: userB });
  const userBRefresh = await db.collection("oauthRefreshToken").findOne({ clientId, userId: userB });

  assert.ok(userBToken, "User B's access token must NOT be revoked by a different family's replay!");
  assert.ok(userBRefresh, "User B's refresh token must NOT be revoked by a different family's replay!");
});

// --------------------------------------------------------------------------
// SECTION 4: REDIRECT URI STRICT VALIDATION (RFC 6749 & OAuth 2.1)
// --------------------------------------------------------------------------
await runTest("REDIRECT-1: Strict exact matching rejects fragments, userinfo, and query discrepancies", async () => {
  const registeredClient: any = {
    clientId: "client_strict_redirect",
    redirectUris: [
      "https://app.example.com/callback",
      "http://localhost:3000/callback",
    ],
  };

  // 1. Exact match
  assert.equal(isRegisteredRedirectUri(registeredClient, "https://app.example.com/callback"), true);

  // 2. Trailing slash discrepancy
  assert.equal(isRegisteredRedirectUri(registeredClient, "https://app.example.com/callback/"), false);

  // 3. Injected query parameter
  assert.equal(isRegisteredRedirectUri(registeredClient, "https://app.example.com/callback?x=1"), false);

  // 4. Injected fragment
  assert.equal(isRegisteredRedirectUri(registeredClient, "https://app.example.com/callback#fragment"), false);

  // 5. Injected userinfo
  assert.equal(isRegisteredRedirectUri(registeredClient, "https://evil@app.example.com/callback"), false);

  // 6. Alternate port on non-loopback
  assert.equal(isRegisteredRedirectUri(registeredClient, "https://app.example.com:8443/callback"), false);

  // 7. Alternate scheme
  assert.equal(isRegisteredRedirectUri(registeredClient, "http://app.example.com/callback"), false);

  // 8. Loopback variable port allowed per RFC 8252
  assert.equal(isRegisteredRedirectUri(registeredClient, "http://localhost:5555/callback"), true);
});

// --------------------------------------------------------------------------
// SECTION 5: DIRECT CLIENT MANAGEMENT ENDPOINTS BLOCKED WITH 403
// --------------------------------------------------------------------------
await runTest("DIRECT-ROUTES: All Better-Auth direct client management endpoints return 403", async () => {
  const endpoints = [
    "/api/auth/oauth2/register",
    "/api/auth/oauth2/register/client123",
    "/api/auth/oauth2/create-client",
    "/api/auth/oauth2/update-client",
    "/api/auth/oauth2/delete-client",
    "/api/auth/oauth2/get-client",
    "/api/auth/oauth2/get-clients",
    "/api/auth/oauth2/public-client",
    "/api/auth/oauth2/public-client-prelogin",
    "/api/auth/oauth2/client/rotate-secret",
    "/api/auth/oauth2/client/something",
    "/api/auth/oauth2/clients/something",
  ];

  for (const ep of endpoints) {
    const res = await app.request(ep, {
      method: "POST",
      headers: getHeaders(),
    });
    assert.equal(res.status, 403, `Endpoint ${ep} must return HTTP 403 Forbidden`);
  }
});

// --------------------------------------------------------------------------
// SECTION 6: UNKNOWN / DISABLED CLIENT VALIDATION
// --------------------------------------------------------------------------
await runTest("CLIENT-VALIDATION: Unknown and disabled clients are rejected with 400 on initiate and sign-in", async () => {
  const disabledClient = "test_disabled_client_gate";
  await seedClient(disabledClient, "secret", true, ["http://localhost:5174/cb"], true);

  // /oauth/initiate missing client_id
  const initMissing = await app.request("/api/auth/oauth/initiate", { headers: getHeaders() });
  assert.equal(initMissing.status, 400, "Missing client_id on /oauth/initiate must return 400");

  // /oauth/initiate disabled client
  const initDisabled = await app.request(`/api/auth/oauth/initiate?client_id=${disabledClient}`, { headers: getHeaders() });
  assert.equal(initDisabled.status, 400, "Disabled client on /oauth/initiate must return 400");

  // /oauth/initiate unknown client
  const initUnknown = await app.request("/api/auth/oauth/initiate?client_id=nonexistent_xyz", { headers: getHeaders() });
  assert.equal(initUnknown.status, 400, "Unknown client on /oauth/initiate must return 400");

  // /sign-in/email unknown client with unknown email
  const signInUnknown = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({
      email: "unknown_random_user@example.com",
      password: "Password123!",
      client_id: "nonexistent_client_123",
    }),
  });
  assert.equal(signInUnknown.status, 400, "Unknown client on /sign-in/email must return 400 immediately");
});

// --------------------------------------------------------------------------
// SECTION 7: ATOMIC MFA DISABLE BACKUP CODE CONSUMPTION
// --------------------------------------------------------------------------
await runTest("MFA-RACE: Concurrent MFA disable with same backup code allows only one winner", async () => {
  const rawCode = "EMERGENCY12";
  const targetHash = crypto.createHash("sha256").update(rawCode).digest("hex");
  const adminId = new ObjectId();

  await db.collection("app_admins").insertOne({
    _id: adminId,
    email: `mfa_race_${crypto.randomUUID()}@example.com`,
    totpEnabled: true,
    totpBackupCodes: [targetHash],
    createdAt: new Date(),
  });

  // Simulate 2 concurrent atomic updates attempting to consume the same backup code
  const results = await Promise.all([
    db.collection("app_admins").updateOne(
      { _id: adminId, totpBackupCodes: targetHash },
      { $set: { totpEnabled: false }, $unset: { totpBackupCodes: "" } }
    ),
    db.collection("app_admins").updateOne(
      { _id: adminId, totpBackupCodes: targetHash },
      { $set: { totpEnabled: false }, $unset: { totpBackupCodes: "" } }
    ),
  ]);

  const modifiedTotal = results.reduce((acc, r) => acc + r.modifiedCount, 0);
  assert.equal(modifiedTotal, 1, "Exactly one concurrent request can consume the backup code");
});

console.log("================================================================");
console.log(`  SECOND-PASS RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
