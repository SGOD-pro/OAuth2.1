import dotenv from "dotenv";
dotenv.config();

import assert from "node:assert/strict";
import crypto from "crypto";
import { ObjectId } from "mongodb";

// Configure test environment
process.env.NODE_ENV = "test";
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "https://auth.example.com";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "https://app.example.com";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32";
process.env.APP_ADMIN_JWT_SECRET = process.env.APP_ADMIN_JWT_SECRET || "b".repeat(32);
process.env.APP_ADMIN_TOTP_KEY = process.env.APP_ADMIN_TOTP_KEY || "c".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "test_adversarial_gateway_secret_32_characters";

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");
const { registerTokenFamily, verifyAndRotateTokenFamily } = await import("../../src/db/state");

console.log("================================================================");
console.log("  SWYRA AUTH -- CROSS-CLIENT REFRESH TOKEN ISOLATION MATRIX");
console.log("  Verifying Cases 1 through 7 & Grace Window Determinism");
console.log("================================================================");

const db = await getDb();
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

let ipCounter = 200;
function getTestHeaders(overrides: Record<string, string> = {}) {
  const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
  return {
    "host": "auth.example.com",
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    "x-gateway-secret": process.env.INTERNAL_GATEWAY_SECRET || "test_adversarial_gateway_secret_32_characters",
    "Origin": process.env.FRONTEND_URL || "https://app.example.com",
    ...overrides,
  };
}

function generatePkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

async function seedOAuthClient(
  clientId: string,
  clientSecret: string,
  isPublic: boolean,
  redirectUris: string[]
) {
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
        isDev: false,
        is_dev: false,
        disabled: false,
        redirectUris,
        redirect_uris: redirectUris,
        allowedOrigins: ["https://app.example.com"],
        skipConsent: true,
        skip_consent: true,
        applicationType: "web",
        updatedAt: new Date(),
      },
    },
    { upsert: true }
  );
}

// --------------------------------------------------------------------------
// PROVISION TEST FIXTURES
// --------------------------------------------------------------------------
const testSuffix = crypto.randomBytes(4).toString("hex");
const appA_id = `cc_client_a_${testSuffix}`;
const appA_secret = `secret_a_${testSuffix}_12345`;
const appB_id = `cc_client_b_${testSuffix}`;
const appB_secret = `secret_b_${testSuffix}_12345`;
const redirectUriA = "https://app.example.com/callback-a";
const redirectUriB = "https://app.example.com/callback-b";

await seedOAuthClient(appA_id, appA_secret, false, [redirectUriA]);
await seedOAuthClient(appB_id, appB_secret, false, [redirectUriB]);

// Provision User 1 for Client A
const user1Email = `user1_${testSuffix}@example.com`;
const user1Pass = "User1Password@123!";
const u1Res = await authProvider.api.signUpEmail({
  body: { email: user1Email, password: user1Pass, name: "User One" },
  asResponse: true,
});
const user1Cookie = (u1Res.headers.get("set-cookie") || "").split(";")[0];
const user1Doc = await db.collection("user").findOne({ email: user1Email });
const user1Id = String(user1Doc?.id || user1Doc?._id);

await db.collection("user_app_registrations").insertOne({
  userId: user1Id,
  clientId: appA_id,
  registeredAt: new Date(),
});
await db.collection("user_app_registrations").insertOne({
  userId: user1Id,
  clientId: appB_id,
  registeredAt: new Date(),
});

const basicA = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
const basicB = Buffer.from(`${appB_id}:${appB_secret}`).toString("base64");

// Helper to obtain a full authorization code and initial refresh token for Client A
async function obtainClientAToken(): Promise<{ refreshToken: string; accessToken: string }> {
  const pkce = generatePkce();
  const state = crypto.randomBytes(16).toString("hex");
  const authUrl = `/api/auth/oauth2/authorize?response_type=code&client_id=${appA_id}&redirect_uri=${encodeURIComponent(
    redirectUriA
  )}&scope=openid%20profile%20email%20offline_access&state=${state}&code_challenge=${pkce.challenge}&code_challenge_method=S256`;

  const authRes = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders({ Cookie: user1Cookie }),
  });
  assert.equal(authRes.status, 302, "Authorize must redirect with 302");
  const loc = authRes.headers.get("location");
  assert.ok(loc, "Location header required on authorize redirect");
  const parsed = new URL(loc);
  const code = parsed.searchParams.get("code");
  assert.ok(code, "Auth code required in redirect URL");

  // Exchange code for tokens
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicA}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUriA,
      code_verifier: pkce.verifier,
    }).toString(),
  });
  assert.equal(tokenRes.status, 200, "Token exchange for Client A must succeed");
  const data = await tokenRes.json();
  assert.ok(data.refresh_token, "Client A must receive refresh_token");
  assert.ok(data.access_token, "Client A must receive access_token");
  return { refreshToken: data.refresh_token, accessToken: data.access_token };
}

let clientATokens = await obtainClientAToken();
let activeRefreshTokenA = clientATokens.refreshToken;
let consumedTokensA: string[] = [];

// ==========================================================================
// CASE 1: Client A Valid Active Refresh Token Presented with Client B Credentials
// ==========================================================================
await runTest("Case 1: Cross-client presentation of active token (App A token with App B credentials)", async () => {
  const tokenHash = crypto.createHash("sha256").update(activeRefreshTokenA).digest("hex");
  
  // Inspect DB state BEFORE attack
  const familyBefore = await db.collection("oauth_token_families").findOne({ activeTokenHash: tokenHash });
  assert.ok(familyBefore, "Client A family must exist before test");
  assert.equal(familyBefore.clientId, appA_id, "Family must belong to Client A");
  assert.equal(familyBefore.status, "active", "Family must be active before test");

  // Client B presents Client A's refresh token
  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicB}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: activeRefreshTokenA,
    }).toString(),
  });

  // Assertions on response
  assert.equal(res.status, 400, "Cross-client refresh MUST return HTTP 400");
  const json = await res.json();
  assert.equal(json.error, "invalid_grant", "OAuth error MUST be invalid_grant");
  assert.equal(json.access_token, undefined, "NO access token issued");
  assert.equal(json.refresh_token, undefined, "NO refresh token issued");

  // Inspect DB state AFTER attack: Client A's family must be completely untouched
  const familyAfter = await db.collection("oauth_token_families").findOne({ activeTokenHash: tokenHash });
  assert.ok(familyAfter, "Client A family must still exist");
  assert.equal(familyAfter.status, "active", "Client A family MUST remain active");
  assert.notEqual(familyAfter.rotating, true, "Client A family rotating MUST NOT be true");
  assert.equal(familyAfter.activeTokenHash, familyBefore.activeTokenHash, "Active token hash must be unchanged");
  assert.deepEqual(familyAfter.consumedTokenHashes, familyBefore.consumedTokenHashes, "Consumed token hashes must be unchanged");
  assert.equal(familyAfter.revokedAt, undefined, "Client A family must NOT have revokedAt set");
});

// ==========================================================================
// CASE 4: Same Client (Client A) with Valid Refresh Token Rotates Normally
// ==========================================================================
await runTest("Case 4: Same-client legitimate refresh succeeds (Client A with Client A credentials)", async () => {
  const oldHash = crypto.createHash("sha256").update(activeRefreshTokenA).digest("hex");

  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicA}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: activeRefreshTokenA,
    }).toString(),
  });

  assert.equal(res.status, 200, "Legitimate Client A refresh MUST succeed");
  const json = await res.json();
  assert.ok(json.access_token, "Must issue new access token");
  assert.ok(json.refresh_token, "Must issue new refresh token");
  assert.notEqual(json.refresh_token, activeRefreshTokenA, "Must rotate to a distinct refresh token");

  // Record old token as consumed, update active token
  consumedTokensA.push(activeRefreshTokenA);
  activeRefreshTokenA = json.refresh_token;

  // Verify DB state
  const newHash = crypto.createHash("sha256").update(activeRefreshTokenA).digest("hex");
  const familyDoc = await db.collection("oauth_token_families").findOne({ activeTokenHash: newHash });
  assert.ok(familyDoc, "Family document must have new activeTokenHash");
  assert.equal(familyDoc.clientId, appA_id, "Family must belong to Client A");
  assert.equal(familyDoc.status, "active", "Family must remain active");
  assert.ok(familyDoc.consumedTokenHashes.includes(oldHash), "consumedTokenHashes must include oldHash");
});

// ==========================================================================
// CASE 2: Attack against Consumed Token (App A Consumed Token Presented to App B)
// ==========================================================================
await runTest("Case 2: Cross-client presentation of consumed token does not mutate or revoke victim family", async () => {
  const consumedToken = consumedTokensA[0];
  assert.ok(consumedToken, "Must have a consumed token from Case 4");
  const activeHash = crypto.createHash("sha256").update(activeRefreshTokenA).digest("hex");

  // Client B attempts to refresh using Client A's previously consumed token
  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicB}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: consumedToken,
    }).toString(),
  });

  assert.equal(res.status, 400, "Cross-client consumed token refresh MUST return HTTP 400");
  const json = await res.json();
  assert.equal(json.error, "invalid_grant", "OAuth error MUST be invalid_grant");

  // CRITICAL: Client A's family must NOT be cascade-revoked merely because Client B presented its consumed token!
  const familyAfter = await db.collection("oauth_token_families").findOne({ activeTokenHash: activeHash });
  assert.ok(familyAfter, "Client A family must still exist");
  assert.equal(familyAfter.status, "active", "Client A family MUST remain active (NOT cascade-revoked)");

  // Client A's active tokens must still be valid
  const activeTokensInDb = await db.collection("oauthRefreshToken").find({
    clientId: appA_id,
    userId: { $in: [user1Id, new ObjectId(user1Id)] },
    $or: [{ revoked: null }, { revoked: false }, { revoked: { $exists: false } }],
  }).toArray();
  assert.ok(activeTokensInDb.length > 0, "Client A's active refresh tokens must NOT have been deleted");
});

// ==========================================================================
// CASE 3: Wrong Client Context, Missing Client, Invalid Client ID
// ==========================================================================
await runTest("Case 3A: Unknown non-existent client ID with valid refresh token", async () => {
  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: "non_existent_client_xyz",
      client_secret: "some_secret_12345",
      refresh_token: activeRefreshTokenA,
    }).toString(),
  });

  assert.equal(res.status, 400, "Unknown client MUST be rejected with HTTP 400");
  const json = await res.json();
  assert.equal(json.error, "invalid_client", "Error must be invalid_client");

  // Victim family remains untouched
  const activeHash = crypto.createHash("sha256").update(activeRefreshTokenA).digest("hex");
  const family = await db.collection("oauth_token_families").findOne({ activeTokenHash: activeHash });
  assert.equal(family?.status, "active", "Victim family must remain active");
});

await runTest("Case 3B: Missing client authentication with valid refresh token", async () => {
  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: activeRefreshTokenA,
    }).toString(),
  });

  assert.equal(res.status, 400, "Missing client credentials MUST be rejected with HTTP 400");
  const json = await res.json();
  assert.equal(json.error, "invalid_client", "Error must be invalid_client");
});

// ==========================================================================
// CASE 5: Concurrent Same-Client Refresh Requests (Atomic CAS Race Invariant)
// ==========================================================================
await runTest("Case 5: Concurrent same-client refresh: exactly 1 winner rotates, 4 losers rejected, family remains active", async () => {
  const tokenToRace = activeRefreshTokenA;
  const oldActiveHash = crypto.createHash("sha256").update(tokenToRace).digest("hex");

  const promises = Array.from({ length: 5 }, () =>
    app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        Authorization: `Basic ${basicA}`,
        "Content-Type": "application/x-www-form-urlencoded",
      }),
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokenToRace,
      }).toString(),
    })
  );

  const responses = await Promise.all(promises);
  const statuses = responses.map((r) => r.status);
  const successCount = statuses.filter((s) => s === 200).length;
  const failureCount = statuses.filter((s) => s >= 400).length;

  assert.equal(successCount, 1, `Expected exactly 1 winner out of 5 concurrent requests, got ${successCount}`);
  assert.equal(failureCount, 4, `Expected exactly 4 losers out of 5 concurrent requests, got ${failureCount}`);

  const winnerRes = responses.find((r) => r.status === 200)!;
  const winnerJson = await winnerRes.json();
  assert.ok(winnerJson.refresh_token, "Winner must receive rotated refresh token");
  activeRefreshTokenA = winnerJson.refresh_token;

  const winnerHash = crypto.createHash("sha256").update(activeRefreshTokenA).digest("hex");
  const familyDoc = await db.collection("oauth_token_families").findOne({ activeTokenHash: winnerHash });
  assert.ok(familyDoc, "Family doc must be updated to winner's token hash");
  assert.equal(familyDoc.status, "active", "Family must remain active after race");
  assert.ok(familyDoc.consumedTokenHashes.includes(oldActiveHash), "consumedTokenHashes must contain oldActiveHash");
});

// ==========================================================================
// CASE 6: Direct verifyAndRotateTokenFamily Boundary & Cross-Client Isolation
// ==========================================================================
await runTest("Case 6: Direct verifyAndRotateTokenFamily rejects cross-client caller without mutating family", async () => {
  const victimFamilyId = `victim_fam_${crypto.randomBytes(4).toString("hex")}`;
  const victimActiveHash = crypto.createHash("sha256").update("victim_active_token").digest("hex");
  const victimConsumedHash = crypto.createHash("sha256").update("victim_consumed_token").digest("hex");

  await db.collection("oauth_token_families").insertOne({
    familyId: victimFamilyId,
    clientId: appA_id,
    userId: user1Id,
    activeTokenHash: victimActiveHash,
    consumedTokenHashes: [victimConsumedHash],
    status: "active",
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Attacker Client B calls verifyAndRotateTokenFamily with victim's active token
  const attackActive = await verifyAndRotateTokenFamily(
    victimActiveHash,
    "attacker_new_hash",
    user1Id,
    Date.now(),
    appB_id // expectedClientId = Client B, but family belongs to Client A!
  );
  assert.equal(attackActive.valid, false, "Cross-client rotation must be invalid");
  assert.equal(attackActive.clientMismatch, true, "clientMismatch must be reported");

  // Verify victim family is UNCHANGED
  const checkActive = await db.collection("oauth_token_families").findOne({ familyId: victimFamilyId });
  assert.equal(checkActive?.status, "active", "Victim family must remain active");
  assert.equal(checkActive?.activeTokenHash, victimActiveHash, "Active token hash must remain unchanged");

  // Attacker Client B calls verifyAndRotateTokenFamily with victim's consumed token
  const attackConsumed = await verifyAndRotateTokenFamily(
    victimConsumedHash,
    "dummy",
    user1Id,
    Date.now() + 5000,
    appB_id
  );
  assert.equal(attackConsumed.valid, false, "Cross-client consumed check must be invalid");
  assert.equal(attackConsumed.clientMismatch, true, "clientMismatch must be reported");
  assert.equal(attackConsumed.replayed, false, "Must NOT be classified as a client-level replay");

  // Verify victim family is NOT cascade-revoked
  const checkConsumed = await db.collection("oauth_token_families").findOne({ familyId: victimFamilyId });
  assert.equal(checkConsumed?.status, "active", "Victim family must NOT be cascade-revoked by cross-client consumed call");

  await db.collection("oauth_token_families").deleteOne({ familyId: victimFamilyId });
});

// ==========================================================================
// CASE 7: Replay Grace Window Boundary Determinism (1999ms, 2000ms, 2001ms)
// ==========================================================================
await runTest("Case 7: Deterministic Grace Window: 1999ms in-flight collision vs 2000ms/2001ms replay theft", async () => {
  const baseTime = Date.now();

  // Fixture at 1999ms: In-flight collision, must NOT trigger replay revocation
  const fam1999Id = `gw_fam_1999_${crypto.randomBytes(4).toString("hex")}`;
  const consumed1999 = crypto.randomBytes(32).toString("hex");
  const active1999 = crypto.randomBytes(32).toString("hex");
  await db.collection("oauth_token_families").insertOne({
    familyId: fam1999Id,
    clientId: appA_id,
    userId: user1Id,
    activeTokenHash: active1999,
    consumedTokenHashes: [consumed1999],
    status: "active",
    createdAt: new Date(baseTime - 5000),
    updatedAt: new Date(baseTime),
  });

  const res1999 = await verifyAndRotateTokenFamily(consumed1999, "dummy", user1Id, baseTime + 1999, appA_id);
  assert.equal(res1999.replayed, false, "At 1999ms (within grace window): replayed must be false");
  const doc1999 = await db.collection("oauth_token_families").findOne({ familyId: fam1999Id });
  assert.equal(doc1999?.status, "active", "At 1999ms: family must remain active");

  // Fixture at 2000ms: Grace window ended, MUST trigger cascade revocation
  const fam2000Id = `gw_fam_2000_${crypto.randomBytes(4).toString("hex")}`;
  const consumed2000 = crypto.randomBytes(32).toString("hex");
  const active2000 = crypto.randomBytes(32).toString("hex");
  await db.collection("oauth_token_families").insertOne({
    familyId: fam2000Id,
    clientId: appA_id,
    userId: user1Id,
    activeTokenHash: active2000,
    consumedTokenHashes: [consumed2000],
    status: "active",
    createdAt: new Date(baseTime - 5000),
    updatedAt: new Date(baseTime),
  });

  const res2000 = await verifyAndRotateTokenFamily(consumed2000, "dummy", user1Id, baseTime + 2000, appA_id);
  assert.equal(res2000.replayed, true, "At 2000ms (grace window ended): replayed must be true");
  const doc2000 = await db.collection("oauth_token_families").findOne({ familyId: fam2000Id });
  assert.equal(doc2000?.status, "revoked", "At 2000ms: family must be marked revoked");

  // Fixture at 2001ms: Past grace window, MUST trigger cascade revocation
  const fam2001Id = `gw_fam_2001_${crypto.randomBytes(4).toString("hex")}`;
  const consumed2001 = crypto.randomBytes(32).toString("hex");
  const active2001 = crypto.randomBytes(32).toString("hex");
  await db.collection("oauth_token_families").insertOne({
    familyId: fam2001Id,
    clientId: appA_id,
    userId: user1Id,
    activeTokenHash: active2001,
    consumedTokenHashes: [consumed2001],
    status: "active",
    createdAt: new Date(baseTime - 5000),
    updatedAt: new Date(baseTime),
  });

  const res2001 = await verifyAndRotateTokenFamily(consumed2001, "dummy", user1Id, baseTime + 2001, appA_id);
  assert.equal(res2001.replayed, true, "At 2001ms (past grace window): replayed must be true");
  const doc2001 = await db.collection("oauth_token_families").findOne({ familyId: fam2001Id });
  assert.equal(doc2001?.status, "revoked", "At 2001ms: family must be marked revoked");

  // Clean up synthetic fixtures
  await db.collection("oauth_token_families").deleteMany({
    familyId: { $in: [fam1999Id, fam2000Id, fam2001Id] },
  });
});

// Cleanup test clients
await db.collection("oauthClient").deleteMany({ clientId: { $in: [appA_id, appB_id] } });
await db.collection("oauth_token_families").deleteMany({ clientId: { $in: [appA_id, appB_id] } });
await db.collection("user_app_registrations").deleteMany({ clientId: { $in: [appA_id, appB_id] } });

console.log("================================================================");
console.log(`  MATRIX SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
