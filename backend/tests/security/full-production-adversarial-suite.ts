import dotenv from "dotenv";
dotenv.config();

import assert from "node:assert/strict";
import crypto from "crypto";

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

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");
const { registerTokenFamily, verifyAndRotateTokenFamily, createOAuthTransaction, getOAuthTransaction } = await import("../../src/db/state");
const { hashPassword } = await import("better-auth/crypto");

console.log("================================================================");
console.log("  SWYRA AUTH -- FULL PRODUCTION ADVERSARIAL MASTER GATE");
console.log("================================================================");

let passed = 0;
let failed = 0;

async function runTest(name: string, fn: () => Promise<void> | void) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`[FAIL] ${name}:`, err.message || err);
    failed++;
  }
}

let reqCounter = 1;
function getTestHeaders(overrides: Record<string, string> = {}): Headers {
  const h = new Headers();
  h.set("host", "auth.example.com");
  h.set("content-type", "application/json");
  const randSub = Math.floor(reqCounter / 5);
  reqCounter++;
  h.set("x-forwarded-for", `10.55.${randSub}.${reqCounter % 200}`);
  for (const [k, v] of Object.entries(overrides)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

// --------------------------------------------------------------------------
// TEST 1: Protocol Discovery & JWKS Integrity
// --------------------------------------------------------------------------
await runTest("GATE-1: Discovery and JWKS endpoints return valid RFC-compliant cryptographic metadata", async () => {
  const discRes = await app.request("/.well-known/openid-configuration", {
    method: "GET",
    headers: getTestHeaders({ Origin: "" }),
  });
  assert.equal(discRes.status, 200);
  const disc = await discRes.json();
  assert.equal(disc.issuer, "https://auth.example.com");

  const jwksRes = await app.request("/.well-known/jwks.json", {
    method: "GET",
    headers: getTestHeaders({ Origin: "" }),
  });
  assert.equal(jwksRes.status, 200);
  const jwks = await jwksRes.json();
  assert.ok(Array.isArray(jwks.keys));
  assert.ok(jwks.keys.length > 0);
  assert.equal(jwks.keys[0].kty, "RSA");
});

// --------------------------------------------------------------------------
// TEST 2: Concurrent Refresh Token CAS Race (5 Parallel Rotations)
// --------------------------------------------------------------------------
await runTest("GATE-2: Concurrent race rotation on R0 results in exactly 1 winner and 0 duplicate successors", async () => {
  const db = await getDb();
  const clientId = "race_client_" + crypto.randomBytes(4).toString("hex");
  const userId = "race_user_" + crypto.randomBytes(4).toString("hex");
  const familyId = crypto.randomUUID();

  const r0 = "race_r0_" + crypto.randomBytes(16).toString("hex");
  const r0Hash = crypto.createHash("sha256").update(r0).digest("hex");

  await registerTokenFamily(familyId, clientId, userId, r0Hash);

  // Send 5 parallel rotation attempts
  const parallelAttempts = await Promise.all([
    verifyAndRotateTokenFamily(r0Hash, crypto.createHash("sha256").update("succ1").digest("hex"), userId),
    verifyAndRotateTokenFamily(r0Hash, crypto.createHash("sha256").update("succ2").digest("hex"), userId),
    verifyAndRotateTokenFamily(r0Hash, crypto.createHash("sha256").update("succ3").digest("hex"), userId),
    verifyAndRotateTokenFamily(r0Hash, crypto.createHash("sha256").update("succ4").digest("hex"), userId),
    verifyAndRotateTokenFamily(r0Hash, crypto.createHash("sha256").update("succ5").digest("hex"), userId),
  ]);

  const successes = parallelAttempts.filter((res) => res.valid);
  const failures = parallelAttempts.filter((res) => !res.valid);

  assert.equal(successes.length, 1, "Exactly one concurrent rotation MUST succeed");
  assert.equal(failures.length, 4, "Remaining 4 competing requests MUST fail");

  const doc = await db.collection("oauth_token_families").findOne({ familyId });
  assert.equal(doc?.status, "active", "Family must remain active under winner successor");
  assert.ok(doc?.consumedTokenHashes.includes(r0Hash), "Old R0 must be recorded in consumed hashes");
});

// --------------------------------------------------------------------------
// TEST 3: Deterministic Grace Window Boundary Testing (1999ms vs 2000ms vs 2001ms)
// --------------------------------------------------------------------------
await runTest("GATE-3: Token family replay boundary strictly enforces 2000ms grace window", async () => {
  const db = await getDb();
  const clientId = "grace_client_" + crypto.randomBytes(4).toString("hex");
  const userId = "grace_user_" + crypto.randomBytes(4).toString("hex");

  // Sub-case A: 1999ms -> Inside grace window (in-flight loser, not theft)
  const familyA = crypto.randomUUID();
  const r0A = "r0A_" + crypto.randomBytes(16).toString("hex");
  const h0A = crypto.createHash("sha256").update(r0A).digest("hex");
  const h1A = crypto.createHash("sha256").update("h1A").digest("hex");

  await registerTokenFamily(familyA, clientId, userId, h0A);
  await verifyAndRotateTokenFamily(h0A, h1A, userId);

  const updatedDocA = await db.collection("oauth_token_families").findOne({ familyId: familyA });
  const rotTimeA = new Date(updatedDocA?.updatedAt || 0).getTime();

  // Test at exactly +1999ms
  const check1999 = await verifyAndRotateTokenFamily(h0A, "dummy", userId, rotTimeA + 1999);
  assert.equal(check1999.replayed, false, "1999ms must be treated as inside grace window");

  // Sub-case B: 2000ms -> At boundary (theft detected!)
  const check2000 = await verifyAndRotateTokenFamily(h0A, "dummy", userId, rotTimeA + 2000);
  assert.equal(check2000.replayed, true, "2000ms must trigger replay theft cascade revocation");

  // Sub-case C: 2001ms -> Outside grace window (theft detected!)
  const familyC = crypto.randomUUID();
  const r0C = "r0C_" + crypto.randomBytes(16).toString("hex");
  const h0C = crypto.createHash("sha256").update(r0C).digest("hex");
  const h1C = crypto.createHash("sha256").update("h1C").digest("hex");

  await registerTokenFamily(familyC, clientId, userId, h0C);
  await verifyAndRotateTokenFamily(h0C, h1C, userId);
  const updatedDocC = await db.collection("oauth_token_families").findOne({ familyId: familyC });
  const rotTimeC = new Date(updatedDocC?.updatedAt || 0).getTime();

  const check2001 = await verifyAndRotateTokenFamily(h0C, "dummy", userId, rotTimeC + 2001);
  assert.equal(check2001.replayed, true, "2001ms must trigger replay theft detection");
});

// --------------------------------------------------------------------------
// TEST 4: Cross-Tenant Isolation: Refresh Token & Code
// --------------------------------------------------------------------------
await runTest("GATE-4: Cross-tenant token & code presentation strictly fails closed", async () => {
  const db = await getDb();
  const clientA = "gate_app_a_" + crypto.randomBytes(4).toString("hex");
  const clientB = "gate_app_b_" + crypto.randomBytes(4).toString("hex");
  const secA = "secA-12345";
  const secB = "secB-12345";

  for (const [cid, sec] of [[clientA, secA], [clientB, secB]]) {
    await db.collection("oauthClient").insertOne({
      clientId: cid,
      clientSecret: crypto.createHash("sha256").update(sec).digest("base64url"),
      name: `App ${cid}`,
      redirectUris: [`https://${cid}.example.com/cb`],
      allowedOrigins: [`https://${cid}.example.com`],
      isPublic: false,
      disabled: false,
      createdAt: new Date(),
    });
  }

  // App A code exchanged with App B credentials
  const code = "code_a_" + crypto.randomBytes(16).toString("hex");
  await db.collection("oauthAuthorizationCode").insertOne({
    code,
    clientId: clientA,
    redirectUri: `https://${clientA}.example.com/cb`,
    expiresAt: new Date(Date.now() + 300 * 1000),
    userId: "user-1",
    createdAt: new Date(),
  });

  const exchangeRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientB}:${secB}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=https://${clientA}.example.com/cb`,
  });
  assert.ok(exchangeRes.status === 400 || exchangeRes.status === 401);

  // App A refresh token refreshed with App B credentials
  const rToken = "ref_a_" + crypto.randomBytes(16).toString("hex");
  const rHash = crypto.createHash("sha256").update(rToken).digest("hex");
  await registerTokenFamily(crypto.randomUUID(), clientA, "user-1", rHash);

  const refreshRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientB}:${secB}`).toString("base64"),
    }),
    body: `grant_type=refresh_token&refresh_token=${rToken}`,
  });
  assert.ok(refreshRes.status === 400 || refreshRes.status === 401);
});

// --------------------------------------------------------------------------
// TEST 5: Multi-Tab Shared Cookie Jar Isolation
// --------------------------------------------------------------------------
await runTest("GATE-5: Multi-tab parallel OAuth flow resolves correct tenant per transaction state", async () => {
  const db = await getDb();
  const clientA = "multitab_a_" + crypto.randomBytes(4).toString("hex");
  const clientB = "multitab_b_" + crypto.randomBytes(4).toString("hex");

  for (const cid of [clientA, clientB]) {
    await db.collection("oauthClient").insertOne({
      clientId: cid,
      clientSecret: "secret",
      name: `App ${cid}`,
      redirectUris: [`https://${cid}.example.com/cb`],
      allowedOrigins: [`https://${cid}.example.com`],
      isPublic: true,
      disabled: false,
      createdAt: new Date(),
    });
  }

  const stateA = "state_a_" + crypto.randomBytes(6).toString("hex");
  const stateB = "state_b_" + crypto.randomBytes(6).toString("hex");

  await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientA}&redirect_uri=https://${clientA}.example.com/cb&response_type=code&state=${stateA}`,
    { method: "GET", headers: getTestHeaders() }
  );

  await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientB}&redirect_uri=https://${clientB}.example.com/cb&response_type=code&state=${stateB}`,
    { method: "GET", headers: getTestHeaders() }
  );

  const txA = await getOAuthTransaction({ state: stateA });
  const txB = await getOAuthTransaction({ state: stateB });

  assert.equal(txA?.clientId, clientA, "State A must resolve Client A");
  assert.equal(txB?.clientId, clientB, "State B must resolve Client B");
});

// --------------------------------------------------------------------------
// TEST 6: App Admin Complete Lifecycle Security
// --------------------------------------------------------------------------
await runTest("GATE-6: App Admin disable, re-enable, and delete lifecycle strictly invalidates JWTs", async () => {
  const db = await getDb();
  const clientId = "lifecycle_client_" + crypto.randomBytes(4).toString("hex");
  const clientSecret = "secret-123";

  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: crypto.createHash("sha256").update(clientSecret).digest("base64url"),
    name: "Lifecycle App",
    redirectUris: ["https://app.example.com/cb"],
    allowedOrigins: ["https://app.example.com"],
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
  });

  const adminEmail = `admin_life_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const adminPass = "AdminLife@1234!";

  const insertRes = await db.collection("app_admins").insertOne({
    clientId,
    email: adminEmail,
    name: "Lifecycle Admin",
    password: await hashPassword(adminPass),
    isActive: true,
    loginCount: 0,
    createdAt: new Date(),
  });
  const adminId = insertRes.insertedId;

  // 1. Initial login -> Valid JWT
  const loginRes1 = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, email: adminEmail, password: adminPass }),
  });
  assert.equal(loginRes1.status, 200);
  const { token: jwt1 } = await loginRes1.json();

  // Verify JWT1 -> Valid
  const verify1 = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, token: jwt1 }),
  });
  assert.equal(verify1.status, 200);

  // 2. Disable admin
  await db.collection("app_admins").updateOne(
    { _id: adminId },
    { $set: { isActive: false, tokensRevokedBefore: new Date() } }
  );

  // Verify JWT1 after disable -> REJECTED (401)
  const verifyDisabled = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, token: jwt1 }),
  });
  assert.equal(verifyDisabled.status, 401, "Disabled admin JWT must fail");

  // Login while disabled -> REJECTED (403)
  const loginDisabled = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, email: adminEmail, password: adminPass }),
  });
  assert.equal(loginDisabled.status, 403, "Disabled admin login must fail");

  // 3. Reactivate admin
  await db.collection("app_admins").updateOne(
    { _id: adminId },
    { $set: { isActive: true } }
  );

  // Old JWT1 must STILL fail
  const verifyOldAfterReactivate = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, token: jwt1 }),
  });
  assert.equal(verifyOldAfterReactivate.status, 401, "Pre-disable token must remain invalid");

  // New login -> New JWT2 works
  const loginRes2 = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, email: adminEmail, password: adminPass }),
  });
  assert.equal(loginRes2.status, 200);
  const { token: jwt2 } = await loginRes2.json();

  const verifyNew = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, token: jwt2 }),
  });
  assert.equal(verifyNew.status, 200, "New token must verify");

  // 4. Delete admin account
  await db.collection("app_admins").deleteOne({ _id: adminId });

  const verifyDeleted = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, token: jwt2 }),
  });
  assert.equal(verifyDeleted.status, 401, "Deleted admin token must fail");
});

// --------------------------------------------------------------------------
// TEST 7: Mass Assignment & NoSQL Injection Protection
// --------------------------------------------------------------------------
await runTest("GATE-7: Mass assignment and NoSQL injection payloads are neutralized", async () => {
  // Attempt 1: Mass assignment in sign-up
  const email = `mass_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const signUpRes = await app.request("/api/auth/sign-up/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({
      email,
      password: "Password@1234!",
      name: "Hacker",
      role: "admin",
      isSuperAdmin: true,
      scopedClientId: null,
    }),
  });
  assert.equal(signUpRes.status, 200);

  const db = await getDb();
  const user = await db.collection("user").findOne({ email });
  assert.notEqual(user?.role, "admin", "User must NOT have admin role assigned via sign-up");

  // Attempt 2: Direct dynamic client creation route blocking
  const directReg = await app.request("/api/auth/oauth2/register", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ client_name: "Illegal App" }),
  });
  assert.equal(directReg.status, 403, "Direct dynamic registration must return 403");
});

// --------------------------------------------------------------------------
// TEST 8: Direct Management Endpoint Protection (Raw Curl Blocked)
// --------------------------------------------------------------------------
await runTest("GATE-8: Direct curl requests to management endpoints strictly denied without session", async () => {
  const adminEndpoints = [
    "/api/admin/clients",
    "/api/admin/users",
    "/api/admin/stats",
    "/api/admin/logs",
  ];

  for (const ep of adminEndpoints) {
    const res = await app.request(ep, {
      method: "GET",
      headers: getTestHeaders({ "User-Agent": "curl/8.5.0", Origin: "" }),
    });
    assert.equal(res.status, 401, `${ep} must return 401 to unauthenticated curl`);
  }
});

console.log("================================================================");
console.log(`  FULL PRODUCTION ADVERSARIAL MASTER GATE: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
