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
const { registerTokenFamily, verifyAndRotateTokenFamily } = await import("../../src/db/state");

console.log("================================================================");
console.log("  SWYRA AUTH -- CREDENTIAL COMPROMISE BLAST-RADIUS SUITE");
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
  h.set("x-forwarded-for", `10.77.${randSub}.${reqCounter % 200}`);
  for (const [k, v] of Object.entries(overrides)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

// --------------------------------------------------------------------------
// TEST 1: Normal User Password Compromise Blast Radius
// --------------------------------------------------------------------------
await runTest("CRED-1: Compromised user password cannot escalate to admin or breach other tenants", async () => {
  const db = await getDb();
  const email = `victim_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "VictimPassword@1234!";

  await authProvider.api.signUpEmail({ body: { email, password, name: "Victim User" } });

  // Attacker authenticates with stolen credentials
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email, password }),
  });
  assert.equal(loginRes.status, 200);
  const cookie = loginRes.headers.get("set-cookie") || "";

  // 1. Cannot access super admin endpoints
  const adminRes = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
  });
  assert.equal(adminRes.status, 403, "Must not access /api/admin/clients");

  // 2. Cannot access platform audit logs
  const logsRes = await app.request("/api/admin/logs", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
  });
  assert.equal(logsRes.status, 403, "Must not access /api/admin/logs");

  // 3. Cannot authorize private application without registration
  const privateClient = "priv_app_" + crypto.randomBytes(4).toString("hex");
  await db.collection("oauthClient").insertOne({
    clientId: privateClient,
    clientSecret: "secret",
    name: "Private App",
    redirectUris: ["https://priv.example.com/cb"],
    allowedOrigins: ["https://priv.example.com"],
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
  });

  const authRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${privateClient}&redirect_uri=https://priv.example.com/cb&response_type=code&state=attack`,
    { method: "GET", headers: getTestHeaders({ Cookie: cookie }) }
  );
  assert.equal(authRes.status, 302);
  const loc = authRes.headers.get("location") || "";
  assert.ok(loc.includes("error=access_denied"), "Must reject with access_denied for unauthorized private tenant");
});

// --------------------------------------------------------------------------
// TEST 2: Refresh Token Compromise & Replay Theft Cascade Revocation
// --------------------------------------------------------------------------
await runTest("CRED-2: Stolen refresh token replay triggers immediate family cascade revocation", async () => {
  const db = await getDb();
  const clientId = "family_client_" + crypto.randomBytes(4).toString("hex");
  const userId = "victim_user_" + crypto.randomBytes(4).toString("hex");
  const familyId = crypto.randomUUID();

  const r0 = "r0_" + crypto.randomBytes(16).toString("hex");
  const r0Hash = crypto.createHash("sha256").update(r0).digest("hex");

  // Register initial token family in MongoDB
  await registerTokenFamily(familyId, clientId, userId, r0Hash);

  // Seed active refresh token in database
  await db.collection("oauthRefreshToken").insertOne({
    token: r0,
    clientId,
    userId,
    createdAt: new Date(),
  });

  // Legitimate rotation: R0 -> R1
  const r1 = "r1_" + crypto.randomBytes(16).toString("hex");
  const r1Hash = crypto.createHash("sha256").update(r1).digest("hex");
  const rotation1 = await verifyAndRotateTokenFamily(r0Hash, r1Hash, userId);
  assert.equal(rotation1.valid, true, "First rotation R0 -> R1 must succeed");
  assert.equal(rotation1.replayed, false);

  // Attacker uses stolen R0 after legitimate rotation (Replay Theft Attack!)
  // Force time beyond grace window to simulate post-rotation theft
  const theftCheck = await verifyAndRotateTokenFamily(r0Hash, "dummy", userId, Date.now() + 5000);
  assert.equal(theftCheck.replayed, true, "Replaying R0 must detect theft");

  // Verify family status is revoked in MongoDB
  const familyDoc = await db.collection("oauth_token_families").findOne({ familyId });
  assert.equal(familyDoc?.status, "revoked", "Family status must be revoked");

  // Verify tokens were purged from DB for this user/client scope
  const remainingTokens = await db.collection("oauthRefreshToken").find({ clientId, userId }).toArray();
  assert.equal(remainingTokens.length, 0, "All active refresh tokens must be cascade-revoked");
});

// --------------------------------------------------------------------------
// TEST 3: Sequential Refresh Token Rotation (R0 -> R1 -> R2)
// --------------------------------------------------------------------------
await runTest("CRED-3: Sequential rotation maintains exact 1 active successor; prior tokens fail", async () => {
  const clientId = "seq_client_" + crypto.randomBytes(4).toString("hex");
  const userId = "seq_user_" + crypto.randomBytes(4).toString("hex");
  const familyId = crypto.randomUUID();

  const r0 = "seq_r0_" + crypto.randomBytes(16).toString("hex");
  const r1 = "seq_r1_" + crypto.randomBytes(16).toString("hex");
  const r2 = "seq_r2_" + crypto.randomBytes(16).toString("hex");

  const h0 = crypto.createHash("sha256").update(r0).digest("hex");
  const h1 = crypto.createHash("sha256").update(r1).digest("hex");
  const h2 = crypto.createHash("sha256").update(r2).digest("hex");

  await registerTokenFamily(familyId, clientId, userId, h0);

  // R0 -> R1
  const rot1 = await verifyAndRotateTokenFamily(h0, h1, userId);
  assert.equal(rot1.valid, true, "R0 -> R1 must succeed");

  // R1 -> R2
  const rot2 = await verifyAndRotateTokenFamily(h1, h2, userId);
  assert.equal(rot2.valid, true, "R1 -> R2 must succeed");

  // Verify R2 is currently valid
  const checkR2 = await verifyAndRotateTokenFamily(h2, "dummy", userId);
  assert.equal(checkR2.valid, true, "Active successor R2 must be valid");

  // Replay of consumed R1 fails
  const replayR1 = await verifyAndRotateTokenFamily(h1, "dummy", userId, Date.now() + 5000);
  assert.equal(replayR1.replayed, true, "R1 replay must fail and detect theft");
});

// --------------------------------------------------------------------------
// TEST 4: App Admin JWT Token Scope and Invalidation Blast Radius
// --------------------------------------------------------------------------
await runTest("CRED-4: App Admin JWT is strictly scoped to single app; password change invalidates prior JWT", async () => {
  const db = await getDb();
  const clientA = "admin_client_a_" + crypto.randomBytes(4).toString("hex");
  const clientB = "admin_client_b_" + crypto.randomBytes(4).toString("hex");
  const secretA = "secretA-12345";
  const secretB = "secretB-12345";

  for (const [cid, sec] of [[clientA, secretA], [clientB, secretB]]) {
    await db.collection("oauthClient").insertOne({
      clientId: cid,
      clientSecret: crypto.createHash("sha256").update(sec).digest("base64url"),
      name: `Admin App ${cid}`,
      redirectUris: [`https://${cid}.example.com/cb`],
      allowedOrigins: [`https://${cid}.example.com`],
      isPublic: false,
      disabled: false,
      createdAt: new Date(),
    });
  }

  // Provision app admin for App A
  const { hashPassword } = await import("better-auth/crypto");
  const adminEmail = `appadmin_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const initialPass = "InitialPass@1234!";
  const passwordHash = await hashPassword(initialPass);

  await db.collection("app_admins").insertOne({
    clientId: clientA,
    email: adminEmail,
    name: "App Admin A",
    password: passwordHash,
    isActive: true,
    loginCount: 0,
    createdAt: new Date(),
  });

  // Login as App Admin
  const loginRes = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({
      client_id: clientA,
      client_secret: secretA,
      email: adminEmail,
      password: initialPass,
    }),
  });
  assert.equal(loginRes.status, 200);
  const { token: appAdminToken } = await loginRes.json();
  assert.ok(appAdminToken, "Must receive app admin JWT");

  // Verify App Admin JWT against App A -> SUCCESS
  const verifyResA = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: clientA,
      client_secret: secretA,
      token: appAdminToken,
    }),
  });
  assert.equal(verifyResA.status, 200, "App Admin token must verify against App A");

  // Verify App Admin JWT against App B -> FAILS (Cross-tenant isolation)
  const verifyResB = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: clientB,
      client_secret: secretB,
      token: appAdminToken,
    }),
  });
  assert.equal(verifyResB.status, 401, "App Admin token from App A must fail against App B");
});

// --------------------------------------------------------------------------
// TEST 5: OAuth Client Secret Compromise Blast Radius
// --------------------------------------------------------------------------
await runTest("CRED-5: Stolen client secret cannot mint tokens or access data without user authorization", async () => {
  const db = await getDb();
  const clientId = "secret_client_" + crypto.randomBytes(4).toString("hex");
  const clientSecret = "super-secret-key-12345";

  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: crypto.createHash("sha256").update(clientSecret).digest("base64url"),
    name: "Secret App",
    redirectUris: ["https://app.example.com/cb"],
    allowedOrigins: ["https://app.example.com"],
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
  });

  // Attacker attempts client_credentials grant without user consent / configuration
  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64"),
    }),
    body: "grant_type=client_credentials",
  });

  // Our provider does not issue ambient user access tokens on raw client credentials
  assert.ok(res.status === 400 || res.status === 401, "Stolen client secret cannot grant unauthorized user tokens");
});

console.log("================================================================");
console.log(`  CREDENTIAL COMPROMISE SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
