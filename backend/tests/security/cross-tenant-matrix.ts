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
const { registerTokenFamily } = await import("../../src/db/state");
const { hashPassword } = await import("better-auth/crypto");

console.log("================================================================");
console.log("  SWYRA AUTH -- CROSS-TENANT ISOLATION MATRIX SUITE");
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
  h.set("x-forwarded-for", `10.66.${randSub}.${reqCounter % 200}`);
  for (const [k, v] of Object.entries(overrides)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

// --------------------------------------------------------------------------
// Setup 3 Independent Tenant Applications: Tenant A, Tenant B, Tenant C
// --------------------------------------------------------------------------
const db = await getDb();
const tenantA = "tenant_a_" + crypto.randomBytes(4).toString("hex");
const tenantB = "tenant_b_" + crypto.randomBytes(4).toString("hex");
const tenantC = "tenant_c_" + crypto.randomBytes(4).toString("hex");

const secretA = "secretA-super-key-123";
const secretB = "secretB-super-key-456";
const secretC = "secretC-super-key-789";

for (const [cid, sec, isPublic] of [
  [tenantA, secretA, false],
  [tenantB, secretB, false],
  [tenantC, secretC, true],
] as const) {
  await db.collection("oauthClient").insertOne({
    clientId: cid,
    clientSecret: crypto.createHash("sha256").update(sec).digest("base64url"),
    name: `App ${cid}`,
    redirectUris: [`https://${cid}.example.com/cb`],
    allowedOrigins: [`https://${cid}.example.com`],
    isPublic,
    disabled: false,
    createdAt: new Date(),
  });
}

// --------------------------------------------------------------------------
// TEST 1: Refresh Token Cross-Tenant Rejection
// --------------------------------------------------------------------------
await runTest("X-TENANT-1: Tenant A refresh token cannot be rotated using Tenant B credentials", async () => {
  const rToken = "ref_token_a_" + crypto.randomBytes(16).toString("hex");
  const rHash = crypto.createHash("sha256").update(rToken).digest("hex");
  const familyId = crypto.randomUUID();

  // Register token family bound to Tenant A
  await registerTokenFamily(familyId, tenantA, "user-123", rHash);

  await db.collection("oauthRefreshToken").insertOne({
    token: rToken,
    clientId: tenantA,
    userId: "user-123",
    createdAt: new Date(),
  });

  // Attempt to refresh token using Tenant B client credentials
  const refreshRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${tenantB}:${secretB}`).toString("base64"),
    }),
    body: `grant_type=refresh_token&refresh_token=${rToken}`,
  });

  assert.ok(
    refreshRes.status === 400 || refreshRes.status === 401,
    `Cross-tenant refresh must fail with 400/401, got ${refreshRes.status}`
  );
  const data = await refreshRes.json();
  assert.equal(data.error, "invalid_grant");
});

// --------------------------------------------------------------------------
// TEST 2: Authorization Code Cross-Tenant Rejection
// --------------------------------------------------------------------------
await runTest("X-TENANT-2: Authorization code issued to Tenant A cannot be exchanged by Tenant B", async () => {
  const code = "auth_code_a_" + crypto.randomBytes(16).toString("hex");

  await db.collection("oauthAuthorizationCode").insertOne({
    code,
    clientId: tenantA,
    redirectUri: `https://${tenantA}.example.com/cb`,
    expiresAt: new Date(Date.now() + 300 * 1000),
    userId: "user-456",
    createdAt: new Date(),
  });

  // Exchange using Tenant B credentials
  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${tenantB}:${secretB}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=https://${tenantA}.example.com/cb`,
  });

  assert.ok(res.status === 400 || res.status === 401, "Cross-tenant code exchange must fail");
  const data = await res.json();
  assert.ok(data.error === "invalid_grant" || data.error === "invalid_request");
});

// --------------------------------------------------------------------------
// TEST 3: App Admin JWT Cross-Tenant Verification
// --------------------------------------------------------------------------
await runTest("X-TENANT-3: App Admin JWT for Tenant A is strictly rejected by Tenant B verify API", async () => {
  const adminEmail = `admin_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const adminPass = "AdminPassword@1234!";
  const passHash = await hashPassword(adminPass);

  await db.collection("app_admins").insertOne({
    clientId: tenantA,
    email: adminEmail,
    name: "Admin Tenant A",
    password: passHash,
    isActive: true,
    loginCount: 0,
    createdAt: new Date(),
  });

  // Login as Tenant A Admin
  const loginRes = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({
      client_id: tenantA,
      client_secret: secretA,
      email: adminEmail,
      password: adminPass,
    }),
  });
  assert.equal(loginRes.status, 200);
  const { token } = await loginRes.json();

  // Present Tenant A token to Tenant B
  const verifyRes = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: tenantB,
      client_secret: secretB,
      token,
    }),
  });
  assert.equal(verifyRes.status, 401, "Tenant A admin JWT must fail verification for Tenant B");
  const data = await verifyRes.json();
  assert.equal(data.valid, false);
});

// --------------------------------------------------------------------------
// TEST 4: Scoped Admin IDOR Across Tenants
// --------------------------------------------------------------------------
await runTest("X-TENANT-4: Scoped Admin for Tenant A cannot read, edit, or delete Tenant B", async () => {
  const scopedAdminEmail = `scoped_admin_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const scopedAdminPass = "ScopedAdmin@1234!";

  await authProvider.api.signUpEmail({
    body: { email: scopedAdminEmail, password: scopedAdminPass, name: "Scoped Admin" },
  });
  await db.collection("user").updateOne(
    { email: scopedAdminEmail },
    { $set: { role: "admin", scopedClientId: tenantA } }
  );

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email: scopedAdminEmail, password: scopedAdminPass }),
  });
  const cookie = loginRes.headers.get("set-cookie") || "";

  // Attempt 1: Read Tenant B details
  const readRes = await app.request(`/api/admin/clients/${tenantB}`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
  });
  assert.equal(readRes.status, 403, "Cannot read Tenant B client (403)");

  // Attempt 2: Modify Tenant B configuration
  const patchRes = await app.request(`/api/admin/clients/${tenantB}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
    body: JSON.stringify({ name: "Hacked Tenant B" }),
  });
  assert.equal(patchRes.status, 403, "Cannot modify Tenant B client (403)");

  // Attempt 3: Delete Tenant B
  const delRes = await app.request(`/api/admin/clients/${tenantB}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
  });
  assert.equal(delRes.status, 403, "Cannot delete Tenant B client (403)");

  // Attempt 4: Read Tenant B users
  const usersRes = await app.request(`/api/admin/clients/${tenantB}/users`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
  });
  assert.equal(usersRes.status, 403, "Cannot read Tenant B users (403)");
});

// --------------------------------------------------------------------------
// TEST 5: Private Tenant Registration Isolation
// --------------------------------------------------------------------------
await runTest("X-TENANT-5: User registered for Tenant A strictly denied on private Tenant B", async () => {
  const userEmail = `tenant_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const userPass = "Password@1234!";

  const user = await authProvider.api.signUpEmail({
    body: { email: userEmail, password: userPass, name: "Tenant User" },
  });
  const userId = String((user as any).user.id);

  // Register user for Tenant A ONLY
  await db.collection("user_app_registrations").insertOne({
    userId,
    clientId: tenantA,
    registeredAt: new Date(),
  });

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email: userEmail, password: userPass }),
  });
  const cookie = loginRes.headers.get("set-cookie") || "";

  // Authorize Tenant A -> SUCCESS (302 with code)
  const authResA = await app.request(
    `/api/auth/oauth2/authorize?client_id=${tenantA}&redirect_uri=https://${tenantA}.example.com/cb&response_type=code&state=legit123`,
    { method: "GET", headers: getTestHeaders({ Cookie: cookie }) }
  );
  // Either 302 to redirectUri or consent
  assert.ok(authResA.status === 302 || authResA.status === 200);

  // Authorize Tenant B -> DENIED (302 with error=access_denied)
  const authResB = await app.request(
    `/api/auth/oauth2/authorize?client_id=${tenantB}&redirect_uri=https://${tenantB}.example.com/cb&response_type=code&state=attack123`,
    { method: "GET", headers: getTestHeaders({ Cookie: cookie }) }
  );
  assert.equal(authResB.status, 302);
  const locationB = authResB.headers.get("location") || "";
  assert.ok(locationB.includes("error=access_denied"), "Tenant B authorization must return access_denied");
});

console.log("================================================================");
console.log(`  CROSS-TENANT MATRIX RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
