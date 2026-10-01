import dotenv from "dotenv";
dotenv.config();

// Ensure test verifies security invariants
process.env.NODE_ENV = "test";
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
process.env.APP_ADMIN_JWT_SECRET = process.env.APP_ADMIN_JWT_SECRET || "b".repeat(32);
process.env.APP_ADMIN_TOTP_KEY = process.env.APP_ADMIN_TOTP_KEY || "c".repeat(32);
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "127.0.0.1/32,10.0.0.0/8";

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import { hashPassword } from "better-auth/crypto";

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");

console.log("================================================================");
console.log("  SWYRA AUTH -- APPLICATION MANAGEMENT AUTHORIZATION AUDIT");
console.log("  Verifying Deleting, Adding, Updating Apps Require Strict Admin Session");
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

let ipCounter = 500;
function getTestHeaders(extra: Record<string, string> = {}): Headers {
  const h = new Headers();
  const ip = `198.51.100.${++ipCounter % 240 + 1}`;
  h.set("content-type", "application/json");
  h.set("host", "localhost:3000");
  h.set("origin", process.env.FRONTEND_URL || "http://localhost:5174");
  h.set("referer", (process.env.FRONTEND_URL || "http://localhost:5174") + "/");
  h.set("x-forwarded-for", `${ip}, 10.0.0.1`);
  h.set("x-gateway-secret", process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32));
  h.set("x-csrf-token", "any");
  for (const [k, v] of Object.entries(extra)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

const db = await getDb();

// --------------------------------------------------------------------------
// SETUP FIXTURES
// --------------------------------------------------------------------------
const client1_id = "test-auth-app1-" + crypto.randomBytes(4).toString("hex");
const client1_secret = "secret1-" + crypto.randomBytes(8).toString("hex");
const client1_secretHash = crypto.createHash("sha256").update(client1_secret).digest("base64url");

const client2_id = "test-auth-app2-" + crypto.randomBytes(4).toString("hex");
const client2_secret = "secret2-" + crypto.randomBytes(8).toString("hex");
const client2_secretHash = crypto.createHash("sha256").update(client2_secret).digest("base64url");

await db.collection("oauthClient").insertMany([
  {
    clientId: client1_id,
    clientSecret: client1_secretHash,
    name: "Managed Application 1",
    redirectUris: ["http://localhost:3000/callback"],
    allowedOrigins: ["http://localhost:3000"],
    isDev: true,
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    clientId: client2_id,
    clientSecret: client2_secretHash,
    name: "Managed Application 2",
    redirectUris: ["http://localhost:3001/callback"],
    allowedOrigins: ["http://localhost:3001"],
    isDev: true,
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  },
]);

// 1. Super Admin User + Session
const superAdminEmail = `super_${crypto.randomBytes(4).toString("hex")}@example.com`;
const superAdminPassword = "SuperAdminPass@1234!";
await authProvider.api.signUpEmail({
  body: { email: superAdminEmail, password: superAdminPassword, name: "Global Super Admin" },
});
await db.collection("user").updateOne(
  { email: superAdminEmail },
  { $set: { role: "admin", scopedClientId: null, emailVerified: true } }
);
const superLogin = await app.request("/api/auth/sign-in/email", {
  method: "POST",
  headers: getTestHeaders(),
  body: JSON.stringify({ email: superAdminEmail, password: superAdminPassword }),
});
assert.equal(superLogin.status, 200, "Super admin login must return 200");
const superAdminCookie = (superLogin.headers.get("set-cookie") || "").split(";")[0];
assert.ok(superAdminCookie, "Super admin must receive session cookie");

// 2. Scoped Admin User (Assigned to Client 1 only) + Session
const scopedAdminEmail = `scoped_${crypto.randomBytes(4).toString("hex")}@example.com`;
const scopedAdminPassword = "ScopedAdminPass@1234!";
await authProvider.api.signUpEmail({
  body: { email: scopedAdminEmail, password: scopedAdminPassword, name: "Scoped Admin Client 1" },
});
await db.collection("user").updateOne(
  { email: scopedAdminEmail },
  { $set: { role: "admin", scopedClientId: client1_id, emailVerified: true } }
);
const scopedLogin = await app.request("/api/auth/sign-in/email", {
  method: "POST",
  headers: getTestHeaders(),
  body: JSON.stringify({ email: scopedAdminEmail, password: scopedAdminPassword }),
});
assert.equal(scopedLogin.status, 200, "Scoped admin login must return 200");
const scopedAdminCookie = (scopedLogin.headers.get("set-cookie") || "").split(";")[0];
assert.ok(scopedAdminCookie, "Scoped admin must receive session cookie");

// 3. Regular End-User + Session
const regularUserEmail = `user_${crypto.randomBytes(4).toString("hex")}@example.com`;
const regularUserPassword = "RegularUserPass@1234!";
await authProvider.api.signUpEmail({
  body: { email: regularUserEmail, password: regularUserPassword, name: "Regular End User" },
});
const regularLogin = await app.request("/api/auth/sign-in/email", {
  method: "POST",
  headers: getTestHeaders(),
  body: JSON.stringify({ email: regularUserEmail, password: regularUserPassword }),
});
assert.equal(regularLogin.status, 200, "Regular user login must return 200");
const regularUserCookie = (regularLogin.headers.get("set-cookie") || "").split(";")[0];
assert.ok(regularUserCookie, "Regular user must receive session cookie");

// 4. App Admin Account & Token (via /api/auth/app-admin/login)
const appAdminEmail = `appadmin_${crypto.randomBytes(4).toString("hex")}@example.com`;
const appAdminPass = "AppAdminPass@1234!";
const appAdminPassHash = await hashPassword(appAdminPass);
await db.collection("app_admins").insertOne({
  clientId: client1_id,
  email: appAdminEmail,
  name: "App 1 Local Admin",
  password: appAdminPassHash,
  redirectUrl: "http://localhost:3000/callback",
  isActive: true,
  totpEnabled: false,
  createdAt: new Date(),
});

const appAdminLoginRes = await app.request("/api/auth/app-admin/login", {
  method: "POST",
  headers: getTestHeaders(),
  body: JSON.stringify({
    client_id: client1_id,
    client_secret: client1_secret,
    email: appAdminEmail,
    password: appAdminPass,
  }),
});
const appAdminLoginData = await appAdminLoginRes.json();
const appAdminJwt = appAdminLoginData.token || "";

// 5. Fake OAuth Access Token
const oauthAccessToken = "swyra_at_" + crypto.randomBytes(24).toString("hex");
await db.collection("oauthAccessToken").insertOne({
  token: oauthAccessToken,
  clientId: client1_id,
  userId: "user-123",
  scope: "openid profile email",
  createdAt: new Date(),
  expiresAt: new Date(Date.now() + 3600 * 1000),
});

// Basic Auth credentials header for Client 1
const client1BasicAuth = "Basic " + Buffer.from(`${client1_id}:${client1_secret}`).toString("base64");

// ==========================================================================
// SUITE 1: ADDING / CREATING NEW APPLICATIONS (POST /api/admin/clients)
// ==========================================================================

await runTest("CREATE-1: Unauthenticated request cannot create new application", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      name: "Hacker App",
      redirect_uris: ["http://localhost:4000/callback"],
      allowed_origins: ["http://localhost:4000"],
    }),
  });
  assert.equal(res.status, 401, "Must return 401 Unauthorized without admin session");
});

await runTest("CREATE-2: OAuth client credentials (Basic Auth) cannot create new application", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Authorization: client1BasicAuth }),
    body: JSON.stringify({
      name: "Hacker App Via Client Credentials",
      redirect_uris: ["http://localhost:4000/callback"],
      allowed_origins: ["http://localhost:4000"],
    }),
  });
  assert.equal(res.status, 401, "Must return 401; client credentials cannot act as admin session");
});

await runTest("CREATE-3: OAuth client credentials in body cannot create new application", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: client1_id,
      client_secret: client1_secret,
      name: "Hacker App Via Body Credentials",
      redirect_uris: ["http://localhost:4000/callback"],
      allowed_origins: ["http://localhost:4000"],
    }),
  });
  assert.equal(res.status, 401, "Must return 401 Unauthorized");
});

await runTest("CREATE-4: OAuth 2.1 user access token cannot create new application", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${oauthAccessToken}` }),
    body: JSON.stringify({
      name: "Hacker App Via User Access Token",
      redirect_uris: ["http://localhost:4000/callback"],
      allowed_origins: ["http://localhost:4000"],
    }),
  });
  assert.equal(res.status, 401, "Must return 401; user access tokens cannot act as admin session");
});

await runTest("CREATE-5: App Admin JWT cannot create new application", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${appAdminJwt}` }),
    body: JSON.stringify({
      name: "Hacker App Via App Admin Token",
      redirect_uris: ["http://localhost:4000/callback"],
      allowed_origins: ["http://localhost:4000"],
    }),
  });
  assert.equal(res.status, 401, "Must return 401; App Admin JWT cannot access central admin endpoints");
});

await runTest("CREATE-6: Regular authenticated user (role: 'user') cannot create new application", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: regularUserCookie }),
    body: JSON.stringify({
      name: "Hacker App Via Regular User",
      redirect_uris: ["http://localhost:4000/callback"],
      allowed_origins: ["http://localhost:4000"],
    }),
  });
  assert.equal(res.status, 403, "Must return 403 Forbidden for non-admin user");
});

await runTest("CREATE-7: Scoped Admin (role: 'admin', scopedClientId: app1) cannot create new application", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: scopedAdminCookie }),
    body: JSON.stringify({
      name: "App Created By Scoped Admin",
      redirect_uris: ["http://localhost:4000/callback"],
      allowed_origins: ["http://localhost:4000"],
    }),
  });
  assert.equal(res.status, 403, "Must return 403 Forbidden; scoped admins cannot create global clients");
});

let createdAppId = "";
await runTest("CREATE-8: Global Super Admin CAN create new application", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      name: "Valid SuperAdmin App",
      isDev: true,
      redirect_uris: ["http://localhost:4000/callback"],
      allowed_origins: ["http://localhost:4000"],
    }),
  });
  assert.equal(res.status, 201, "Super Admin can create application");
  const data = await res.json();
  createdAppId = data.client_id || data.id;
  assert.ok(createdAppId, "Created application must have client ID");
});

// ==========================================================================
// SUITE 2: UPDATING APPLICATIONS (PATCH /api/admin/clients/:id)
// ==========================================================================

await runTest("UPDATE-1: Unauthenticated request cannot update application", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "PATCH",
    headers: getTestHeaders(),
    body: JSON.stringify({ client_name: "Tampered Name" }),
  });
  assert.equal(res.status, 401, "Must return 401 Unauthorized without session");
});

await runTest("UPDATE-2: OAuth client credentials cannot update application", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "PATCH",
    headers: getTestHeaders({ Authorization: client1BasicAuth }),
    body: JSON.stringify({ client_name: "Tampered Name Via Client Credentials" }),
  });
  assert.equal(res.status, 401, "Must return 401 Unauthorized");
});

await runTest("UPDATE-3: OAuth 2.1 access token cannot update application", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "PATCH",
    headers: getTestHeaders({ Authorization: `Bearer ${oauthAccessToken}` }),
    body: JSON.stringify({ client_name: "Tampered Name Via Access Token" }),
  });
  assert.equal(res.status, 401, "Must return 401 Unauthorized");
});

await runTest("UPDATE-4: App Admin JWT cannot update application via central admin route", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "PATCH",
    headers: getTestHeaders({ Authorization: `Bearer ${appAdminJwt}` }),
    body: JSON.stringify({ client_name: "Tampered Name Via App Admin JWT" }),
  });
  assert.equal(res.status, 401, "Must return 401 Unauthorized");
});

await runTest("UPDATE-5: Regular user session cannot update application", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: regularUserCookie }),
    body: JSON.stringify({ client_name: "Tampered Name Via Regular User" }),
  });
  assert.equal(res.status, 403, "Must return 403 Forbidden");
});

await runTest("UPDATE-6: Scoped Admin (for App 1) CANNOT update App 2 (Cross-Tenant Access Forbidden)", async () => {
  const res = await app.request(`/api/admin/clients/${client2_id}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: scopedAdminCookie }),
    body: JSON.stringify({ client_name: "Hacked App 2 Name" }),
  });
  assert.equal(res.status, 403, "Must return 403 Forbidden for cross-tenant update");
});

await runTest("UPDATE-7: Scoped Admin (for App 1) CANNOT update App 2 via /app/:clientId/config", async () => {
  const res = await app.request(`/api/admin/app/${client2_id}/config`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: scopedAdminCookie }),
    body: JSON.stringify({ client_name: "Hacked App 2 Config" }),
  });
  assert.equal(res.status, 403, "Must return 403 Forbidden for cross-tenant config update");
});

await runTest("UPDATE-8: Scoped Admin (for App 1) CAN update own App 1, but privilege fields are stripped", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: scopedAdminCookie }),
    body: JSON.stringify({
      client_name: "Updated App 1 By Scoped Admin",
      isDev: false, // Attempt to flip isDev
      isPublic: true, // Attempt to flip isPublic
      role: "admin", // Attempt privilege escalation
    }),
  });
  assert.equal(res.status, 200, "Scoped Admin can update own app name");
  const doc = await db.collection("oauthClient").findOne({ clientId: client1_id });
  assert.equal(doc?.name, "Updated App 1 By Scoped Admin", "Name should be updated");
  assert.equal(doc?.isDev, true, "isDev must NOT be changed by scoped admin");
  assert.equal(doc?.isPublic, false, "isPublic must NOT be changed by scoped admin");
  assert.equal((doc as any)?.role, undefined, "Injected role field must not exist");
});

await runTest("UPDATE-9: Global Super Admin CAN update any application", async () => {
  const res = await app.request(`/api/admin/clients/${client2_id}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({ client_name: "Updated App 2 By SuperAdmin" }),
  });
  assert.equal(res.status, 200, "Super Admin can update any app");
});

// ==========================================================================
// SUITE 3: DELETING APPLICATIONS (DELETE /api/admin/clients/:id)
// ==========================================================================

await runTest("DELETE-1: Unauthenticated request cannot delete application", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "DELETE",
    headers: getTestHeaders(),
  });
  assert.equal(res.status, 401, "Must return 401 Unauthorized without session");
});

await runTest("DELETE-2: OAuth client credentials (own app) cannot delete application", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "DELETE",
    headers: getTestHeaders({ Authorization: client1BasicAuth }),
  });
  assert.equal(res.status, 401, "Must return 401; app credentials cannot delete itself");
});

await runTest("DELETE-3: OAuth 2.1 access token cannot delete application", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "DELETE",
    headers: getTestHeaders({ Authorization: `Bearer ${oauthAccessToken}` }),
  });
  assert.equal(res.status, 401, "Must return 401; user access tokens cannot delete app");
});

await runTest("DELETE-4: App Admin JWT cannot delete application", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "DELETE",
    headers: getTestHeaders({ Authorization: `Bearer ${appAdminJwt}` }),
  });
  assert.equal(res.status, 401, "Must return 401; App Admin JWT cannot delete app");
});

await runTest("DELETE-5: Regular user session cannot delete application", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: regularUserCookie }),
  });
  assert.equal(res.status, 403, "Must return 403 Forbidden");
});

await runTest("DELETE-6: Scoped Admin (for App 1) CANNOT delete own application (App 1)", async () => {
  const res = await app.request(`/api/admin/clients/${client1_id}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: scopedAdminCookie }),
  });
  assert.equal(res.status, 403, "Must return 403 Forbidden; deletion requires Super Admin");
  const doc = await db.collection("oauthClient").findOne({ clientId: client1_id });
  assert.ok(doc, "Application 1 must still exist in database");
});

await runTest("DELETE-7: Scoped Admin (for App 1) CANNOT delete other application (App 2)", async () => {
  const res = await app.request(`/api/admin/clients/${client2_id}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: scopedAdminCookie }),
  });
  assert.equal(res.status, 403, "Must return 403 Forbidden");
  const doc = await db.collection("oauthClient").findOne({ clientId: client2_id });
  assert.ok(doc, "Application 2 must still exist in database");
});

await runTest("DELETE-8: Global Super Admin CAN delete application", async () => {
  const res = await app.request(`/api/admin/clients/${createdAppId}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
  });
  assert.equal(res.status, 200, "Super Admin can delete application");
  const doc = await db.collection("oauthClient").findOne({ clientId: createdAppId });
  assert.equal(doc, null, "Deleted application must not exist in database");
});

// ==========================================================================
// SUITE 4: DIRECT BETTER-AUTH OAUTH CLIENT MANAGEMENT ENDPOINTS
// ==========================================================================

await runTest("DIRECT-1: Direct POST /api/auth/oauth2/register is strictly blocked (403)", async () => {
  const res = await app.request("/api/auth/oauth2/register", {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({ client_name: "Direct Registration" }),
  });
  assert.equal(res.status, 403, "Dynamic client registration endpoint must return 403");
});

await runTest("DIRECT-2: Direct POST /api/auth/oauth2/create-client is strictly blocked (403)", async () => {
  const res = await app.request("/api/auth/oauth2/create-client", {
    method: "POST",
    headers: getTestHeaders({ Authorization: client1BasicAuth }),
    body: JSON.stringify({ client_name: "Direct Creation" }),
  });
  assert.equal(res.status, 403, "Direct create-client must return 403");
});

await runTest("DIRECT-3: Direct POST /api/auth/oauth2/update-client is strictly blocked (403)", async () => {
  const res = await app.request("/api/auth/oauth2/update-client", {
    method: "POST",
    headers: getTestHeaders({ Authorization: client1BasicAuth }),
    body: JSON.stringify({ client_id: client1_id, client_name: "Direct Update" }),
  });
  assert.equal(res.status, 403, "Direct update-client must return 403");
});

await runTest("DIRECT-4: Direct POST /api/auth/oauth2/delete-client is strictly blocked (403)", async () => {
  const res = await app.request("/api/auth/oauth2/delete-client", {
    method: "POST",
    headers: getTestHeaders({ Authorization: client1BasicAuth }),
    body: JSON.stringify({ client_id: client1_id }),
  });
  assert.equal(res.status, 403, "Direct delete-client must return 403");
});

console.log("================================================================");
console.log(`  APPLICATION MANAGEMENT AUTH RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
