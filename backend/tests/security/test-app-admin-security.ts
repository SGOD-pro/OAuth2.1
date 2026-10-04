import dotenv from "dotenv";
dotenv.config();

import assert from "node:assert/strict";
import crypto from "crypto";
import { ObjectId } from "mongodb";
import * as jose from "jose";

// Configure test environment
process.env.NODE_ENV = "test";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32";

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");
const { envSchema } = await import("../../src/config/schema");
const { config } = await import("../../src/config");

console.log("================================================================");
console.log("  SWYRA AUTH -- APPLICATION ADMIN MIGRATION & AUTHORIZATION AUDIT");
console.log("  Verifying Legacy Auth Retirement (410) & Scoped OAuth Claims (Cases A-I)");
console.log("================================================================");

let passed = 0;
let failed = 0;
let ipCounter = 1;

function getTestHeaders(extra: Record<string, string> = {}) {
  const ip = `198.51.100.${++ipCounter % 250 + 1}`;
  return {
    "Content-Type": "application/json",
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    "x-gateway-secret": process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32),
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

// --------------------------------------------------------------------------
// TEST FIXTURES SETUP
// --------------------------------------------------------------------------
const clientA_id = "test-app-a-" + crypto.randomBytes(4).toString("hex");
const clientA_secret = "secret-a-" + crypto.randomBytes(8).toString("hex");
const clientA_secretHash = crypto.createHash("sha256").update(clientA_secret).digest("base64url");

const clientB_id = "test-app-b-" + crypto.randomBytes(4).toString("hex");
const clientB_secret = "secret-b-" + crypto.randomBytes(8).toString("hex");
const clientB_secretHash = crypto.createHash("sha256").update(clientB_secret).digest("base64url");

await db.collection("oauthClient").insertMany([
  {
    clientId: clientA_id,
    clientSecret: clientA_secretHash,
    name: "Test Application A",
    redirectUris: ["http://localhost:3000/callback"],
    allowedOrigins: ["http://localhost:3000"],
    disabled: false,
    isDev: true,
    isPublic: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    clientId: clientB_id,
    clientSecret: clientB_secretHash,
    name: "Test Application B (Private)",
    redirectUris: ["http://localhost:3001/callback"],
    allowedOrigins: ["http://localhost:3001"],
    disabled: false,
    isDev: true,
    isPublic: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  },
]);

// Generate dedicated test RSA keypair for RS256 token issuance & verification
const testKeyPair = await jose.generateKeyPair("RS256");
const testPublicKeyJwk = await jose.exportJWK(testKeyPair.publicKey);
testPublicKeyJwk.alg = "RS256";
testPublicKeyJwk.use = "sig";
const testKid = "test-kid-" + crypto.randomBytes(4).toString("hex");
testPublicKeyJwk.kid = testKid;

// Insert test public key into jwks collection with future timestamp so getIdpPublicKey selects it
const testJwkDocId = new ObjectId();
await db.collection("jwks").insertOne({
  _id: testJwkDocId,
  publicKey: JSON.stringify(testPublicKeyJwk),
  privateKey: "encrypted-mock",
  alg: "RS256",
  createdAt: new Date(Date.now() + 86400 * 1000), // Far in future to be selected as latest
});

// Helper to sign test RS256 JWT tokens using the test private key
async function signTestToken(payload: Record<string, any>, options: {
  issuer?: string;
  audience?: string;
  expiresIn?: string;
  alg?: string;
} = {}): Promise<string> {
  const alg = options.alg || "RS256";
  if (alg === "HS256") {
    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setIssuer(options.issuer || config.auth.baseURL)
      .setAudience(options.audience || clientA_id)
      .setExpirationTime(options.expiresIn || "15m")
      .sign(new TextEncoder().encode("hs256-symmetric-secret-key-32ch!"));
  }

  const signJwt = new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: testKid })
    .setIssuedAt()
    .setIssuer(options.issuer !== undefined ? options.issuer : config.auth.baseURL);

  if (options.audience !== undefined) {
    signJwt.setAudience(options.audience);
  } else {
    signJwt.setAudience(clientA_id);
  }

  if (options.expiresIn) {
    signJwt.setExpirationTime(options.expiresIn);
  } else {
    signJwt.setExpirationTime("15m");
  }

  return signJwt.sign(testKeyPair.privateKey);
}

// Global Super Admin Session
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
const superAdminCookie = (superLogin.headers.get("set-cookie") || "").split(";")[0];

// Cleanup hook
async function cleanup() {
  try {
    await db.collection("oauthClient").deleteMany({ clientId: { $in: [clientA_id, clientB_id] } });
    await db.collection("jwks").deleteOne({ _id: testJwkDocId });
    await db.collection("app_admins").deleteMany({ clientId: { $in: [clientA_id, clientB_id] } });
    await db.collection("user").deleteMany({ email: superAdminEmail });
    await db.collection("session").deleteMany({});
  } catch (err) {
    console.error("Cleanup error:", err);
  }
}

try {
  // ==========================================================================
  // SUITE 1: PERMANENT RETIREMENT OF LEGACY APP-ADMIN AUTH (HTTP 410 GONE)
  // ==========================================================================
  console.log("\n--- SUITE 1: RETIREMENT OF LEGACY APP-ADMIN AUTHENTICATION ---");

  await runTest("RETIRE-1: POST /api/auth/app-admin/login returns HTTP 410 Gone", async () => {
    const res = await app.request("/api/auth/app-admin/login", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        email: "any@example.com",
        password: "Password123!",
      }),
    });
    assert.equal(res.status, 410, "Must return HTTP 410 Gone");
    const json = await res.json();
    assert.equal(json.error, "endpoint_retired");
    assert.ok(json.error_description.includes("permanently retired"));
  });

  await runTest("RETIRE-2: POST /api/auth/app-admin/verify returns HTTP 410 Gone", async () => {
    const res = await app.request("/api/auth/app-admin/verify", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        client_id: clientA_id,
        client_secret: clientA_secret,
        token: "any-token",
      }),
    });
    assert.equal(res.status, 410, "Must return HTTP 410 Gone");
    const json = await res.json();
    assert.equal(json.error, "endpoint_retired");
  });

  await runTest("RETIRE-3: POST /api/auth/app-admin/logout returns HTTP 410 Gone", async () => {
    const res = await app.request("/api/auth/app-admin/logout", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({ token: "any-token" }),
    });
    assert.equal(res.status, 410, "Must return HTTP 410 Gone");
    const json = await res.json();
    assert.equal(json.error, "endpoint_retired");
  });

  await runTest("RETIRE-4: POST /api/auth/app-admin/mfa/verify-login returns HTTP 410 Gone", async () => {
    const res = await app.request("/api/auth/app-admin/mfa/verify-login", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({ mfa_token: "any-token", code: "123456" }),
    });
    assert.equal(res.status, 410, "Must return HTTP 410 Gone");
    const json = await res.json();
    assert.equal(json.error, "endpoint_retired");
  });

  await runTest("RETIRE-5: POST /api/auth/app-admin/mfa/setup returns HTTP 410 Gone", async () => {
    const res = await app.request("/api/auth/app-admin/mfa/setup", {
      method: "POST",
      headers: getTestHeaders(),
    });
    assert.equal(res.status, 410, "Must return HTTP 410 Gone");
    const json = await res.json();
    assert.equal(json.error, "endpoint_retired");
  });

  await runTest("RETIRE-6: POST /api/auth/app-admin/mfa/confirm returns HTTP 410 Gone", async () => {
    const res = await app.request("/api/auth/app-admin/mfa/confirm", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({ code: "123456" }),
    });
    assert.equal(res.status, 410, "Must return HTTP 410 Gone");
    const json = await res.json();
    assert.equal(json.error, "endpoint_retired");
  });

  await runTest("RETIRE-7: POST /api/auth/app-admin/mfa/disable returns HTTP 410 Gone", async () => {
    const res = await app.request("/api/auth/app-admin/mfa/disable", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({ code: "123456" }),
    });
    assert.equal(res.status, 410, "Must return HTTP 410 Gone");
    const json = await res.json();
    assert.equal(json.error, "endpoint_retired");
  });

  await runTest("RETIRE-8: Catch-all /api/auth/app-admin/* returns HTTP 410 Gone", async () => {
    const res = await app.request("/api/auth/app-admin/arbitrary-endpoint", {
      method: "GET",
      headers: getTestHeaders(),
    });
    assert.equal(res.status, 410, "Must return HTTP 410 Gone");
    const json = await res.json();
    assert.equal(json.error, "endpoint_retired");
  });

  // ==========================================================================
  // SUITE 2: APPLICATION ADMIN AUTHORIZATION VIA OAUTH IDENTITY (CASES A-I)
  // ==========================================================================
  console.log("\n--- SUITE 2: SCOPED APPLICATION ADMIN AUTHORIZATION (CASES A-I) ---");

  // Case A: role=user → denied application-admin operation
  await runTest("CASE-A: role=user is denied application-admin operation (HTTP 403)", async () => {
    const token = await signTestToken({
      sub: "regular-user-id",
      role: "user",
      scoped_client_id: clientA_id,
    });
    const res = await app.request(`/api/admin/clients/${clientA_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ client_name: "Tampered App A" }),
    });
    assert.equal(res.status, 403, "Regular user must be denied application-admin operation");
    const json = await res.json();
    assert.equal(json.error, "Admin access required");
  });

  // Case B: role=admin, scoped_client_id=client-A, requesting client-A → allowed
  await runTest("CASE-B: role=admin with scoped_client_id=client-A requesting client-A is allowed (HTTP 200)", async () => {
    const token = await signTestToken({
      sub: "admin-user-id-a",
      role: "admin",
      scoped_client_id: clientA_id,
    });
    const res = await app.request(`/api/admin/clients/${clientA_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ client_name: "Updated App A Name" }),
    });
    assert.equal(res.status, 200, "Scoped admin must be allowed to manage assigned application");
    const updated = await db.collection("oauthClient").findOne({ clientId: clientA_id });
    assert.equal(updated?.name, "Updated App A Name");
  });

  // Case C: role=admin, scoped_client_id=client-A, requesting client-B → denied
  await runTest("CASE-C: role=admin with scoped_client_id=client-A requesting client-B is denied (HTTP 403)", async () => {
    const token = await signTestToken({
      sub: "admin-user-id-a",
      role: "admin",
      scoped_client_id: clientA_id,
    });
    const res = await app.request(`/api/admin/clients/${clientB_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ client_name: "Breached App B" }),
    });
    assert.equal(res.status, 403, "Scoped admin must be denied cross-tenant management");
    const json = await res.json();
    assert.equal(json.error, "forbidden");
    assert.ok(json.message.includes("Cross-tenant access forbidden"));
  });

  // Case D: role=admin, scoped_client_id=null → Super Admin behavior according to policy
  await runTest("CASE-D: role=admin with scoped_client_id=null possesses Super Admin authorization (HTTP 200)", async () => {
    const token = await signTestToken({
      sub: "global-super-admin-id",
      role: "admin",
      scoped_client_id: null,
    });
    const resA = await app.request(`/api/admin/clients/${clientA_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ client_name: "SuperAdmin Managed App A" }),
    });
    assert.equal(resA.status, 200, "Super admin must be allowed to manage App A");

    const resB = await app.request(`/api/admin/clients/${clientB_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ client_name: "SuperAdmin Managed App B" }),
    });
    assert.equal(resB.status, 200, "Super admin must be allowed to manage App B");
  });

  // Case E: forged/unsigned token → denied
  await runTest("CASE-E: forged or unsigned token is denied (HTTP 401)", async () => {
    // Unsigned / malformed token
    const resMalformed = await app.request(`/api/admin/clients/${clientA_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: "Bearer malformed.unsigned.token" }),
      body: JSON.stringify({ client_name: "Hacker App" }),
    });
    assert.equal(resMalformed.status, 401, "Malformed token must be denied");

    // Token signed with unrelated private key (signature forgery)
    const unrelatedKey = await jose.generateKeyPair("RS256");
    const forgedToken = await new jose.SignJWT({
      sub: "attacker",
      role: "admin",
      scoped_client_id: null,
    })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(config.auth.baseURL)
      .setAudience(clientA_id)
      .setExpirationTime("15m")
      .sign(unrelatedKey.privateKey);

    const resForged = await app.request(`/api/admin/clients/${clientA_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: `Bearer ${forgedToken}` }),
      body: JSON.stringify({ client_name: "Forged Token Update" }),
    });
    assert.equal(resForged.status, 401, "Forged token signature must be denied with 401");
  });

  // Case F: wrong issuer → denied
  await runTest("CASE-F: token with wrong issuer is denied (HTTP 401)", async () => {
    const wrongIssuerToken = await signTestToken(
      { sub: "admin-id", role: "admin", scoped_client_id: clientA_id },
      { issuer: "https://untrusted-foreign-idp.com" }
    );
    const res = await app.request(`/api/admin/clients/${clientA_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: `Bearer ${wrongIssuerToken}` }),
      body: JSON.stringify({ client_name: "Wrong Issuer Update" }),
    });
    assert.equal(res.status, 401, "Token with untrusted issuer must be denied with 401");
  });

  // Case G: wrong audience → denied
  await runTest("CASE-G: token with wrong audience is denied (HTTP 401)", async () => {
    const wrongAudToken = await signTestToken(
      { sub: "admin-id", role: "admin", scoped_client_id: clientA_id },
      { audience: "completely-unrelated-audience" }
    );
    const res = await app.request(`/api/admin/clients/${clientA_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: `Bearer ${wrongAudToken}` }),
      body: JSON.stringify({ client_name: "Wrong Aud Update" }),
    });
    assert.equal(res.status, 401, "Token with unregistered audience must be denied with 401");
  });

  // Case H: HS256 token → denied
  await runTest("CASE-H: HS256 token is denied (algorithm pinning enforces RS256) (HTTP 401)", async () => {
    const hs256Token = await signTestToken(
      { sub: "admin-id", role: "admin", scoped_client_id: clientA_id },
      { alg: "HS256" }
    );
    const res = await app.request(`/api/admin/clients/${clientA_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: `Bearer ${hs256Token}` }),
      body: JSON.stringify({ client_name: "HS256 Algorithm Confusion Attack" }),
    });
    assert.equal(res.status, 401, "HS256 symmetric token must be strictly rejected with 401");
  });

  // Case I: expired token → denied
  await runTest("CASE-I: expired token is denied (HTTP 401)", async () => {
    const expiredToken = await new jose.SignJWT({
      sub: "admin-id",
      role: "admin",
      scoped_client_id: clientA_id,
    })
      .setProtectedHeader({ alg: "RS256", kid: testKid })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setIssuer(config.auth.baseURL)
      .setAudience(clientA_id)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600) // Expired 1 hour ago
      .sign(testKeyPair.privateKey);

    const res = await app.request(`/api/admin/clients/${clientA_id}`, {
      method: "PATCH",
      headers: getTestHeaders({ Authorization: `Bearer ${expiredToken}` }),
      body: JSON.stringify({ client_name: "Expired Token Update" }),
    });
    assert.equal(res.status, 401, "Expired token must be denied with 401");
  });

  // Remove test JWK so Better Auth uses its legitimate JWKS key for subsequent user creations
  await db.collection("jwks").deleteOne({ _id: testJwkDocId });

  // ==========================================================================
  // SUITE 3: SUPER ADMIN APPLICATION ADMIN PROVISIONING
  // ==========================================================================
  console.log("\n--- SUITE 3: APPLICATION ADMIN PROVISIONING VIA SUPER ADMIN ---");

  const provisionAdminEmail = `prov_${crypto.randomBytes(4).toString("hex")}@example.com`;
  let provisionedAdminId = "";

  await runTest("PROV-1: Super Admin provisions application admin; user is created in IdP with scopedClientId", async () => {
    const res = await app.request(`/api/admin/clients/${clientA_id}/app-admins`, {
      method: "POST",
      headers: getTestHeaders({ Cookie: superAdminCookie }),
      body: JSON.stringify({
        email: provisionAdminEmail,
        password: "ProvPassword@1234!",
        name: "Provisioned App A Admin",
      }),
    });
    assert.equal(res.status, 201, "Must return 201 Created");
    const data = await res.json();
    provisionedAdminId = data.admin.id;

    // Verify user exists in centralized IdP user collection with role: admin and scopedClientId
    const idpUser = await db.collection("user").findOne({ email: provisionAdminEmail });
    assert.ok(idpUser, "User must exist in centralized IdP collection");
    assert.equal(idpUser.role, "admin", "Role must be admin");
    assert.equal(idpUser.scopedClientId, clientA_id, "scopedClientId must match clientA");
  });

  await runTest("PROV-2: Super Admin deletes application admin; user role & scopedClientId are unlinked", async () => {
    const res = await app.request(`/api/admin/clients/${clientA_id}/app-admins/${provisionedAdminId}`, {
      method: "DELETE",
      headers: getTestHeaders({ Cookie: superAdminCookie }),
    });
    assert.equal(res.status, 200, "Must return 200 OK");

    // Verify user role was reset or unlinked
    const idpUser = await db.collection("user").findOne({ email: provisionAdminEmail });
    assert.equal(idpUser?.scopedClientId, null, "scopedClientId must be unlinked");
    assert.equal(idpUser?.role, "user", "Role must be reset to user");
  });

  await runTest("PROV-3: Super Admin re-adds application admin; identity, password hash, and app registration are restored", async () => {
    const res = await app.request(`/api/admin/clients/${clientA_id}/app-admins`, {
      method: "POST",
      headers: getTestHeaders({ Cookie: superAdminCookie }),
      body: JSON.stringify({
        email: provisionAdminEmail,
        password: "ReAddedPassword@1234!",
        name: "Re-Added App A Admin",
      }),
    });
    assert.equal(res.status, 201, "Must return 201 Created");

    // Verify user exists with role: admin and scopedClientId
    const idpUser = await db.collection("user").findOne({ email: provisionAdminEmail });
    assert.ok(idpUser, "User must exist in centralized IdP collection");
    assert.equal(idpUser.role, "admin", "Role must be admin again");
    assert.equal(idpUser.scopedClientId, clientA_id, "scopedClientId must match clientA");

    // Verify account exists with password
    const userId = idpUser.id || idpUser._id;
    const account = await db.collection("account").findOne({
      $or: [{ userId }, { userId: userId.toString() }, { accountId: userId.toString() }],
      providerId: "credential",
    });
    assert.ok(account, "Account must exist for re-added user");
    assert.ok(account.password, "Password hash must exist in account");

    // Verify registration exists
    const reg = await db.collection("user_app_registrations").findOne({
      clientId: clientA_id,
      $or: [{ userId: userId.toString() }, { userId }],
    });
    assert.ok(reg, "Registration must exist in user_app_registrations for client");
  });

  await runTest("PROV-4: Scoped Admin CAN list app-admins for own app, but is DENIED for other apps", async () => {
    const scopedTokenA = await signTestToken({
      sub: "scoped-admin-a",
      role: "admin",
      scoped_client_id: clientA_id,
    });

    // 1. Scoped Admin A requests App A app-admins -> Allowed (200)
    const resA = await app.request(`/api/admin/clients/${clientA_id}/app-admins`, {
      method: "GET",
      headers: getTestHeaders({ Authorization: `Bearer ${scopedTokenA}` }),
    });
    assert.equal(resA.status, 200, "Scoped Admin A must be allowed to list own App A admins");
    const jsonA = await resA.json();
    assert.ok(Array.isArray(jsonA.admins), "Must return admins array");

    // 2. Scoped Admin A requests App B app-admins -> Forbidden (403)
    const resB = await app.request(`/api/admin/clients/${clientB_id}/app-admins`, {
      method: "GET",
      headers: getTestHeaders({ Authorization: `Bearer ${scopedTokenA}` }),
    });
    assert.equal(resB.status, 403, "Scoped Admin A must be denied from listing other App B admins");
  });

  // ==========================================================================
  // SUITE 4: OBSOLETE SECRETS REMOVAL INVARIANTS
  // ==========================================================================
  console.log("\n--- SUITE 4: OBSOLETE SECRETS CONFIGURATION INVARIANTS ---");

  await runTest("CONFIG-1: envSchema does not require APP_ADMIN_JWT_SECRET or APP_ADMIN_TOTP_KEY", async () => {
    // Valid production config without APP_ADMIN_JWT_SECRET or APP_ADMIN_TOTP_KEY succeeds
    const parsed = envSchema.parse({
      NODE_ENV: "production",
      PORT: 3000,
      MONGO_URI: "mongodb://127.0.0.1:27017/db",
      BETTER_AUTH_SECRET: "s".repeat(32),
      BETTER_AUTH_URL: "https://auth.example.com",
      GOOGLE_CLIENT_ID: "g-id",
      GOOGLE_CLIENT_SECRET: "g-sec",
      FRONTEND_URL: "https://app.example.com",
      INTERNAL_GATEWAY_SECRET: "g".repeat(32),
    });
    assert.ok(parsed, "Schema parsing must succeed without obsolete secrets");
    assert.equal((parsed as any).APP_ADMIN_JWT_SECRET, undefined);
    assert.equal((parsed as any).APP_ADMIN_TOTP_KEY, undefined);
  });

} finally {
  await cleanup();
}

console.log("================================================================");
console.log(`  APPLICATION ADMIN SECURITY AUDIT RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
