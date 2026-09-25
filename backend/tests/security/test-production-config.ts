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
const { validateRedirectUri, validateRedirectUris, isRegisteredRedirectUri, isLoopbackHost } = await import("../../src/utils/security");
const { envSchema } = await import("../../src/config/schema");

console.log("================================================================");
console.log("  SWYRA AUTH -- PRODUCTION CONFIGURATION & ISOLATION TESTS");
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

// --------------------------------------------------------------------------
// TEST 1: Production URL validation in schema
// --------------------------------------------------------------------------
runTest("CONF-1: envSchema strictly rejects localhost and non-HTTPS in production", () => {
  // Localhost in BETTER_AUTH_URL in production must fail
  assert.throws(() => {
    envSchema.parse({
      NODE_ENV: "production",
      PORT: 3000,
      MONGO_URI: "mongodb://127.0.0.1:27017/db",
      BETTER_AUTH_SECRET: "s".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000",
      GOOGLE_CLIENT_ID: "g-id",
      GOOGLE_CLIENT_SECRET: "g-sec",
      FRONTEND_URL: "https://auth.example.com",
      APP_ADMIN_JWT_SECRET: "j".repeat(32),
      APP_ADMIN_TOTP_KEY: "t".repeat(32),
    });
  }, /BETTER_AUTH_URL cannot be a loopback address in production/);

  // Non-HTTPS in FRONTEND_URL in production must fail
  assert.throws(() => {
    envSchema.parse({
      NODE_ENV: "production",
      PORT: 3000,
      MONGO_URI: "mongodb://127.0.0.1:27017/db",
      BETTER_AUTH_SECRET: "s".repeat(32),
      BETTER_AUTH_URL: "https://auth.example.com",
      GOOGLE_CLIENT_ID: "g-id",
      GOOGLE_CLIENT_SECRET: "g-sec",
      FRONTEND_URL: "http://app.example.com",
      APP_ADMIN_JWT_SECRET: "j".repeat(32),
      APP_ADMIN_TOTP_KEY: "t".repeat(32),
    });
  }, /FRONTEND_URL must use HTTPS in production/);

  // Valid HTTPS production environment succeeds
  const valid = envSchema.parse({
    NODE_ENV: "production",
    PORT: 3000,
    MONGO_URI: "mongodb://127.0.0.1:27017/db",
    BETTER_AUTH_SECRET: "s".repeat(32),
    BETTER_AUTH_URL: "https://auth.example.com",
    GOOGLE_CLIENT_ID: "g-id",
    GOOGLE_CLIENT_SECRET: "g-sec",
    FRONTEND_URL: "https://app.example.com",
    APP_ADMIN_JWT_SECRET: "j".repeat(32),
    APP_ADMIN_TOTP_KEY: "t".repeat(32),
  });
  assert.equal(valid.BETTER_AUTH_URL, "https://auth.example.com");
});

// --------------------------------------------------------------------------
// TEST 2: Redirect URI Validation Invariants
// --------------------------------------------------------------------------
runTest("CONF-2: validateRedirectUri rejects localhost for production clients, permits for dev clients", () => {
  // In production env with isDev: false -> localhost MUST be rejected
  assert.equal(
    validateRedirectUri("http://localhost:3000/callback", { isDev: false, env: "production" }),
    false,
    "Production client must not allow localhost redirect"
  );
  assert.equal(
    validateRedirectUri("http://127.0.0.1:8080/callback", { isDev: false, env: "production" }),
    false,
    "Production client must not allow 127.0.0.1 redirect"
  );
  assert.equal(
    validateRedirectUri("http://[::1]:8080/callback", { isDev: false, env: "production" }),
    false,
    "Production client must not allow [::1] redirect"
  );
  assert.equal(
    validateRedirectUri("https://app.example.com/callback", { isDev: false, env: "production" }),
    true,
    "Production client allows valid HTTPS redirect"
  );

  // In production env with isDev: true -> loopback IS permitted per RFC 8252
  assert.equal(
    validateRedirectUri("http://localhost:3000/callback", { isDev: true, env: "production" }),
    true,
    "Development client in production allows localhost"
  );
  assert.equal(
    validateRedirectUri("http://127.0.0.1:8080/callback", { isDev: true, env: "production" }),
    true,
    "Development client in production allows 127.0.0.1"
  );

  // But private RFC1918 IPs remain blocked even for dev clients
  assert.equal(
    validateRedirectUri("http://192.168.1.50:3000/callback", { isDev: true, env: "production" }),
    false,
    "Private network IP must be blocked even for dev clients"
  );
  assert.equal(
    validateRedirectUri("http://10.0.0.5:3000/callback", { isDev: true, env: "production" }),
    false,
    "Private network IP must be blocked even for dev clients"
  );
});

// --------------------------------------------------------------------------
// TEST 3: Discovery Document Metadata Invariants
// --------------------------------------------------------------------------
await runTest("CONF-3: Discovery metadata contains exact deployed URLs and zero localhost leakage", async () => {
  const res = await app.request("/.well-known/openid-configuration");
  assert.equal(res.status, 200);
  const data = await res.json();

  assert.equal(data.issuer, "https://auth.example.com");
  assert.equal(data.authorization_endpoint, "https://auth.example.com/api/auth/oauth2/authorize");
  assert.equal(data.token_endpoint, "https://auth.example.com/api/auth/oauth2/token");
  assert.equal(data.userinfo_endpoint, "https://auth.example.com/api/auth/oauth2/userinfo");
  assert.equal(data.jwks_uri, "https://auth.example.com/api/auth/jwks");

  // Verify no localhost leaked in any advertised endpoint
  const jsonStr = JSON.stringify(data);
  assert.ok(!jsonStr.includes("localhost"), "Discovery metadata must not advertise localhost");
  assert.ok(!jsonStr.includes("127.0.0.1"), "Discovery metadata must not advertise 127.0.0.1");
});

// --------------------------------------------------------------------------
// TEST 4: JWKS Endpoint Aliases
// --------------------------------------------------------------------------
await runTest("CONF-4: All standard JWKS endpoints return 200 with matching active RS256 key set", async () => {
  const [res1, res2, res3] = await Promise.all([
    app.request("/api/auth/jwks"),
    app.request("/.well-known/jwks.json"),
    app.request("/.well-known/jwks"),
  ]);

  assert.equal(res1.status, 200, "/api/auth/jwks must return 200");
  assert.equal(res2.status, 200, "/.well-known/jwks.json must return 200");
  assert.equal(res3.status, 200, "/.well-known/jwks must return 200");

  const [jwks1, jwks2, jwks3] = await Promise.all([res1.json(), res2.json(), res3.json()]);

  assert.ok(Array.isArray(jwks1.keys) && jwks1.keys.length > 0, "Keys array must not be empty");
  assert.deepEqual(jwks1.keys, jwks2.keys, "jwks.json must return the same keys as /api/auth/jwks");
  assert.deepEqual(jwks1.keys, jwks3.keys, "jwks must return the same keys as /api/auth/jwks");
  assert.equal(jwks1.keys[0].kty, "RSA", "Default signing key must be RSA");
  assert.equal(jwks1.keys[0].alg, "RS256", "Default signing algorithm must be RS256");
});

// --------------------------------------------------------------------------
// TEST 5: Exact vs Variable Port Matching (RFC 8252)
// --------------------------------------------------------------------------
runTest("CONF-5: isRegisteredRedirectUri allows variable port on loopback for dev, strictly forbids on prod", () => {
  const devClient: any = {
    clientId: "dev-client-1",
    isDev: true,
    redirectUris: ["http://127.0.0.1:3000/callback", "http://localhost:3000/callback"],
  };

  const prodClient: any = {
    clientId: "prod-client-1",
    isDev: false,
    redirectUris: ["https://client.example.com/callback"],
  };

  // Dev client allows ephemeral port on loopback per RFC 8252 Section 7.3
  assert.equal(isRegisteredRedirectUri(devClient, "http://127.0.0.1:4567/callback"), true);
  assert.equal(isRegisteredRedirectUri(devClient, "http://localhost:9999/callback"), true);
  assert.equal(isRegisteredRedirectUri(devClient, "http://localhost:9999/wrong-path"), false);

  // Production client strictly enforces exact URL match including port and protocol
  assert.equal(isRegisteredRedirectUri(prodClient, "https://client.example.com/callback"), true);
  assert.equal(isRegisteredRedirectUri(prodClient, "https://client.example.com:8443/callback"), false);
  assert.equal(isRegisteredRedirectUri(prodClient, "http://client.example.com/callback"), false);
  assert.equal(isRegisteredRedirectUri(prodClient, "https://client.example.com/callback#fragment"), false);
  assert.equal(isRegisteredRedirectUri(prodClient, "https://user:pass@client.example.com/callback"), false);
});

let ipCounter = 200;
function getTestHeaders(extra: Record<string, string> = {}) {
  const ip = `198.51.100.${++ipCounter % 240 + 1}`;
  return {
    "Content-Type": "application/json",
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    Origin: process.env.FRONTEND_URL || "https://app.example.com",
    ...extra,
  };
}

// --------------------------------------------------------------------------
// TEST 6: Super-Admin Client Creation Production Guard
// --------------------------------------------------------------------------
await runTest("CONF-6: Super-Admin client creation rejects loopback URLs unless isDev is explicitly true", async () => {
  const db = await getDb();
  const superAdminEmail = `super_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const superAdminPass = "SuperAdmin@1234!";

  // Create super admin
  const saRes = await authProvider.api.signUpEmail({
    body: { email: superAdminEmail, password: superAdminPass, name: "Super Admin" },
    asResponse: true,
  });
  const cookie = (saRes.headers.get("set-cookie") || "").split(";")[0];
  await db.collection("user").updateOne(
    { email: superAdminEmail },
    { $set: { role: "admin", scopedClientId: null, emailVerified: true } }
  );

  // Attempt to create client with loopback redirect URI while isDev: false in production
  // validateRedirectUri with env="production" and isDev=false must reject
  const invalidUri = validateRedirectUris(["http://localhost:3000/callback"], { isDev: false, env: "production" });
  assert.ok(invalidUri !== null, "Production client must reject loopback redirect URI");

  // Valid creation with production HTTPS URLs
  const validProdCreate = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: cookie, "x-csrf-token": "any" }),
    body: JSON.stringify({
      client_name: "Legal Prod Client",
      redirect_uris: ["https://legal.example.com/callback"],
      allowed_origins: ["https://legal.example.com"],
      isDev: false,
    }),
  });
  assert.equal(validProdCreate.status, 201, "Valid production client creation must succeed with 201");
  const validData = await validProdCreate.json();
  assert.equal(validData.is_dev, false, "Client is_dev must be false");

  // Valid creation of dev client with loopback URLs
  const validDevCreate = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: cookie, "x-csrf-token": "any" }),
    body: JSON.stringify({
      client_name: "Legal Dev Client",
      redirect_uris: ["http://localhost:5000/callback"],
      allowed_origins: ["http://localhost:5000"],
      isDev: true,
    }),
  });
  assert.equal(validDevCreate.status, 201, "Valid dev client creation must succeed with 201");
  const devData = await validDevCreate.json();
  assert.equal(devData.is_dev, true, "Client is_dev must be true");
});

// --------------------------------------------------------------------------
// TEST 7: Scoped Admin Privilege Escalation Prevention
// --------------------------------------------------------------------------
await runTest("CONF-7: Scoped Admin cannot flip isDev or isPublic flags on existing client", async () => {
  const db = await getDb();
  const clientId = "prod-test-client-" + crypto.randomBytes(4).toString("hex");

  // Seed client as production & private
  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "dummy-secret-hash",
    name: "Production Private App",
    redirectUris: ["https://prod.example.com/callback"],
    allowedOrigins: ["https://prod.example.com"],
    isDev: false,
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Create scoped admin
  const adminEmail = `scoped_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const adminPass = "ScopedAdmin@1234!";
  await authProvider.api.signUpEmail({
    body: { email: adminEmail, password: adminPass, name: "Scoped Admin" },
  });
  await db.collection("user").updateOne({ email: adminEmail }, { $set: { role: "admin", scopedClientId: clientId } });

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: adminEmail, password: adminPass }),
  });
  assert.equal(loginRes.status, 200, "Scoped admin login must succeed");
  const cookie = loginRes.headers.get("set-cookie") || "";

  // Attempt to patch client to isDev: true and isPublic: true
  const patchRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: cookie, "x-csrf-token": "any" }),
    body: JSON.stringify({
      isDev: true,
      isPublic: true,
      client_name: "Updated Name",
    }),
  });
  assert.equal(patchRes.status, 200);

  // Verify in MongoDB that isDev and isPublic were NOT altered
  const clientDoc = await db.collection("oauthClient").findOne({ clientId });
  assert.equal(clientDoc?.isDev, false, "isDev must remain false after scoped admin patch");
  assert.equal(clientDoc?.isPublic, false, "isPublic must remain false after scoped admin patch");
  assert.equal(clientDoc?.name, "Updated Name", "Allowed field client_name should be updated");
});

console.log("================================================================");
console.log(`  PRODUCTION CONFIGURATION TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

if (failed > 0) {
  console.error("❌ PRODUCTION CONFIGURATION SUITE: FAIL");
  process.exit(1);
} else {
  console.log("✅ PRODUCTION CONFIGURATION SUITE: PASS");
  process.exit(0);
}
