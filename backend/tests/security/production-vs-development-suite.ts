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
const { envSchema } = await import("../../src/config/schema");
const { validateRedirectUri, validateRedirectUris, isRegisteredRedirectUri } = await import("../../src/utils/security");

console.log("================================================================");
console.log("  SWYRA AUTH -- PRODUCTION VS DEVELOPMENT CONFIGURATION SUITE");
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
// TEST 1: envSchema Strict Production Fail-Closed Requirements
// --------------------------------------------------------------------------
await runTest("PROD-1: envSchema strictly rejects non-HTTPS and localhost URLs in production", () => {
  // Rejects http:// BETTER_AUTH_URL
  assert.throws(() => {
    envSchema.parse({
      NODE_ENV: "production",
      PORT: 3000,
      MONGO_URI: "mongodb://127.0.0.1:27017/db",
      BETTER_AUTH_SECRET: "s".repeat(32),
      BETTER_AUTH_URL: "http://auth.example.com",
      GOOGLE_CLIENT_ID: "g-id",
      GOOGLE_CLIENT_SECRET: "g-sec",
      FRONTEND_URL: "https://app.example.com",
      APP_ADMIN_JWT_SECRET: "j".repeat(32),
      APP_ADMIN_TOTP_KEY: "t".repeat(32),
    });
  }, /BETTER_AUTH_URL must use HTTPS in production/);

  // Rejects localhost BETTER_AUTH_URL in production
  assert.throws(() => {
    envSchema.parse({
      NODE_ENV: "production",
      PORT: 3000,
      MONGO_URI: "mongodb://127.0.0.1:27017/db",
      BETTER_AUTH_SECRET: "s".repeat(32),
      BETTER_AUTH_URL: "https://localhost:3000",
      GOOGLE_CLIENT_ID: "g-id",
      GOOGLE_CLIENT_SECRET: "g-sec",
      FRONTEND_URL: "https://app.example.com",
      APP_ADMIN_JWT_SECRET: "j".repeat(32),
      APP_ADMIN_TOTP_KEY: "t".repeat(32),
    });
  }, /BETTER_AUTH_URL cannot be a loopback address in production/);

  // Rejects missing APP_ADMIN_JWT_SECRET in production
  assert.throws(() => {
    envSchema.parse({
      NODE_ENV: "production",
      PORT: 3000,
      MONGO_URI: "mongodb://127.0.0.1:27017/db",
      BETTER_AUTH_SECRET: "s".repeat(32),
      BETTER_AUTH_URL: "https://auth.example.com",
      GOOGLE_CLIENT_ID: "g-id",
      GOOGLE_CLIENT_SECRET: "g-sec",
      FRONTEND_URL: "https://app.example.com",
      APP_ADMIN_TOTP_KEY: "t".repeat(32),
    });
  }, /APP_ADMIN_JWT_SECRET is required in production/);

  // Rejects short secrets (<32 characters)
  assert.throws(() => {
    envSchema.parse({
      NODE_ENV: "production",
      PORT: 3000,
      MONGO_URI: "mongodb://127.0.0.1:27017/db",
      BETTER_AUTH_SECRET: "short-secret",
      BETTER_AUTH_URL: "https://auth.example.com",
      GOOGLE_CLIENT_ID: "g-id",
      GOOGLE_CLIENT_SECRET: "g-sec",
      FRONTEND_URL: "https://app.example.com",
      APP_ADMIN_JWT_SECRET: "j".repeat(32),
      APP_ADMIN_TOTP_KEY: "t".repeat(32),
    });
  }, />=32 characters|too_small/);
});

// --------------------------------------------------------------------------
// TEST 2: ALLOW_DEV_CLIENTS_IN_PRODUCTION Enforcement
// --------------------------------------------------------------------------
await runTest("PROD-2: validateRedirectUri strictly rejects localhost in production when allowDevInProd is false", () => {
  // When allowDevInProd is false, even isDev: true MUST NOT allow localhost redirect
  assert.equal(
    validateRedirectUri("http://localhost:3000/callback", {
      isDev: true,
      env: "production",
      allowDevInProd: false,
    }),
    false,
    "When allowDevInProd=false, dev client in production cannot register localhost"
  );

  // Production client without dev mode always rejects localhost
  assert.equal(
    validateRedirectUri("http://localhost:3000/callback", {
      isDev: false,
      env: "production",
    }),
    false,
    "Production client without dev mode strictly rejects localhost"
  );

  // Valid HTTPS domain is allowed
  assert.equal(
    validateRedirectUri("https://app.example.com/callback", {
      isDev: false,
      env: "production",
    }),
    true,
    "Valid HTTPS URL is allowed in production"
  );
});

// --------------------------------------------------------------------------
// TEST 3: SSRF / Private IP Range Blocking in Redirect URIs
// --------------------------------------------------------------------------
await runTest("PROD-3: validateRedirectUri strictly rejects private/intranet IP addresses (SSRF)", () => {
  const privateIps = [
    "http://10.0.0.1/callback",
    "http://172.16.0.1/callback",
    "http://192.168.1.1/callback",
    "http://169.254.169.254/latest/meta-data", // AWS IMDSv1 SSRF vector
    "https://10.0.0.1/callback",
    "https://169.254.169.254/callback",
  ];

  for (const uri of privateIps) {
    assert.equal(
      validateRedirectUri(uri, { env: "production" }),
      false,
      `Private IP redirect URI ${uri} must be strictly rejected`
    );
  }
});

// --------------------------------------------------------------------------
// TEST 4: OIDC Discovery Document Production URL Inspection
// --------------------------------------------------------------------------
await runTest("PROD-4: OIDC discovery document contains zero localhost references and only HTTPS", async () => {
  const res = await app.request("/.well-known/openid-configuration", {
    method: "GET",
    headers: { host: "auth.example.com" },
  });
  assert.equal(res.status, 200);
  const data = await res.json();
  const text = JSON.stringify(data);

  assert.ok(!text.includes("localhost"), "Discovery metadata must contain zero localhost references");
  assert.ok(!text.includes("127.0.0.1"), "Discovery metadata must contain zero 127.0.0.1 references");
  assert.ok(!text.includes("http://"), "Discovery metadata must NOT contain any unencrypted http:// URLs");

  assert.equal(data.issuer, "https://auth.example.com");
  assert.ok(data.authorization_endpoint.startsWith("https://"));
  assert.ok(data.token_endpoint.startsWith("https://"));
  assert.ok(data.jwks_uri.startsWith("https://"));
});

// --------------------------------------------------------------------------
// TEST 5: Loopback Variable Port Enforcement
// --------------------------------------------------------------------------
await runTest("PROD-5: isRegisteredRedirectUri allows variable port on loopback ONLY in dev mode", () => {
  const devClient = {
    clientId: "dev-client",
    redirectUris: ["http://localhost:3000/callback"],
    isDev: true,
  };
  const prodClient = {
    clientId: "prod-client",
    redirectUris: ["https://app.example.com:8443/callback"],
    isDev: false,
  };

  // Dev client with loopback allows ephemeral port (RFC 8252)
  assert.equal(
    isRegisteredRedirectUri(devClient, "http://localhost:54321/callback"),
    true,
    "Dev client allows variable loopback port"
  );

  // Prod client strictly forbids port tampering
  assert.equal(
    isRegisteredRedirectUri(prodClient, "https://app.example.com:9999/callback"),
    false,
    "Prod client strictly forbids different port"
  );
});

console.log("================================================================");
console.log(`  PRODUCTION CONFIG SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
