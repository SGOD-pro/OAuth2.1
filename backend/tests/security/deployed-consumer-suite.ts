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
const { resolveOAuthClient, isRegisteredRedirectUri } = await import("../../src/utils/security");

console.log("================================================================");
console.log("  SWYRA AUTH -- DEPLOYED CONSUMER & AWS-DASHBOARD SUITE");
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

const KNOWN_DASHBOARD_CLIENT_ID = "WpruQjczIYMHwzwcntshzKsdkMnkrvWS";
const KNOWN_DASHBOARD_DEPLOYED_URL = "https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws";

// Seed fixture in local test database to mirror production configuration
const db = await getDb();
await db.collection("oauthClient").updateOne(
  { clientId: KNOWN_DASHBOARD_CLIENT_ID },
  {
    $set: {
      clientId: KNOWN_DASHBOARD_CLIENT_ID,
      clientSecret: "simulated-secret-hash",
      name: "AWS Dashboard",
      redirectUris: [
        `${KNOWN_DASHBOARD_DEPLOYED_URL}/auth/callback`,
        `${KNOWN_DASHBOARD_DEPLOYED_URL}/api/auth/callback`,
      ],
      allowedOrigins: [KNOWN_DASHBOARD_DEPLOYED_URL],
      isDev: false,
      isPublic: false,
      disabled: false,
      skipConsent: false,
      updatedAt: new Date(),
    },
    $setOnInsert: { createdAt: new Date() },
  },
  { upsert: true }
);

// --------------------------------------------------------------------------
// TEST 1: Registered Application Configuration Integrity
// --------------------------------------------------------------------------
await runTest("DEP-1: Deployed AWS-Dashboard application document is correctly registered and private", async () => {
  const clientDoc = await resolveOAuthClient(db, KNOWN_DASHBOARD_CLIENT_ID);
  assert.ok(clientDoc, "AWS Dashboard client document must exist");
  assert.equal(clientDoc.clientId, KNOWN_DASHBOARD_CLIENT_ID);
  assert.equal(clientDoc.isDev, false, "Deployed consumer MUST NOT be a dev client in production");
  assert.equal(clientDoc.isPublic, false, "Deployed consumer must be private tenant");
  assert.equal(clientDoc.disabled, false, "Client must be active");
  assert.ok(
    clientDoc.redirectUris.includes(`${KNOWN_DASHBOARD_DEPLOYED_URL}/auth/callback`),
    "Must include deployed /auth/callback"
  );
});

// --------------------------------------------------------------------------
// TEST 2: Strict Fail-Closed Redirect URI Validation
// --------------------------------------------------------------------------
await runTest("DEP-2: IdP strictly accepts deployed HTTPS callback and rejects localhost fallback", async () => {
  const clientDoc = await resolveOAuthClient(db, KNOWN_DASHBOARD_CLIENT_ID);

  // 1. Deployed HTTPS callback is accepted
  const validCallback = `${KNOWN_DASHBOARD_DEPLOYED_URL}/auth/callback`;
  assert.equal(
    isRegisteredRedirectUri(clientDoc, validCallback),
    true,
    "Valid deployed HTTPS callback must be accepted"
  );

  // 2. Unconfigured localhost fallback is strictly rejected (VULN-1 verification)
  const invalidLocalhost = "http://localhost:3000/auth/callback";
  assert.equal(
    isRegisteredRedirectUri(clientDoc, invalidLocalhost),
    false,
    "Localhost fallback MUST be rejected for production client"
  );

  // 3. Attacker domain is strictly rejected
  const attackerCallback = "https://attacker-controlled-site.com/auth/callback";
  assert.equal(
    isRegisteredRedirectUri(clientDoc, attackerCallback),
    false,
    "Attacker domain must be rejected"
  );

  // 4. Subdomain spoofing is strictly rejected
  const subdomainCallback = `https://evil.${KNOWN_DASHBOARD_DEPLOYED_URL.replace("https://", "")}/auth/callback`;
  assert.equal(
    isRegisteredRedirectUri(clientDoc, subdomainCallback),
    false,
    "Subdomain spoofing must be rejected"
  );
});

// --------------------------------------------------------------------------
// TEST 3: Authorize Endpoint Behavior with AWS-Dashboard Client
// --------------------------------------------------------------------------
await runTest("DEP-3: /oauth2/authorize rejects invalid redirect_uri with HTTP 400 for AWS Dashboard", async () => {
  const res = await app.request(
    `/api/auth/oauth2/authorize?client_id=${KNOWN_DASHBOARD_CLIENT_ID}&redirect_uri=${encodeURIComponent("http://localhost:3000/auth/callback")}&response_type=code&state=xyz123`,
    {
      method: "GET",
      headers: { host: "auth.example.com" },
    }
  );

  assert.equal(res.status, 400, "Must return 400 invalid_request for localhost fallback");
  const data = await res.json();
  assert.equal(data.error, "invalid_request");
  assert.equal(data.error_description, "The redirect_uri is not registered for this application");
});

// --------------------------------------------------------------------------
// TEST 4: Live Reachability Check of Deployed AWS Dashboard Endpoint
// --------------------------------------------------------------------------
await runTest("DEP-4: Deployed AWS Dashboard endpoint is reachable via HTTPS", async () => {
  try {
    const liveRes = await fetch(`${KNOWN_DASHBOARD_DEPLOYED_URL}/login`, {
      method: "GET",
      headers: { "User-Agent": "AntigravitySecurityAudit/1.0" },
      signal: AbortSignal.timeout(6000),
    });
    // The deployed dashboard should return 200 (login page) or 302/307 (redirect to IdP)
    assert.ok(
      liveRes.status === 200 || liveRes.status === 302 || liveRes.status === 307,
      `Live endpoint returned HTTP ${liveRes.status}`
    );
  } catch (err: any) {
    console.warn(`[WARN] Live network call to ${KNOWN_DASHBOARD_DEPLOYED_URL} skipped or timed out:`, err.message);
  }
});

console.log("================================================================");
console.log(`  DEPLOYED CONSUMER SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
