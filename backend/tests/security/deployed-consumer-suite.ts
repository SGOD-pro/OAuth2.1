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

const KNOWN_DASHBOARD_CLIENT_ID = "vIaLkLJZpfMesoHlhJHNGOtnFRTcbzUx";
const KNOWN_DASHBOARD_DEPLOYED_URL = "https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws";

// Seed fixture in local test database to mirror production configuration
const db = await getDb();
await db.collection("oauthClient").updateOne(
  { clientId: KNOWN_DASHBOARD_CLIENT_ID },
  {
    $set: {
      clientId: KNOWN_DASHBOARD_CLIENT_ID,
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
    $setOnInsert: {
      createdAt: new Date(),
      clientSecret: "A1BRanE7qugJuDbx_sm8HBlXqGeCtJQt_2GyHxLZYk4",
      client_secret: "A1BRanE7qugJuDbx_sm8HBlXqGeCtJQt_2GyHxLZYk4",
    },
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
// Helper for live network calls with retry and 25s cold-start tolerance
async function fetchWithRetry(url: string, options: RequestInit = {}, maxRetries = 4): Promise<Response> {
  let lastErr: any;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const signal = options.signal || AbortSignal.timeout(25000);
      return await fetch(url, { ...options, signal });
    } catch (err: any) {
      lastErr = err;
      if (attempt < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, 1500 * (attempt + 1)));
      }
    }
  }
  throw lastErr;
}

// --------------------------------------------------------------------------
// TEST 4: Live Reachability Check of Deployed AWS Dashboard UI Endpoint
// --------------------------------------------------------------------------
await runTest("DEP-4: Deployed AWS Dashboard endpoint is reachable via HTTPS and returns UI", async () => {
  const liveRes = await fetchWithRetry(`${KNOWN_DASHBOARD_DEPLOYED_URL}/login`, {
    method: "GET",
    headers: { "User-Agent": "AntigravitySecurityAudit/1.0" },
  });
  assert.equal(liveRes.status, 200, "Deployed dashboard login page must return HTTP 200");
  const html = await liveRes.text();
  assert.ok(html.includes("SWYRA") || html.includes("Lambda") || html.includes("login"), "Response must contain dashboard UI content");
});

// --------------------------------------------------------------------------
// TEST 5: Live Consumer Auth Login Initiates Valid OAuth 2.1 PKCE Flow
// --------------------------------------------------------------------------
let liveAuthUrl = "";
await runTest("DEP-5: Live consumer /api/auth/login initiates OAuth 2.1 PKCE redirect", async () => {
  const loginRes = await fetchWithRetry(`${KNOWN_DASHBOARD_DEPLOYED_URL}/api/auth/login`, {
    method: "GET",
    headers: { "User-Agent": "AntigravitySecurityAudit/1.0" },
    redirect: "manual",
  });

  assert.equal(loginRes.status, 307, "Must return HTTP 307 Temporary Redirect");
  const location = loginRes.headers.get("location") || "";
  assert.ok(location.includes("/oauth2/authorize"), "Location must point to OAuth authorize endpoint");
  assert.ok(
    location.includes(`client_id=${KNOWN_DASHBOARD_CLIENT_ID}`) ||
    location.includes("client_id=vIaLkLJZpfMesoHlhJHNGOtnFRTcbzUx"),
    "Must include dashboard client_id"
  );
  assert.ok(location.includes("code_challenge="), "Must include PKCE code_challenge");
  assert.ok(location.includes("code_challenge_method=S256"), "Must require S256 code challenge method");

  // Verify cookies are set for PKCE verifier and state (or unified encrypted transaction cookie)
  const setCookie = loginRes.headers.get("set-cookie") || "";
  assert.ok(
    setCookie.includes("oauth_verifier") || setCookie.includes("swyra_pkce_verifier") || setCookie.includes("swyra_oauth_tx"),
    "Must set PKCE verifier cookie"
  );
  assert.ok(
    setCookie.includes("oauth_state") || setCookie.includes("swyra_auth_state") || setCookie.includes("swyra_oauth_tx"),
    "Must set OAuth state cookie"
  );

  liveAuthUrl = location;
});

// --------------------------------------------------------------------------
// TEST 6: Live IdP Discovery & JWKS RFC Compliance
// --------------------------------------------------------------------------
await runTest("DEP-6: Live IdP Discovery and JWKS endpoints return valid production RFC metadata", async () => {
  const discRes = await fetchWithRetry("https://oauth21.vercel.app/.well-known/openid-configuration");
  assert.equal(discRes.status, 200, "Discovery must return 200");
  const disc = await discRes.json();
  assert.equal(disc.issuer, "https://oauth21.vercel.app", "Issuer must match live production origin");
  assert.ok(disc.jwks_uri, "JWKS URI must be present");
  assert.ok(disc.authorization_endpoint, "Authorization endpoint must be present");
  assert.ok(disc.token_endpoint, "Token endpoint must be present");

  const jwksRes = await fetchWithRetry(disc.jwks_uri);
  assert.equal(jwksRes.status, 200, "JWKS must return 200");
  const jwks = await jwksRes.json();
  assert.ok(Array.isArray(jwks.keys), "JWKS must contain keys array");
  assert.ok(jwks.keys.length > 0, "JWKS must contain at least one public key");
});

// --------------------------------------------------------------------------
// TEST 7: Live IdP + Live Consumer Fail-Closed Redirect Verification
// --------------------------------------------------------------------------
await runTest("DEP-7: Live IdP strictly fails closed against unconfigured consumer localhost callback", async () => {
  const unconfiguredUrl = new URL("https://oauth21.vercel.app/api/auth/oauth2/authorize");
  unconfiguredUrl.searchParams.set("client_id", KNOWN_DASHBOARD_CLIENT_ID);
  unconfiguredUrl.searchParams.set("redirect_uri", "http://localhost:3000/auth/callback");
  unconfiguredUrl.searchParams.set("response_type", "code");
  unconfiguredUrl.searchParams.set("state", "test_state");

  const idpRes = await fetchWithRetry(unconfiguredUrl.toString(), {
    method: "GET",
    headers: { "User-Agent": "AntigravitySecurityAudit/1.0" },
    redirect: "manual",
  });

  // The live IdP MUST fail closed because localhost:3000 callback is rejected in production
  assert.equal(idpRes.status, 400, "Live IdP must return HTTP 400 for unregistered redirect_uri");
  const data = await idpRes.json();
  assert.equal(data.error, "invalid_request");
  assert.equal(data.error_description, "The redirect_uri is not registered for this application");
});

// --------------------------------------------------------------------------
// TEST 8: Live IdP Accepts Registered Production Callback for AWS Dashboard
// --------------------------------------------------------------------------
await runTest("DEP-8: Live IdP accepts registered HTTPS callback for deployed AWS Dashboard", async () => {
  const registeredCallback = `${KNOWN_DASHBOARD_DEPLOYED_URL}/auth/callback`;
  const validLiveUrl = new URL("https://oauth21.vercel.app/api/auth/oauth2/authorize");
  validLiveUrl.searchParams.set("client_id", KNOWN_DASHBOARD_CLIENT_ID);
  validLiveUrl.searchParams.set("redirect_uri", registeredCallback);
  validLiveUrl.searchParams.set("response_type", "code");
  validLiveUrl.searchParams.set("scope", "openid profile email");
  validLiveUrl.searchParams.set("state", "test_live_state_" + crypto.randomBytes(4).toString("hex"));
  validLiveUrl.searchParams.set("code_challenge", crypto.randomBytes(32).toString("base64url"));
  validLiveUrl.searchParams.set("code_challenge_method", "S256");

  const idpRes = await fetchWithRetry(validLiveUrl.toString(), {
    method: "GET",
    headers: { "User-Agent": "AntigravitySecurityAudit/1.0" },
    redirect: "manual",
  });

  // The live IdP should accept the registered redirect URI and redirect to login/consent (302)
  // instead of rejecting with HTTP 400
  assert.notEqual(idpRes.status, 400, "Must NOT return 400 invalid_request for registered HTTPS callback");
  assert.ok(
    idpRes.status === 302 || idpRes.status === 200,
    `Registered callback should proceed to login flow (got ${idpRes.status})`
  );
});

console.log("================================================================");
console.log(`  DEPLOYED CONSUMER SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
