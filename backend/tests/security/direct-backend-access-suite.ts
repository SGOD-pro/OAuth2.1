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
const { config } = await import("../../src/config");

console.log("================================================================");
console.log("  SWYRA AUTH -- DIRECT BACKEND ACCESS & PROTOCOL BOUNDARY SUITE");
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

function getTestHeaders(overrides: Record<string, string> = {}): Headers {
  const h = new Headers();
  h.set("host", "auth.example.com");
  h.set("content-type", "application/json");
  for (const [k, v] of Object.entries(overrides)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

// --------------------------------------------------------------------------
// TEST 1: Public Protocol Endpoints are Usable by Direct HTTP (curl-like)
// --------------------------------------------------------------------------
await runTest("DIR-1: Public OIDC Discovery is ALLOWED to unauthenticated curl", async () => {
  const res = await app.request("/.well-known/openid-configuration", {
    method: "GET",
    headers: getTestHeaders({ "User-Agent": "curl/8.5.0", Origin: "" }),
  });
  assert.equal(res.status, 200, "OIDC discovery must return 200 to curl");
  const data = await res.json();
  assert.equal(data.issuer, "https://auth.example.com");
  assert.ok(data.jwks_uri);
  assert.ok(data.authorization_endpoint);
  assert.ok(data.token_endpoint);
});

await runTest("DIR-2: Public JWKS Endpoints are ALLOWED to unauthenticated curl", async () => {
  for (const path of ["/.well-known/jwks.json", "/.well-known/jwks", "/api/auth/jwks"]) {
    const res = await app.request(path, {
      method: "GET",
      headers: getTestHeaders({ "User-Agent": "curl/8.5.0", Origin: "" }),
    });
    assert.equal(res.status, 200, `JWKS on ${path} must return 200 to curl`);
    const data = await res.json();
    assert.ok(Array.isArray(data.keys), "JWKS must contain keys array");
    assert.ok(data.keys.length > 0, "JWKS must contain at least one key");
  }
});

// --------------------------------------------------------------------------
// TEST 3: OAuth Token Endpoint is Accessible to Confidential Clients via Direct POST
// --------------------------------------------------------------------------
await runTest("DIR-3: OAuth token endpoint is exempt from browser CSRF for confidential client curl POST", async () => {
  // A direct curl POST to /api/auth/oauth2/token with invalid client credentials must fail with 400/401 (client error), NOT 403 CSRF!
  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "User-Agent": "curl/8.5.0",
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from("fake-client:fake-secret").toString("base64"),
      Origin: "", // Server-to-server HTTP request has no Origin
    }),
    body: "grant_type=client_credentials",
  });
  // Must return 400 or 401 client error, NEVER 403 CSRF Forbidden
  assert.ok(
    res.status === 400 || res.status === 401,
    `Token endpoint must return 400/401 invalid_client to server curl, got ${res.status}`
  );
  const data = await res.json();
  assert.equal(data.error, "invalid_client");
});

// --------------------------------------------------------------------------
// TEST 4: Direct Access to Admin Management Endpoints Fails Without Session
// --------------------------------------------------------------------------
await runTest("DIR-4: Admin management endpoints strictly DENY unauthenticated curl", async () => {
  const endpoints = [
    { method: "GET", path: "/api/admin/clients" },
    { method: "POST", path: "/api/admin/clients", body: JSON.stringify({ name: "Hacked" }) },
    { method: "GET", path: "/api/admin/users" },
    { method: "GET", path: "/api/admin/stats" },
    { method: "GET", path: "/api/admin/logs" },
  ];

  for (const ep of endpoints) {
    const res = await app.request(ep.path, {
      method: ep.method,
      headers: getTestHeaders({ "User-Agent": "curl/8.5.0", Origin: "" }),
      body: ep.body,
    });
    assert.ok(
      res.status === 401 || res.status === 403,
      `Unauthenticated curl access to ${ep.method} ${ep.path} must return 401 or 403, got ${res.status}`
    );
  }
});

// --------------------------------------------------------------------------
// TEST 5: Forged Origin Rejection on Admin Endpoints
// --------------------------------------------------------------------------
await runTest("DIR-5: Admin endpoints strictly DENY requests with forged malicious Origin", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({
      "User-Agent": "curl/8.5.0",
      Origin: "https://evil-attacker.com",
      Referer: "https://evil-attacker.com/dashboard",
    }),
    body: JSON.stringify({ name: "Attacker Client" }),
  });
  assert.equal(res.status, 403, "Forged origin must be rejected with 403 CSRF");
});

// --------------------------------------------------------------------------
// TEST 6: Regular Authenticated User Cannot Access Admin Management Endpoints
// --------------------------------------------------------------------------
await runTest("DIR-6: Stolen regular user session DENIED on admin endpoints", async () => {
  const db = await getDb();
  const userEmail = `reguser_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const userPass = "NormalUser@1234!";

  await authProvider.api.signUpEmail({
    body: { email: userEmail, password: userPass, name: "Normal User" },
  });

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email: userEmail, password: userPass }),
  });
  assert.equal(loginRes.status, 200);
  const cookie = loginRes.headers.get("set-cookie") || "";

  // Regular user attempts to access /api/admin/clients
  const adminRes = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
  });
  assert.equal(adminRes.status, 403, "Regular user must receive 403 Forbidden on admin endpoints");
  const data = await adminRes.json();
  assert.equal(data.error, "Admin access required");
});

// --------------------------------------------------------------------------
// TEST 7: App Admin Endpoints Require Bearer Token and Reject Direct Curl
// --------------------------------------------------------------------------
await runTest("DIR-7: App Admin management endpoints DENY unauthenticated direct curl", async () => {
  const res = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ "User-Agent": "curl/8.5.0", Origin: "" }),
  });
  assert.ok(
    res.status === 400 || res.status === 401,
    `App admin verify must reject unauthenticated direct curl, got ${res.status}`
  );
  const data = await res.json();
  assert.equal(data.valid, false);

  const forgedRes = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({
      "User-Agent": "curl/8.5.0",
      Authorization: "Bearer forged-jwt-token-string",
    }),
    body: JSON.stringify({
      client_id: "any-client",
      client_secret: "any-secret",
      token: "forged-jwt-token-string",
    }),
  });
  assert.equal(forgedRes.status, 401, "Forged Bearer token must return 401");
  const forgedData = await forgedRes.json();
  assert.equal(forgedData.valid, false);
});

// --------------------------------------------------------------------------
// TEST 8: Internal Dynamic Registration Endpoints Are Strictly Blocked
// --------------------------------------------------------------------------
await runTest("DIR-8: Internal dynamic client registration endpoints return 403 to all callers", async () => {
  const internalRoutes = [
    { method: "POST", path: "/api/auth/oauth2/register" },
    { method: "POST", path: "/api/auth/oauth2/create-client" },
    { method: "POST", path: "/api/auth/oauth2/update-client" },
    { method: "POST", path: "/api/auth/oauth2/delete-client" },
    { method: "GET", path: "/api/auth/oauth2/get-client" },
    { method: "GET", path: "/api/auth/oauth2/get-clients" },
    { method: "POST", path: "/api/auth/oauth2/client/rotate-secret" },
  ];

  for (const route of internalRoutes) {
    const res = await app.request(route.path, {
      method: route.method,
      headers: getTestHeaders({ "User-Agent": "curl/8.5.0" }),
      body: route.method === "POST" ? "{}" : undefined,
    });
    assert.equal(res.status, 403, `${route.method} ${route.path} must return 403 forbidden`);
  }
});

// --------------------------------------------------------------------------
// TEST 9: Forged Client Identity Headers Cannot Bypass Security
// --------------------------------------------------------------------------
await runTest("DIR-9: Forged headers (X-Forwarded-For, Sec-Fetch-Site, User-Agent) cannot bypass auth", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "Sec-Fetch-Site": "same-origin",
      "User-Agent": "Mozilla/5.0 (Internal Healthcheck)",
    }),
  });
  assert.equal(res.status, 401, "Spoofed loopback headers must not bypass admin authentication");
});

// --------------------------------------------------------------------------
// TEST 10: Gateway Secret Enforcement on Internal Boundary
// --------------------------------------------------------------------------
await runTest("DIR-10: Gateway secret enforces server-to-server boundary when configured", async () => {
  const secret = "test-internal-gateway-secret-32-chars!!";
  // Temporarily set gateway secret in config
  process.env.INTERNAL_GATEWAY_SECRET = secret;

  try {
    // Request without gateway secret -> 403 Forbidden
    const deniedRes = await app.request("/api/admin/clients", {
      method: "GET",
      headers: getTestHeaders(),
    });
    assert.equal(deniedRes.status, 403, "Request without gateway secret must be rejected with 403");

    // Request with invalid gateway secret -> 403 Forbidden
    const invalidSecretRes = await app.request("/api/admin/clients", {
      method: "GET",
      headers: getTestHeaders({ "x-gateway-secret": "wrong-secret-value" }),
    });
    assert.equal(invalidSecretRes.status, 403, "Request with wrong gateway secret must be rejected with 403");
  } finally {
    delete process.env.INTERNAL_GATEWAY_SECRET;
  }
});

console.log(`  DIRECT BACKEND SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");
process.exit(failed > 0 ? 1 : 0);
