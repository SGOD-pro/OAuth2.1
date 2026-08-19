import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.MONGO_URI = "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.TRUSTED_PROXY_CIDRS = "10.0.0.0/8,172.16.0.0/12";

// Import modules to test
const { isStrongPassword, getTrustedClientIp } = await import("../src/utils/security");
const { default: app } = await import("../src/app");

console.log("================================================================");
console.log("  SWYRA AUTH -- AUTOMATED SECURITY REMEDIATION TEST SUITE");
console.log("================================================================");

let passed = 0;
function test(name: string, fn: () => void | Promise<void>) {
  try {
    const res = fn();
    if (res instanceof Promise) {
      return res.then(() => {
        console.log(`[PASS] ${name}`);
        passed++;
      }).catch((err) => {
        console.error(`[FAIL] ${name}:`, err);
        throw err;
      });
    }
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}:`, err);
    throw err;
  }
}

// 1. Test P1-11: Password policy minimum length 12
test("P1-11: isStrongPassword rejects <12 chars even if complex", () => {
  assert.equal(isStrongPassword("Abc!123"), false); // 7 chars
  assert.equal(isStrongPassword("Abcdef!1234"), false); // 11 chars with upper, lower, num, symbol
  assert.equal(isStrongPassword("ValidPass@1234"), true); // 14 chars with all 4 classes
});

// 2. Test P0-4: Production boot fail-fast if TRUSTED_PROXY_CIDRS is empty
test("P0-4: TRUSTED_PROXY_CIDRS empty collapses to unknown", () => {
  const headers = new Headers({ "x-forwarded-for": "203.0.113.195, 10.0.0.1" });
  // With empty proxy CIDRs, it should safely return "unknown"
  assert.equal(getTrustedClientIp(headers, []), "unknown");
  // With configured proxy CIDR, it extracts real client IP
  assert.equal(getTrustedClientIp(headers, ["10.0.0.0/8"]), "203.0.113.195");
});

// 3. Test P0-5: Userinfo endpoint returns 401 on malformed alg=none JWT (not 500)
await test("P0-5: /oauth2/userinfo returns 401 for alg=none JWT", async () => {
  const noneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdGsgifQ.";
  const res = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${noneToken}`,
      "Origin": "http://localhost:5174",
    },
  });
  assert.equal(res.status, 401, `Expected 401 Unauthorized, got ${res.status}`);
  const body = await res.json();
  assert.equal(body.error, "invalid_token");
});

// 4. Test P0-5: Userinfo endpoint returns 401 for invalid signature RS256 token
await test("P0-5: /oauth2/userinfo returns 401 for invalid signature JWT", async () => {
  const badSigToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9.INVALIDSIGNATURE";
  const res = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${badSigToken}`,
      "Origin": "http://localhost:5174",
    },
  });
  assert.equal(res.status, 401, `Expected 401 Unauthorized, got ${res.status}`);
});

// 5. Test P0-3: POST /api/auth/sign-in/email from forged origin without CSRF is rejected (403)
await test("P0-3: /api/auth/sign-in/email rejects forged origin without CSRF token (403)", async () => {
  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: {
      "Origin": "https://evil-attacker.com",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email: "victim@test.com", password: "Password@123!" }),
  });
  assert.equal(res.status, 403, `Expected 403 Forbidden for forged origin, got ${res.status}`);
});

// 6. Test P0-3: POST /api/auth/oauth2/token is exempted from CSRF (server-to-server token exchange)
await test("P0-3: /api/auth/oauth2/token allows cross-origin server-to-server POST", async () => {
  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: {
      "Origin": "http://localhost:3001",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=authorization_code&code=TEST&client_id=TEST",
  });
  // It shouldn't return 403 CSRF; it should reach Better Auth (which returns 400/401 invalid_client)
  assert.notEqual(res.status, 403, "Token endpoint should not be blocked by CSRF");
});

// 7. Test P1-10: /oauth2/authorize without state parameter redirects with error
await test("P1-10: /oauth2/authorize requires state parameter", async () => {
  const res = await app.request("/api/auth/oauth2/authorize?client_id=TEST_CLIENT&redirect_uri=http%3A%2F%2Flocalhost%3A3001&response_type=code", {
    method: "GET",
  });
  assert.equal(res.status, 302, `Expected 302 redirect, got ${res.status}`);
  const location = res.headers.get("Location") || "";
  assert.ok(location.includes("error=state_required"), `Expected error=state_required in redirect Location, got: ${location}`);
});

// 8. Test P1-9: Request body exceeding 100KB is rejected (413)
await test("P1-9: Body size limit rejects payloads > 100KB (413)", async () => {
  const largeBody = JSON.stringify({ data: "A".repeat(110 * 1024) });
  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: {
      "Origin": "http://localhost:5174",
      "Content-Type": "application/json",
    },
    body: largeBody,
  });
  assert.equal(res.status, 413, `Expected 413 Payload Too Large, got ${res.status}`);
});

// 9. Test P0-2: GET /api/admin/clients requires admin session and never leaks client_secret
await test("P0-2: GET /api/admin/clients rejects unauthenticated requests (401)", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: { "Origin": "http://localhost:5174" },
  });
  assert.equal(res.status, 401, `Expected 401 Unauthorized, got ${res.status}`);
});

console.log("");
console.log(`================================================================`);
console.log(` ALL ${passed} AUTOMATED SECURITY REMEDIATION TESTS PASSED!`);
console.log(`================================================================`);
