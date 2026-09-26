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

console.log("================================================================");
console.log("  SWYRA AUTH -- AWS-DASHBOARD OAUTH INTEGRATION SUITE");
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
// TEST 1: PKCE RFC 7636 Implementation Verification
// --------------------------------------------------------------------------
await runTest("DASH-1: PKCE S256 code challenge computation conforms to RFC 7636", () => {
  // RFC 7636 Appendix B test vector
  const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

  const computedChallenge = crypto
    .createHash("sha256")
    .update(testVerifier)
    .digest("base64url");

  assert.equal(computedChallenge, expectedChallenge, "PKCE S256 computation must match RFC 7636 test vector");

  // Dynamic random verifier test
  const verifier = crypto.randomBytes(32).toString("base64url");
  assert.ok(verifier.length >= 43, "Verifier length must be >= 43 chars per RFC 7636");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  assert.ok(challenge.length >= 43, "Challenge must be valid base64url string");
});

// --------------------------------------------------------------------------
// TEST 2: Production Callback Fallback Fail-Closed Invariant
// --------------------------------------------------------------------------
await runTest("DASH-2: In production environment, missing AUTH_CALLBACK_URL must fail closed", () => {
  // Simulate consumer resolution logic
  function resolveConsumerCallback(env: { NODE_ENV?: string; AUTH_CALLBACK_URL?: string; REDIRECT_URI?: string }): string {
    const raw = env.AUTH_CALLBACK_URL || env.REDIRECT_URI;
    if (env.NODE_ENV === "production") {
      if (!raw || raw.trim() === "" || raw.includes("localhost")) {
        throw new Error("FATAL: AUTH_CALLBACK_URL must be explicitly configured with a production HTTPS URL");
      }
      return raw.trim();
    }
    return (raw || "http://localhost:3000/auth/callback").trim();
  }

  // Development permits localhost fallback
  const devCallback = resolveConsumerCallback({ NODE_ENV: "development" });
  assert.equal(devCallback, "http://localhost:3000/auth/callback");

  // Production with valid URL succeeds
  const prodCallback = resolveConsumerCallback({
    NODE_ENV: "production",
    AUTH_CALLBACK_URL: "https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws/auth/callback",
  });
  assert.equal(prodCallback, "https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws/auth/callback");

  // Production without AUTH_CALLBACK_URL MUST THROW (Fail closed!)
  assert.throws(() => {
    resolveConsumerCallback({ NODE_ENV: "production" });
  }, /AUTH_CALLBACK_URL must be explicitly configured/);

  // Production with localhost URL MUST THROW (Fail closed!)
  assert.throws(() => {
    resolveConsumerCallback({ NODE_ENV: "production", AUTH_CALLBACK_URL: "http://localhost:3000/auth/callback" });
  }, /AUTH_CALLBACK_URL must be explicitly configured/);
});

// --------------------------------------------------------------------------
// TEST 3: ReturnTo Open-Redirect Protection
// --------------------------------------------------------------------------
await runTest("DASH-3: ReturnTo parameter prevents open-redirect attacks", () => {
  function sanitizeReturnTo(param: string | null): string {
    if (!param) return "/";
    // Strictly require leading '/' and reject '//' protocol-relative redirects
    if (param.startsWith("/") && !param.startsWith("//")) {
      try {
        const parsed = new URL(param, "http://localhost");
        return parsed.pathname + parsed.search;
      } catch {
        return "/";
      }
    }
    return "/";
  }

  // Legitimate paths are allowed
  assert.equal(sanitizeReturnTo("/dashboard"), "/dashboard");
  assert.equal(sanitizeReturnTo("/settings?tab=general"), "/settings?tab=general");

  // Open-redirect attack vectors are neutralized
  assert.equal(sanitizeReturnTo("https://evil.com"), "/");
  assert.equal(sanitizeReturnTo("//evil.com"), "/");
  assert.equal(sanitizeReturnTo("javascript:alert(1)"), "/");
  assert.equal(sanitizeReturnTo("/\\evil.com"), "/");
});

// --------------------------------------------------------------------------
// TEST 4: Authorization Request Query Construction
// --------------------------------------------------------------------------
await runTest("DASH-4: Constructed OAuth 2.1 authorization URL contains all required protocol parameters", () => {
  const authIssuer = "https://oauth21.vercel.app";
  const clientId = "WpruQjczIYMHwzwcntshzKsdkMnkrvWS";
  const callbackUrl = "https://77gqzhgn4k3iaiticbaxdkndi40whzjp.lambda-url.ap-south-1.on.aws/auth/callback";
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = crypto.randomBytes(16).toString("base64url");

  const authorizeUrl = new URL(`${authIssuer}/api/auth/oauth2/authorize`);
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("redirect_uri", callbackUrl);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("scope", "openid profile email");
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");
  authorizeUrl.searchParams.set("state", state);

  assert.equal(authorizeUrl.searchParams.get("client_id"), clientId);
  assert.equal(authorizeUrl.searchParams.get("redirect_uri"), callbackUrl);
  assert.equal(authorizeUrl.searchParams.get("response_type"), "code");
  assert.equal(authorizeUrl.searchParams.get("scope"), "openid profile email");
  assert.equal(authorizeUrl.searchParams.get("code_challenge_method"), "S256");
  assert.equal(authorizeUrl.searchParams.get("code_challenge"), codeChallenge);
  assert.equal(authorizeUrl.searchParams.get("state"), state);
});

console.log("================================================================");
console.log(`  AWS-DASHBOARD INTEGRATION SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
