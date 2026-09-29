import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.MONGO_URI = "mongodb://172.25.240.1:27017/test";
process.env.BETTER_AUTH_SECRET = "x".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = "test";
process.env.GOOGLE_CLIENT_SECRET = "test";
process.env.FRONTEND_URL = "http://localhost:5173";
process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION = "true";

const {
  getTrustedClientIp,
  isLoopbackHost,
  isPrivateOrLocalHost,
  isStrongPassword,
  originMatchesRedirectUri,
  safeCallbackURL,
  validateRedirectUri,
} = await import("../src/utils/security");

const { envSchema } = await import("../src/config/schema");

// --------------------------------------------------------------------------
// 1. Production Configuration Contract Validation
// --------------------------------------------------------------------------

const baseProdConfig = {
  NODE_ENV: "production",
  PORT: 3000,
  MONGO_URI: "mongodb://127.0.0.1:27017/prod_db",
  BETTER_AUTH_SECRET: "s".repeat(32),
  BETTER_AUTH_URL: "https://auth.example.com",
  FRONTEND_URL: "https://auth.example.com",
  GOOGLE_CLIENT_ID: "google-prod-id",
  GOOGLE_CLIENT_SECRET: "google-prod-secret",
  APP_ADMIN_JWT_SECRET: "a".repeat(32),
  APP_ADMIN_TOTP_KEY: "b".repeat(32),
  INTERNAL_GATEWAY_SECRET: "g".repeat(32),
  ALLOW_DEV_CLIENTS_IN_PRODUCTION: "false",
};

// 1A: Production + missing INTERNAL_GATEWAY_SECRET => rejected
const missingGatewayRes = envSchema.safeParse({
  ...baseProdConfig,
  INTERNAL_GATEWAY_SECRET: undefined,
});
assert.equal(missingGatewayRes.success, false, "Production without INTERNAL_GATEWAY_SECRET must fail closed");

// 1B: Production + weak INTERNAL_GATEWAY_SECRET (< 32 chars) => rejected
const weakGatewayRes = envSchema.safeParse({
  ...baseProdConfig,
  INTERNAL_GATEWAY_SECRET: "too-short-secret-under-32-chars",
});
assert.equal(weakGatewayRes.success, false, "Production with weak INTERNAL_GATEWAY_SECRET must fail closed");

// 1C: Production + valid INTERNAL_GATEWAY_SECRET (>= 32 chars) => accepted
const validGatewayRes = envSchema.safeParse(baseProdConfig);
assert.equal(validGatewayRes.success, true, "Production with valid configuration must pass");

// 1D: Development / test modes remain compatible without mandatory gateway secret
const validDevConfig = envSchema.safeParse({
  NODE_ENV: "development",
  MONGO_URI: "mongodb://127.0.0.1:27017/dev_db",
  BETTER_AUTH_SECRET: "d".repeat(32),
  BETTER_AUTH_URL: "http://localhost:3000",
  FRONTEND_URL: "http://localhost:5173",
  GOOGLE_CLIENT_ID: "google-dev-id",
  GOOGLE_CLIENT_SECRET: "google-dev-secret",
});
assert.equal(validDevConfig.success, true, "Development mode without gateway secret must be accepted");

// --------------------------------------------------------------------------
// 2. ALLOW_DEV_CLIENTS_IN_PRODUCTION Enforcement
// --------------------------------------------------------------------------

// When ALLOW_DEV_CLIENTS_IN_PRODUCTION is false: dev client with loopback redirect is rejected in production
assert.equal(
  validateRedirectUri("http://localhost:3001/api/auth/callback", { isDev: true, env: "production", allowDevInProd: false }),
  false,
  "Dev client loopback MUST be rejected in production when allowDevInProd is false"
);
assert.equal(
  validateRedirectUri("https://app.example.com/callback", { isDev: true, env: "production", allowDevInProd: false }),
  true,
  "Public HTTPS client remains valid when allowDevInProd is false"
);

// When ALLOW_DEV_CLIENTS_IN_PRODUCTION is true: dev client loopback is permitted, but private networks remain blocked
assert.equal(
  validateRedirectUri("http://localhost:3001/api/auth/callback", { isDev: true, env: "production", allowDevInProd: true }),
  true,
  "Dev client loopback is permitted in production when allowDevInProd is true"
);
assert.equal(
  validateRedirectUri("http://192.168.1.1/api/auth/callback", { isDev: true, env: "production", allowDevInProd: true }),
  false,
  "Private RFC1918 network must NEVER be permitted in production even with allowDevInProd=true"
);
assert.equal(
  validateRedirectUri("http://169.254.169.254/cb", { isDev: true, env: "production", allowDevInProd: true }),
  false,
  "AWS/Cloud metadata IP must NEVER be permitted in production"
);

// --------------------------------------------------------------------------
// 3. General Security Utilities Validation
// --------------------------------------------------------------------------

assert.equal(originMatchesRedirectUri("https://evil.com", "https://evil.com.attacker.test/cb"), false);
assert.equal(originMatchesRedirectUri("https://app.example.com", "https://app.example.com/cb"), true);

assert.equal(validateRedirectUri("https://user:pass@app.example.com/cb"), false);
assert.equal(validateRedirectUri("javascript:alert(1)"), false);
assert.equal(validateRedirectUri("https://app.example.com/cb"), true);

assert.equal(isLoopbackHost("localhost"), true);
assert.equal(isLoopbackHost("127.0.0.1"), true);
assert.equal(isLoopbackHost("::1"), true);
assert.equal(isLoopbackHost("app.localhost"), true);
assert.equal(isLoopbackHost("192.168.1.1"), false);
assert.equal(isLoopbackHost("169.254.169.254"), false);

// Production mode with isDev: false (strictly HTTPS, blocks localhost and private networks)
assert.equal(validateRedirectUri("http://localhost:3001/api/auth/callback", { isDev: false, env: "production" }), false);
assert.equal(validateRedirectUri("https://app.example.com/cb", { isDev: false, env: "production" }), true);

assert.equal(isPrivateOrLocalHost("localhost"), true);
assert.equal(isPrivateOrLocalHost("169.254.169.254"), true);
assert.equal(isPrivateOrLocalHost("app.example.com"), false);

assert.equal(safeCallbackURL("https://evil.example/cb"), undefined);
assert.equal(safeCallbackURL("//evil.example/cb"), undefined);
assert.equal(safeCallbackURL("/oauth/callback?code=abc"), "/oauth/callback?code=abc");

assert.equal(isStrongPassword("short"), false);
assert.equal(isStrongPassword("longbutmissingclasses"), false);
assert.equal(isStrongPassword("LongEnough123!"), true);

const forged = new Headers({
  "x-forwarded-for": "203.0.113.10, 10.0.0.5",
});
assert.equal(getTrustedClientIp(forged, []), "unknown");
assert.equal(getTrustedClientIp(new Headers({ "x-real-ip": "203.0.113.7" }), []), "unknown");
assert.equal(getTrustedClientIp(forged, ["10.0.0.0/8"]), "203.0.113.10");

console.log("security self-check passed");
