import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.MONGO_URI = "mongodb://172.25.240.1:27017/test";
process.env.BETTER_AUTH_SECRET = "x".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = "test";
process.env.GOOGLE_CLIENT_SECRET = "test";
process.env.FRONTEND_URL = "http://localhost:5173";

const {
  getTrustedClientIp,
  isLoopbackHost,
  isPrivateOrLocalHost,
  isStrongPassword,
  originMatchesRedirectUri,
  safeCallbackURL,
  validateRedirectUri,
} = await import("../src/utils/security");

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

// Production mode with isDev: true (allows localhost loopback, blocks private networks)
assert.equal(validateRedirectUri("http://localhost:3001/api/auth/callback", { isDev: true, env: "production" }), true);
assert.equal(validateRedirectUri("http://127.0.0.1:3001/api/auth/callback", { isDev: true, env: "production" }), true);
assert.equal(validateRedirectUri("http://192.168.1.1/api/auth/callback", { isDev: true, env: "production" }), false);
assert.equal(validateRedirectUri("http://169.254.169.254/cb", { isDev: true, env: "production" }), false);
assert.equal(validateRedirectUri("https://app.example.com/cb", { isDev: true, env: "production" }), true);

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
