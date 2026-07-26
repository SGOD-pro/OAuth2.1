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
