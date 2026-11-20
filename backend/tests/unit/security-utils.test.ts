/// <reference types="node" />
process.env.NODE_ENV = "test";
process.env.MONGO_URI = "mongodb://localhost:27017/test";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";

import assert from "node:assert/strict";

const {
  isRegisteredRedirectUri,
  normalizeOrigin,
  hasDangerousMongoKeys,
  validateSafePrimitiveString,
  timingSafeEqualStr,
  isLoopbackHost,
  validateRedirectUri,
  getTrustedClientIp,
} = await import("../../src/utils/security");

console.log("================================================================");
console.log("  SWYRA AUTH -- SECURITY UTILITIES UNIT TESTS");
console.log("================================================================\n");

// Helper to construct a mock CanonicalOAuthClient
function makeClient(partial: any = {}): any {
  return {
    _id: "client-id-1",
    id: "client-id-1",
    clientId: "client-id-1",
    name: "Test Client",
    redirectUris: ["https://app.swyra.com/callback"],
    allowedOrigins: ["https://app.swyra.com"],
    disabled: false,
    isDev: false,
    isPublic: true,
    skipConsent: false,
    ...partial,
  };
}

// -----------------------------------------------------------------------------
// 1. isRegisteredRedirectUri (RFC 6749 and RFC 8252)
// -----------------------------------------------------------------------------

// Happy path: exact match
{
  const client = makeClient({ redirectUris: ["https://app.swyra.com/callback"] });
  assert.equal(
    isRegisteredRedirectUri(client, "https://app.swyra.com/callback"),
    true,
    "Exact registered redirect URI must match"
  );
}

// Rejection: fragment component (#) per RFC 6749 Section 3.1.2
{
  const client = makeClient({ redirectUris: ["https://app.swyra.com/callback"] });
  assert.equal(
    isRegisteredRedirectUri(client, "https://app.swyra.com/callback#token=secret"),
    false,
    "Fragment components must be rejected"
  );
}

// Rejection: userinfo (user:pass@) per RFC 6749 Section 3.1.2
{
  const client = makeClient({ redirectUris: ["https://app.swyra.com/callback"] });
  assert.equal(
    isRegisteredRedirectUri(client, "https://user:pass@app.swyra.com/callback"),
    false,
    "Userinfo components must be rejected"
  );
}

// Rejection: protocol mismatch (http vs https)
{
  const client = makeClient({ redirectUris: ["https://app.swyra.com/callback"] });
  assert.equal(
    isRegisteredRedirectUri(client, "http://app.swyra.com/callback"),
    false,
    "Protocol mismatch must be rejected"
  );
}

// Rejection: host mismatch and lookalike attacks
{
  const client = makeClient({ redirectUris: ["https://app.swyra.com/callback"] });
  assert.equal(
    isRegisteredRedirectUri(client, "https://app.swyra.com.evil.com/callback"),
    false,
    "Subdomain spoofing must be rejected"
  );
  assert.equal(
    isRegisteredRedirectUri(client, "https://evil-swyra.com/callback"),
    false,
    "Lookalike domain must be rejected"
  );
}

// Rejection: port mismatch on public non-loopback clients
{
  const client = makeClient({ redirectUris: ["https://app.swyra.com/callback"] });
  assert.equal(
    isRegisteredRedirectUri(client, "https://app.swyra.com:8443/callback"),
    false,
    "Arbitrary ports on non-loopback clients must be rejected"
  );
}

// Loopback port relaxation per RFC 8252 Section 7.3
{
  const loopbackClient = makeClient({
    isDev: true,
    redirectUris: [
      "http://localhost:3000/callback",
      "http://127.0.0.1:3000/callback",
      "http://[::1]:3000/callback",
    ],
  });

  assert.equal(
    isRegisteredRedirectUri(loopbackClient, "http://localhost:49152/callback"),
    true,
    "Loopback localhost must permit variable ephemeral ports"
  );
  assert.equal(
    isRegisteredRedirectUri(loopbackClient, "http://127.0.0.1:54321/callback"),
    true,
    "Loopback 127.0.0.1 must permit variable ephemeral ports"
  );
  assert.equal(
    isRegisteredRedirectUri(loopbackClient, "http://[::1]:9999/callback"),
    true,
    "Loopback [::1] must permit variable ephemeral ports"
  );
}

// Path exactness and path traversal protection
{
  const client = makeClient({ redirectUris: ["https://app.swyra.com/auth/callback"] });
  assert.equal(
    isRegisteredRedirectUri(client, "https://app.swyra.com/auth/callback/"),
    false,
    "Trailing slash discrepancies must be rejected"
  );
  assert.equal(
    isRegisteredRedirectUri(client, "https://app.swyra.com/auth/callback/extra"),
    false,
    "Subpath traversal must be rejected"
  );
  assert.equal(
    isRegisteredRedirectUri(client, "https://app.swyra.com/auth"),
    false,
    "Parent path must be rejected"
  );
}

// Query string strict matching
{
  const clientWithQuery = makeClient({
    redirectUris: ["https://app.swyra.com/callback?source=web"],
  });

  assert.equal(
    isRegisteredRedirectUri(clientWithQuery, "https://app.swyra.com/callback?source=web"),
    true,
    "Matching query string must be accepted"
  );
  assert.equal(
    isRegisteredRedirectUri(clientWithQuery, "https://app.swyra.com/callback"),
    false,
    "Missing query string must be rejected"
  );
  assert.equal(
    isRegisteredRedirectUri(clientWithQuery, "https://app.swyra.com/callback?source=web&evil=1"),
    false,
    "Injected query parameters must be rejected"
  );
}

// Defensive handling: empty, null, and malformed inputs
{
  assert.equal(isRegisteredRedirectUri(null, "https://app.swyra.com/callback"), false);
  assert.equal(isRegisteredRedirectUri(makeClient({ redirectUris: [] }), "https://app.swyra.com/callback"), false);
  assert.equal(isRegisteredRedirectUri(makeClient(), ""), false);
  assert.equal(isRegisteredRedirectUri(makeClient(), "not-a-valid-url"), false);
}
console.log("[PASS] isRegisteredRedirectUri enforces RFC 6749 and RFC 8252 security boundaries");

// -----------------------------------------------------------------------------
// 2. normalizeOrigin
// -----------------------------------------------------------------------------

// Valid origins
assert.equal(normalizeOrigin("https://app.swyra.com"), "https://app.swyra.com");
assert.equal(normalizeOrigin("https://app.swyra.com/"), "https://app.swyra.com");
assert.equal(normalizeOrigin("http://localhost:3000"), "http://localhost:3000");

// Invalid origins rejected
assert.equal(normalizeOrigin("https://app.swyra.com/path"), null, "Subpaths must be rejected");
assert.equal(normalizeOrigin("https://app.swyra.com?query=1"), null, "Query strings must be rejected");
assert.equal(normalizeOrigin("https://app.swyra.com#hash"), null, "Fragments must be rejected");
assert.equal(normalizeOrigin("https://user:pass@app.swyra.com"), null, "Credentials must be rejected");
assert.equal(normalizeOrigin("javascript:alert(1)"), null, "Dangerous schemes must be rejected");
assert.equal(normalizeOrigin("data:text/html,test"), null, "Data URIs must be rejected");
assert.equal(normalizeOrigin("file:///etc/passwd"), null, "File URIs must be rejected");
assert.equal(normalizeOrigin(""), null, "Empty strings must be rejected");
console.log("[PASS] normalizeOrigin strictly sanitizes and validates origins");

// -----------------------------------------------------------------------------
// 3. hasDangerousMongoKeys (NoSQL Injection & Prototype Pollution)
// -----------------------------------------------------------------------------

// Mongo operators
assert.equal(hasDangerousMongoKeys({ $gt: 5 }), true, "$gt operator must be flagged");
assert.equal(hasDangerousMongoKeys({ $where: "1 == 1" }), true, "$where operator must be flagged");
assert.equal(hasDangerousMongoKeys({ nested: { $ne: null } }), true, "Nested operators must be flagged");

// Dotted path keys
assert.equal(hasDangerousMongoKeys({ "user.role": "admin" }), true, "Dotted keys must be flagged");
assert.equal(hasDangerousMongoKeys({ filter: { "profile.email": "x" } }), true, "Nested dotted keys must be flagged");

// Prototype pollution keys (testing JSON.parse payloads as received over HTTP)
assert.equal(hasDangerousMongoKeys(JSON.parse('{"__proto__": {"admin": true}}')), true, "__proto__ must be flagged");
assert.equal(hasDangerousMongoKeys({ constructor: {} }), true, "constructor must be flagged");
assert.equal(hasDangerousMongoKeys({ prototype: {} }), true, "prototype must be flagged");

// Deep arrays containing malicious keys
assert.equal(
  hasDangerousMongoKeys([1, "safe", [{ payload: { $regex: ".*" } }]]),
  true,
  "Dangerous keys in deep arrays must be flagged"
);

// Benign objects
assert.equal(hasDangerousMongoKeys({ name: "Alice", email: "alice@swyra.com" }), false);
assert.equal(hasDangerousMongoKeys({ price: "$100 USD", note: "Cost is $50" }), false, "Dollar values must be permitted");
assert.equal(hasDangerousMongoKeys(null), false);
assert.equal(hasDangerousMongoKeys([]), false);
console.log("[PASS] hasDangerousMongoKeys detects operator injection and prototype pollution");

// -----------------------------------------------------------------------------
// 4. validateSafePrimitiveString
// -----------------------------------------------------------------------------

assert.equal(validateSafePrimitiveString("  valid-id  "), "valid-id");
assert.equal(validateSafePrimitiveString(""), null, "Empty strings must be rejected by default");
assert.equal(validateSafePrimitiveString("", "field", { allowEmpty: true }), "");
assert.equal(validateSafePrimitiveString("$bad-operator"), null, "Leading $ must be rejected");
assert.equal(validateSafePrimitiveString("hello\0world"), null, "Null bytes must be rejected");
assert.equal(validateSafePrimitiveString(12345), null, "Non-string types must be rejected");
assert.equal(validateSafePrimitiveString("short", "field", { minLength: 10 }), null, "Short string must be rejected");
assert.equal(validateSafePrimitiveString("toolongstring", "field", { maxLength: 5 }), null, "Long string must be rejected");
console.log("[PASS] validateSafePrimitiveString rejects injections and enforces string constraints");

// -----------------------------------------------------------------------------
// 5. timingSafeEqualStr
// -----------------------------------------------------------------------------

assert.equal(timingSafeEqualStr("secret-token", "secret-token"), true);
assert.equal(timingSafeEqualStr("secret-token", "secret-tokex"), false);
assert.equal(timingSafeEqualStr("secret-token", "short"), false);
assert.equal(timingSafeEqualStr("", ""), true);
console.log("[PASS] timingSafeEqualStr compares strings securely");

// -----------------------------------------------------------------------------
// 6. isLoopbackHost
// -----------------------------------------------------------------------------

assert.equal(isLoopbackHost("localhost"), true);
assert.equal(isLoopbackHost("127.0.0.1"), true);
assert.equal(isLoopbackHost("::1"), true);
assert.equal(isLoopbackHost("sub.localhost"), true);
assert.equal(isLoopbackHost("::ffff:127.0.0.1"), true);
assert.equal(isLoopbackHost("localhost.evil.com"), false);
assert.equal(isLoopbackHost("127.0.0.1.evil.com"), false);
assert.equal(isLoopbackHost("notlocalhost"), false);
assert.equal(isLoopbackHost("192.168.1.1"), false);
console.log("[PASS] isLoopbackHost identifies loopback interfaces accurately");

// -----------------------------------------------------------------------------
// 7. validateRedirectUri
// -----------------------------------------------------------------------------

// Production requirements
assert.equal(
  validateRedirectUri("https://app.swyra.com/callback", { env: "production", isDev: false }),
  true
);
assert.equal(
  validateRedirectUri("http://app.swyra.com/callback", { env: "production", isDev: false }),
  false,
  "HTTP must be rejected in production"
);
assert.equal(
  validateRedirectUri("http://localhost:3000/callback", { env: "production", isDev: false }),
  false,
  "Loopback must be rejected when isDev is false"
);
assert.equal(
  validateRedirectUri("http://localhost:3000/callback", { env: "production", isDev: true }),
  true,
  "Loopback must be permitted when isDev is true"
);

// Private network / AWS metadata rejection
assert.equal(
  validateRedirectUri("http://169.254.169.254/latest/meta-data", { env: "production", isDev: true }),
  false,
  "AWS metadata endpoint must be rejected"
);
assert.equal(
  validateRedirectUri("https://10.0.0.1/callback", { env: "production", isDev: true }),
  false,
  "Private RFC 1918 addresses must be rejected"
);
assert.equal(
  validateRedirectUri("https://192.168.1.1/callback", { env: "production", isDev: true }),
  false,
  "Private RFC 1918 addresses must be rejected"
);
console.log("[PASS] validateRedirectUri protects production boundaries and metadata endpoints");

// -----------------------------------------------------------------------------
// 8. getTrustedClientIp
// -----------------------------------------------------------------------------

{
  const trustedProxies = ["10.0.0.0/8", "127.0.0.1/32"];

  // Chain: untrusted client (203.0.113.195) -> trusted proxy (10.0.1.5)
  const headers = new Headers();
  headers.set("x-forwarded-for", "203.0.113.195, 10.0.1.5");
  const ip = getTrustedClientIp(headers, trustedProxies);
  assert.equal(ip, "203.0.113.195", "Should return the real client IP before trusted proxy");
}

{
  const trustedProxies = ["10.0.0.0/8"];
  // Spoofed attempt where incoming header has extra forged IP but immediate hop is untrusted
  const headers = new Headers();
  headers.set("x-forwarded-for", "1.1.1.1, 198.51.100.22");
  const ip = getTrustedClientIp(headers, trustedProxies);
  assert.equal(ip, "198.51.100.22", "Untrusted proxy cannot spoof upstream headers");
}

{
  const headers = new Headers();
  const ip = getTrustedClientIp(headers, []);
  assert.equal(ip, "unknown", "Empty headers or untrusted configuration yields unknown");
}
console.log("[PASS] getTrustedClientIp resolves client IP safely with proxy CIDR verification");

console.log("\n================================================================");
console.log("  ALL SECURITY UTILITIES UNIT TESTS PASSED!");
console.log("================================================================\n");
process.exit(0);
