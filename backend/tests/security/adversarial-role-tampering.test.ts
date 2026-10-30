import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId } from "mongodb";
import { SignJWT, generateKeyPair, exportJWK } from "jose";

// 1. Start disposable in-memory MongoDB
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
const GATEWAY_SECRET = "g".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = GATEWAY_SECRET;
process.env.TRUSTED_PROXY_CIDRS = "127.0.0.1/32,10.0.0.0/8";

// 2. Import modules
const { getDb, closeDb } = await import("../../src/db/mongo");
const { default: app } = await import("../../src/app");
const { authProvider } = await import("../../src/utils/auth");

console.log("================================================================");
console.log("  ADVERSARIAL ROLE TAMPERING & TOKEN BOUNDARY REGRESSION SUITE");
console.log("================================================================\n");

let passed = 0;
let failed = 0;

async function runTest(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`[FAIL] ${name}:`, err.message || err);
    failed++;
  }
}

let ipCounter = 800;
function getTestHeaders(extra: Record<string, string> = {}): Headers {
  const h = new Headers();
  const ip = `198.51.100.${++ipCounter % 240 + 1}`;
  h.set("content-type", "application/json");
  h.set("host", "localhost:3000");
  h.set("origin", "http://localhost:5174");
  h.set("x-forwarded-for", `${ip}, 10.0.0.1`);
  h.set("x-gateway-secret", GATEWAY_SECRET);
  for (const [k, v] of Object.entries(extra)) {
    h.set(k, v);
  }
  return h;
}

const db = await getDb();

// Generate genuine IdP RS256 keypair and store in jwks collection
const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwkPublic = await exportJWK(publicKey);
const kid = "idp-valid-key";
jwkPublic.kid = kid;
jwkPublic.alg = "RS256";
jwkPublic.use = "sig";

await db.collection("jwks").insertOne({
  _id: kid as any,
  id: kid,
  kid,
  publicKey: JSON.stringify(jwkPublic),
  createdAt: new Date(),
});

// Setup 2 OAuth clients in db: app-alpha and app-beta
const now = new Date();
await db.collection("oauthClient").insertMany([
  {
    _id: new ObjectId(),
    clientId: "app-alpha",
    id: "app-alpha",
    name: "Application Alpha",
    redirectUris: ["http://localhost:3000/callback"],
    allowedOrigins: ["http://localhost:3000"],
    isPublic: true,
    isDev: true,
    createdAt: now,
  },
  {
    _id: new ObjectId(),
    clientId: "app-beta",
    id: "app-beta",
    name: "Application Beta",
    redirectUris: ["http://localhost:3001/callback"],
    allowedOrigins: ["http://localhost:3001"],
    isPublic: true,
    isDev: true,
    createdAt: now,
  },
]);

// Seed users:
// 1. Super Admin: swyra@auth2.1.com
const superAdminId = new ObjectId().toString();
await db.collection("user").insertOne({
  _id: new ObjectId(superAdminId),
  id: superAdminId,
  email: "swyra@auth2.1.com",
  role: "super-admin",
  scopedClientId: null,
  emailVerified: true,
  createdAt: now,
});

// 2. App Admin for App Alpha: alpha-admin@example.com
const alphaAdminId = new ObjectId().toString();
await db.collection("user").insertOne({
  _id: new ObjectId(alphaAdminId),
  id: alphaAdminId,
  email: "alpha-admin@example.com",
  role: "app-admin",
  scopedClientId: "app-alpha",
  emailVerified: true,
  createdAt: now,
});
await db.collection("user_app_registrations").insertOne({
  userId: alphaAdminId,
  clientId: "app-alpha",
  appRole: "admin",
  registeredAt: now,
});

// 3. Regular End User: standard-user@example.com
const standardUserId = new ObjectId().toString();
await db.collection("user").insertOne({
  _id: new ObjectId(standardUserId),
  id: standardUserId,
  email: "standard-user@example.com",
  role: "user",
  scopedClientId: null,
  emailVerified: true,
  createdAt: now,
});

// Helper to mint signed RS256 token
async function mintToken(payload: Record<string, any>, customKid: string = kid, customKey = privateKey): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: customKid })
    .setIssuer("http://localhost:3000")
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(customKey);
}

// ==============================================================================
// 1. Unsigned Tokens & Algorithm Confusion (alg: none, HS256)
// ==============================================================================

await runTest("TOKEN-1: Unsigned token (alg: none) is strictly rejected (401)", async () => {
  // Construct alg: none token
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    sub: superAdminId,
    role: "super-admin",
    aud: "http://localhost:3000",
    iss: "http://localhost:3000",
  })).toString("base64url");
  const unsignedToken = `${header}.${payload}.`;

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${unsignedToken}` }),
  });
  assert.equal(res.status, 401, "Unsigned token must return 401 unauthenticated");
});

await runTest("TOKEN-2: Symmetric algorithm confusion (alg: HS256) is strictly rejected (401)", async () => {
  const symmetricKey = crypto.createSecretKey(Buffer.from("a".repeat(32)));
  const hsToken = await new SignJWT({
    sub: superAdminId,
    role: "super-admin",
    aud: "http://localhost:3000",
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("http://localhost:3000")
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(symmetricKey);

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${hsToken}` }),
  });
  assert.equal(res.status, 401, "HS256 token must fail algorithm pinning and return 401");
});

await runTest("TOKEN-3: Token signed with unauthorized external key is strictly rejected (401)", async () => {
  const { privateKey: rogueKey } = await generateKeyPair("RS256");
  const rogueToken = await mintToken(
    { sub: superAdminId, role: "super-admin", aud: "http://localhost:3000" },
    "rogue-key-id",
    rogueKey
  );

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${rogueToken}` }),
  });
  assert.equal(res.status, 401, "Token with unregistered key must return 401");
});

// ==============================================================================
// 2. Token Payload Tampering Without Re-signing
// ==============================================================================

await runTest("TOKEN-4: Tampered JWT payload role without valid signature is rejected (401)", async () => {
  const validAlphaToken = await mintToken({
    sub: alphaAdminId,
    role: "app-admin",
    scoped_client_id: "app-alpha",
    aud: "app-alpha",
  });

  const parts = validAlphaToken.split(".");
  // Modify payload role to "super-admin"
  const decodedPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  decodedPayload.role = "super-admin";
  decodedPayload.scoped_client_id = null;
  const forgedPayload = Buffer.from(JSON.stringify(decodedPayload)).toString("base64url");
  const tamperedToken = `${parts[0]}.${forgedPayload}.${parts[2]}`;

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${tamperedToken}` }),
  });
  assert.equal(res.status, 401, "Tampered token payload must fail cryptographic verification");
});

// ==============================================================================
// 3. Cross-Tenant and Audience Boundary Verification
// ==============================================================================

await runTest("AUDIENCE-1: Valid App Alpha admin token cannot access MAuth platform APIs (403)", async () => {
  const validAlphaToken = await mintToken({
    sub: alphaAdminId,
    role: "app-admin",
    scoped_client_id: "app-alpha",
    aud: "app-alpha",
  });

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${validAlphaToken}` }),
  });
  assert.equal(res.status, 403, "App admin token must be rejected on central platform management APIs");
  const data = await res.json();
  assert.ok(
    ["ERR_AUDIENCE_FORBIDDEN", "ERR_ROLE_FORBIDDEN", "ERR_SUPER_ADMIN_REQUIRED"].includes(data.code),
    `Expected role/audience forbidden code, got: ${data.code}`
  );
});

await runTest("AUDIENCE-2: Valid App Alpha admin token cannot access App Beta config (403)", async () => {
  const validAlphaToken = await mintToken({
    sub: alphaAdminId,
    role: "app-admin",
    scoped_client_id: "app-alpha",
    aud: "app-alpha",
  });

  const res = await app.request("/api/admin/clients/app-beta", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${validAlphaToken}` }),
  });
  assert.equal(res.status, 403, "App Alpha admin cannot access App Beta");
  const data = await res.json();
  assert.equal(data.code, "ERR_CROSS_TENANT_FORBIDDEN");
});

await runTest("AUDIENCE-3: Platform Super Admin token cannot access consumer app admin route (403)", async () => {
  const validSuperToken = await mintToken({
    sub: superAdminId,
    role: "super-admin",
    scoped_client_id: null,
    aud: "http://localhost:3000",
  });

  // Consumer app admin guard: requireConsumerAppAdmin on /api/admin/app/:clientId/config
  const res = await app.request("/api/admin/app/app-alpha/config", {
    method: "PATCH",
    headers: getTestHeaders({ Authorization: `Bearer ${validSuperToken}` }),
    body: JSON.stringify({ name: "Updated via Super Admin" }),
  });
  // Super admin accessing scoped endpoint gets 403 ERR_AUDIENCE_FORBIDDEN or cannot act as consumer admin
  assert.equal(res.status, 403, "Platform token audience does not match consumer application client ID");
});

// ==============================================================================
// 4. Conflicting Credentials & Authentication Boundary Defense
// ==============================================================================

await runTest("CRED-1: Conflicting credentials (Bearer token User A + Cookie Session User B) fail closed (401)", async () => {
  // Create an authentic user and session via Better Auth sign-in
  const otherPass = "OtherPass123!Aa";
  const otherEmail = `conflicting_${crypto.randomBytes(4).toString("hex")}@example.com`;
  await authProvider.api.signUpEmail({
    body: { email: otherEmail, password: otherPass, name: "Other User" },
  });
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: otherEmail, password: otherPass }),
  });
  assert.equal(loginRes.status, 200, "Sign in must succeed");
  const setCookieHeader = loginRes.headers.get("set-cookie");
  const setCookies = typeof (loginRes.headers as any).getSetCookie === "function" ? (loginRes.headers as any).getSetCookie() : [setCookieHeader];
  const conflictingCookie = (setCookies.find((c: string) => c?.includes("session_token")) || setCookieHeader || "").split(";")[0];
  assert.ok(conflictingCookie, "Session cookie must be present");

  // Mint token for superAdminId
  const superToken = await mintToken({
    sub: superAdminId,
    role: "super-admin",
    scoped_client_id: null,
    aud: "http://localhost:3000",
  });

  // Supply header with Bearer superToken AND a cookie session belonging to other user
  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({
      Authorization: `Bearer ${superToken}`,
      Cookie: conflictingCookie,
    }),
  });
  // Since session token and bearer token identify different users, requests fail closed (401)
  assert.equal(res.status, 401, "Conflicting credentials must return 401 unauthenticated");
});

// ==============================================================================
// 5. Token Replay After User Deletion, Demotion, or Revocation
// ==============================================================================

await runTest("REVOKE-1: Token replay after user deletion returns 401", async () => {
  // Create ephemeral admin
  const ephemId = new ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new ObjectId(ephemId),
    id: ephemId,
    email: "ephem@example.com",
    role: "super-admin",
    scopedClientId: null,
    emailVerified: true,
  });

  const ephemToken = await mintToken({
    sub: ephemId,
    role: "super-admin",
    aud: "http://localhost:3000",
  });

  // Verify access works initially
  const res1 = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${ephemToken}` }),
  });
  assert.equal(res1.status, 200, "Initial access must succeed");

  // Delete user from MongoDB
  await db.collection("user").deleteOne({ _id: new ObjectId(ephemId) });

  // Replay token
  const res2 = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${ephemToken}` }),
  });
  assert.equal(res2.status, 401, "Deleted user token replay must return 401 unauthenticated");
});

await runTest("REVOKE-2: Token replay after tokensRevokedBefore returns 401", async () => {
  const revokeUserEmail = "revoked-admin@example.com";
  const revokeUserId = new ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new ObjectId(revokeUserId),
    id: revokeUserId,
    email: revokeUserEmail,
    role: "super-admin",
    scopedClientId: null,
    emailVerified: true,
  });

  // Mint token with past iat
  const oldIat = Math.floor(Date.now() / 1000) - 60; // 60 seconds ago
  const oldToken = await new SignJWT({
    sub: revokeUserId,
    role: "super-admin",
    aud: "http://localhost:3000",
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer("http://localhost:3000")
    .setIssuedAt(oldIat)
    .setExpirationTime("15m")
    .sign(privateKey);

  // Set tokensRevokedBefore to 10 seconds ago
  await db.collection("user").updateOne(
    { _id: new ObjectId(revokeUserId) },
    { $set: { tokensRevokedBefore: new Date(Date.now() - 10000) } }
  );

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${oldToken}` }),
  });
  assert.equal(res.status, 401, "Token issued prior to tokensRevokedBefore must return 401");
});

// ==============================================================================
// 6. Privilege Injection on Signup and User Creation
// ==============================================================================

await runTest("SIGNUP-1: Attempting to supply role: 'super-admin' in signup fails or ignores role", async () => {
  const testEmail = `signup_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const res = await app.request("/api/auth/sign-up/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: testEmail,
      password: "StrongPassword123!Aa",
      name: "Attacker User",
      role: "super-admin",
      scopedClientId: null,
    }),
  });

  // Check role in database: must be "user", NEVER "super-admin"
  const created = await db.collection("user").findOne({ email: testEmail });
  if (created) {
    assert.equal(created.role, "user", "Signup must NEVER grant super-admin role");
  }
});

await runTest("PROVISION-1: POST /api/admin/users requires scopedClientId when provisioning app-admin (400)", async () => {
  const superToken = await mintToken({
    sub: superAdminId,
    role: "super-admin",
    aud: "http://localhost:3000",
  });

  const res = await app.request("/api/admin/users", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${superToken}` }),
    body: JSON.stringify({
      email: "new-admin-attempt@example.com",
      role: "app-admin",
      // omitted scopedClientId
    }),
  });

  assert.equal(res.status, 400, "App admin without scopedClientId must be rejected (400)");
  const data = await res.json();
  assert.equal(data.code, "ERR_SCOPED_CLIENT_REQUIRED");
});

await runTest("PROVISION-2: POST /api/admin/users rejects super-admin with scopedClientId (400)", async () => {
  const superToken = await mintToken({
    sub: superAdminId,
    role: "super-admin",
    aud: "http://localhost:3000",
  });

  const res = await app.request("/api/admin/users", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${superToken}` }),
    body: JSON.stringify({
      email: "super-with-scope@example.com",
      role: "super-admin",
      scopedClientId: "app-alpha",
    }),
  });

  assert.equal(res.status, 400, "Super admin with scopedClientId must be rejected (400)");
  const data = await res.json();
  assert.equal(data.code, "ERR_SUPER_ADMIN_CANNOT_BE_SCOPED");
});

// ==============================================================================
// 7. DB Fallback & Zero Elevation Regressions
// ==============================================================================

await runTest("FALLBACK-1: App-admin token cannot acquire platform privileges via DB fallback (401)", async () => {
  // Create user who in DB has role: "super-admin"
  const dualUserId = new ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new ObjectId(dualUserId),
    id: dualUserId,
    email: "dual-role@example.com",
    role: "super-admin",
    scopedClientId: null,
    emailVerified: true,
    createdAt: new Date(),
  });

  // Mint an app-admin token for this user
  const appAdminToken = await mintToken({
    sub: dualUserId,
    role: "app-admin",
    scoped_client_id: "app-alpha",
    aud: ["app-alpha", "http://localhost:3000"],
  });

  // Request central platform endpoint: MUST NOT elevate to super-admin via DB record
  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${appAdminToken}` }),
  });

  assert.equal(res.status, 401, "App admin token must not elevate to super admin via DB fallback (401)");
});

// ==============================================================================
// 8. Session Cookie Tampering & Cryptographic Verification Regressions
// ==============================================================================

await runTest("COOKIE-1: Tampered session cookie signature fails authentication (401)", async () => {
  // Sign in genuinely to get authentic session
  const cookieEmail = `cookie_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const cookiePass = "CookiePass123!Aa";
  await authProvider.api.signUpEmail({
    body: { email: cookieEmail, password: cookiePass, name: "Cookie User" },
  });
  await db.collection("user").updateOne(
    { email: cookieEmail },
    { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
  );

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: cookieEmail, password: cookiePass }),
  });
  assert.equal(loginRes.status, 200);
  const setCookie = loginRes.headers.get("set-cookie") || "";
  const match = setCookie.match(/better-auth\.session_token=([^;]+)/);
  assert.ok(match, "Session cookie must exist");
  const rawCookieVal = match[1];

  // Tamper with the HMAC signature part of the cookie
  const parts = decodeURIComponent(rawCookieVal).split(".");
  const tamperedCookieVal = encodeURIComponent(`${parts[0]}.forgedHMACSignature1234567890`);

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: `better-auth.session_token=${tamperedCookieVal}` }),
  });

  assert.equal(res.status, 401, "Tampered session cookie signature must be rejected with 401");
});

await runTest("COOKIE-2: Revoked session via tokensRevokedBefore returns 401", async () => {
  const revokeEmail = `revoked_cookie_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const revokePass = "RevokePass123!Aa";
  await authProvider.api.signUpEmail({
    body: { email: revokeEmail, password: revokePass, name: "Revoke Cookie User" },
  });
  await db.collection("user").updateOne(
    { email: revokeEmail },
    { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
  );

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: revokeEmail, password: revokePass }),
  });
  assert.equal(loginRes.status, 200);
  const cookie = (loginRes.headers.get("set-cookie") || "").split(";")[0];

  // Now set tokensRevokedBefore in database to future
  await db.collection("user").updateOne(
    { email: revokeEmail },
    { $set: { tokensRevokedBefore: new Date(Date.now() + 60_000) } }
  );

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie }),
  });

  assert.equal(res.status, 401, "Session created before tokensRevokedBefore must return 401");
});

// ==============================================================================
// 9. Ambiguous Legacy Admin Token Regressions
// ==============================================================================

await runTest("LEGACY-1: Ambiguous legacy admin token with missing scope fails closed (401)", async () => {
  const legacyToken = await mintToken({
    sub: superAdminId,
    role: "admin",
    // scoped_client_id omitted entirely (undefined)
    aud: "http://localhost:3000",
  });

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${legacyToken}` }),
  });

  assert.equal(res.status, 401, "Ambiguous legacy admin token with undefined scope must return 401");
});

await runTest("LEGACY-2: Ambiguous legacy admin token with empty string scope fails closed (401)", async () => {
  const legacyToken = await mintToken({
    sub: superAdminId,
    role: "admin",
    scoped_client_id: "",
    aud: "http://localhost:3000",
  });

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${legacyToken}` }),
  });

  assert.equal(res.status, 401, "Ambiguous legacy admin token with empty string scope must return 401");
});

// ==============================================================================
// 10. Role-Based Policy Independence From Hardcoded Emails
// ==============================================================================

await runTest("EMAIL-1: Non-swyra email with super-admin role has valid platform access", async () => {
  const arbitrarySuperId = new ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new ObjectId(arbitrarySuperId),
    id: arbitrarySuperId,
    email: "platform-ops@enterprise.acme",
    role: "super-admin",
    scopedClientId: null,
    emailVerified: true,
    createdAt: new Date(),
  });

  const superToken = await mintToken({
    sub: arbitrarySuperId,
    role: "super-admin",
    scoped_client_id: null,
    aud: "http://localhost:3000",
  });

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${superToken}` }),
  });

  assert.equal(res.status, 200, "Super admin with arbitrary email must succeed");
});

await runTest("EMAIL-2: Account with swyra email but role: 'user' is forbidden (403)", async () => {
  const fakeSwyraId = new ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new ObjectId(fakeSwyraId),
    id: fakeSwyraId,
    email: "imposter-swyra@auth2.1.com",
    role: "user",
    scopedClientId: null,
    emailVerified: true,
    createdAt: new Date(),
  });

  const userToken = await mintToken({
    sub: fakeSwyraId,
    role: "user",
    aud: "http://localhost:3000",
  });

  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${userToken}` }),
  });

  assert.equal(res.status, 403, "User role must be rejected regardless of email");
});

await runTest("CLIENT-PRIV-1: Reconciled clientPrivileges accepts super-admin and rejects app-admin", async () => {
  const { isSuperAdminUser } = await import("../../src/utils/auth");

  assert.equal(isSuperAdminUser({ role: "super-admin", scopedClientId: null }), true);
  assert.equal(isSuperAdminUser({ role: "super-admin", scopedClientId: undefined }), true);
  assert.equal(isSuperAdminUser({ role: "super-admin", scopedClientId: "app-1" }), false);
  assert.equal(isSuperAdminUser({ role: "super-admin", scopedClientId: "" }), false);
  assert.equal(isSuperAdminUser({ role: "admin", scopedClientId: null }), true);
  assert.equal(isSuperAdminUser({ role: "admin", scopedClientId: "app-1" }), false);
  assert.equal(isSuperAdminUser({ role: "admin", scopedClientId: undefined }), false);
  assert.equal(isSuperAdminUser({ role: "app-admin", scopedClientId: "app-1" }), false);
  assert.equal(isSuperAdminUser({ role: "user" }), false);
});

console.log("\n================================================================");
console.log(`  ADVERSARIAL ROLE TAMPERING RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================\n");

await closeDb();
await mongod.stop();

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
