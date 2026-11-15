import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId } from "mongodb";
import { SignJWT, generateKeyPair, exportJWK } from "jose";

console.log("================================================================");
console.log("  SWYRA AUTH -- SESSION EXPIRY & ISOLATION VERIFICATION SUITE");
console.log("================================================================\n");

const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
const GATEWAY_SECRET = "g".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = GATEWAY_SECRET;
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = "10.0.0.0/8,172.16.0.0/12";

const { getDb, closeDb } = await import("../../src/db/mongo");
const { default: app } = await import("../../src/app");
const { authProvider } = await import("../../src/utils/auth");

const db = await getDb();

// Seed IdP signing key in DB using production jwks schema
const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
const jwkPublic = await exportJWK(publicKey);
const jwkPrivate = await exportJWK(privateKey);
const keyObjectId = new ObjectId();
const kid = keyObjectId.toString();
jwkPublic.kid = kid;
jwkPublic.alg = "RS256";
jwkPublic.use = "sig";
jwkPrivate.kid = kid;
jwkPrivate.alg = "RS256";
jwkPrivate.use = "sig";

const { symmetricEncrypt } = await import("better-auth/crypto");
const enc = await symmetricEncrypt({
  key: process.env.BETTER_AUTH_SECRET!,
  data: JSON.stringify(jwkPrivate),
});

await db.collection("jwks").insertOne({
  _id: keyObjectId,
  id: kid,
  kid,
  alg: "RS256",
  publicKey: JSON.stringify(jwkPublic),
  privateKey: JSON.stringify(enc),
  createdAt: new Date(),
});

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

let ipCounter = 300;
function getTestHeaders(overrides: Record<string, string> = {}) {
  const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
  return {
    "host": "localhost:3000",
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    "x-gateway-secret": GATEWAY_SECRET,
    "Origin": "http://localhost:5174",
    ...overrides,
  };
}

// --------------------------------------------------------------------------
// TEST 1: IdP Session Expiry while uncleaned MongoDB document exists
// --------------------------------------------------------------------------
await runTest("EXP-1: Expired IdP session is rejected even when uncleaned MongoDB document still exists (TTL is not the auth check)", async () => {
  const email = `expired_idp_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password@1234!";

  await authProvider.api.signUpEmail({
    body: { email, password, name: "Expired IdP User" },
  });

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ "content-type": "application/json" }),
    body: JSON.stringify({ email, password }),
  });
  assert.equal(loginRes.status, 200, "Login must succeed");
  const cookie = loginRes.headers.get("set-cookie") || "";
  assert.ok(cookie.includes("better-auth.session_token="), "Must set session cookie");

  // Verify valid session works immediately
  const checkRes1 = await app.request("/api/auth/get-session", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie }),
  });
  assert.equal(checkRes1.status, 200);
  const data1 = await checkRes1.json();
  assert.ok(data1 && data1.session, "Session must be active initially");

  // Find the session document
  const rawCookie = cookie.split("better-auth.session_token=")[1].split(";")[0];
  const tokenVal = decodeURIComponent(rawCookie.split(".")[0]);
  const sessionDoc = await db.collection("session").findOne({
    $or: [
      { token: rawCookie },
      { token: tokenVal },
      { token: decodeURIComponent(rawCookie) },
    ],
  });
  assert.ok(sessionDoc, "Session document must exist in MongoDB");

  // Force document expiresAt to the past (simulating expired session before MongoDB TTL thread runs)
  const updateRes = await db.collection("session").updateOne(
    { _id: sessionDoc._id },
    { $set: { expiresAt: new Date(Date.now() - 60000) } } // Expired 1 minute ago
  );
  assert.equal(updateRes.matchedCount, 1, "Session document must still physically exist in MongoDB");

  // Request with expired cookie must fail closed immediately
  const checkRes2 = await app.request("/api/auth/get-session", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie }),
  });
  const data2 = await checkRes2.json();
  assert.equal(data2, null, "Expired session must return null even when DB document still exists");
});

// --------------------------------------------------------------------------
// TEST 2: Access Token Expiry (RS256 JWT exp claim)
// --------------------------------------------------------------------------
await runTest("EXP-2: Expired RS256 access token is strictly rejected (exp claim enforced offline)", async () => {
  const clientId = `test_client_${crypto.randomBytes(4).toString("hex")}`;
  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "secret123",
    name: "Test OAuth Client",
    redirectUris: ["https://example.com/callback"],
    disabled: false,
    createdAt: new Date(),
  });

  const userEmail = `jwt_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const userId = new ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new ObjectId(userId),
    id: userId,
    email: userEmail,
    name: "Valid User",
    role: "user",
    emailVerified: true,
    createdAt: new Date(),
  });

  // 1. Prove an otherwise valid token succeeds at the real protected endpoint
  const validJwt = await new SignJWT({
    sub: userId,
    email: userEmail,
    client_id: clientId,
    aud: clientId,
    scope: "openid profile email",
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer("http://localhost:3000")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);

  const validRes = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${validJwt}` }),
  });
  assert.equal(validRes.status, 200, "Valid token must succeed at protected endpoint");
  const validData = await validRes.json();
  assert.equal(validData.sub, userId, "Valid token must return matching subject");

  // 2. Change only expiry, then assert rejection
  const expiredJwt = await new SignJWT({
    sub: userId,
    email: userEmail,
    client_id: clientId,
    aud: clientId,
    scope: "openid profile email",
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer("http://localhost:3000")
    .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
    .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
    .sign(privateKey);

  const expiredRes = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${expiredJwt}` }),
  });
  assert.equal(expiredRes.status, 401, "Expired JWT must return 401 Unauthorized");
  const expiredBody = await expiredRes.json();
  assert.equal(expiredBody.error, "invalid_token", "Rejection must specifically be invalid_token due to expiry");
});

// --------------------------------------------------------------------------
// TEST 3: Forged / Algorithm-Swapped JWT Rejection
// --------------------------------------------------------------------------
await runTest("EXP-3: Forged RS256 token and HS256 algorithm swapping are strictly rejected", async () => {
  // Mint a forged token with an unknown foreign RSA key pair
  const foreignKeys = await generateKeyPair("RS256");
  const forgedJwt = await new SignJWT({
    sub: "attacker_user",
    role: "super_admin",
    aud: "admin_console",
  })
    .setProtectedHeader({ alg: "RS256", kid: "unknown-kid" })
    .setIssuer("http://localhost:3000")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(foreignKeys.privateKey);

  const res1 = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${forgedJwt}` }),
  });
  assert.equal(res1.status, 401, "Forged RSA signature must return 401");

  // Attempt algorithm confusion (HS256 signed with symmetric secret)
  const hs256Jwt = await new SignJWT({
    sub: "attacker_user",
    role: "super_admin",
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("http://localhost:3000")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(crypto.createSecretKey(Buffer.from("a".repeat(32))));

  const res2 = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${hs256Jwt}` }),
  });
  assert.equal(res2.status, 401, "HS256 token must be rejected under RS256 pinning");
});

// --------------------------------------------------------------------------
// TEST 4: Conflicting Cookie and Bearer Identities
// --------------------------------------------------------------------------
await runTest("EXP-4: Conflicting Cookie and Bearer identities fail closed (identity mismatch defense)", async () => {
  const userAEmail = `user_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const userBEmail = `user_b_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password@1234!";

  // Create User A and User B
  const userA = await authProvider.api.signUpEmail({ body: { email: userAEmail, password, name: "User A" } });
  const userB = await authProvider.api.signUpEmail({ body: { email: userBEmail, password, name: "User B" } });

  const userAId = String((userA as any).user.id);
  const userBId = String((userB as any).user.id);

  // Grant super-admin role to both users in the database
  await db.collection("user").updateOne({ email: userAEmail }, { $set: { role: "super-admin" } });
  await db.collection("user").updateOne({ email: userBEmail }, { $set: { role: "super-admin" } });

  // Log in as User A to get Session Cookie A
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ "content-type": "application/json" }),
    body: JSON.stringify({ email: userAEmail, password }),
  });
  const cookieUserA = loginRes.headers.get("set-cookie") || "";
  assert.ok(cookieUserA.includes("better-auth.session_token="), "Must acquire User A session cookie");

  // Mint valid Bearer token for User B with correct platform audience and super-admin role
  const tokenUserB = await new SignJWT({
    sub: userBId,
    email: userBEmail,
    role: "super-admin",
    aud: "http://localhost:3000",
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer("http://localhost:3000")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);

  // Mint valid Bearer token for User A with matching identity
  const tokenUserA = await new SignJWT({
    sub: userAId,
    email: userAEmail,
    role: "super-admin",
    aud: "http://localhost:3000",
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer("http://localhost:3000")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);

  // 1. Prove Cookie A succeeds alone
  const resCookieOnly = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookieUserA }),
  });
  assert.equal(resCookieOnly.status, 200, "Cookie A alone must succeed at protected admin route");

  // 2. Prove Bearer B succeeds alone
  const resBearerOnly = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${tokenUserB}` }),
  });
  assert.equal(resBearerOnly.status, 200, "Bearer B alone must succeed at protected admin route");

  // 3. Combine Cookie A and Bearer B (conflicting identities) -> must fail closed
  const resConflict = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders({
      Cookie: cookieUserA,
      Authorization: `Bearer ${tokenUserB}`,
    }),
  });
  assert.ok(
    resConflict.status === 401 || resConflict.status === 403,
    "Conflicting cookie and bearer identities must fail closed"
  );

  // 4. Combine Cookie A and Bearer A (matching credentials) -> must succeed following policy
  const resMatching = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders({
      Cookie: cookieUserA,
      Authorization: `Bearer ${tokenUserA}`,
    }),
  });
  assert.equal(resMatching.status, 200, "Matching cookie and bearer identities must succeed");
});

// --------------------------------------------------------------------------
// TEST 5: Public Client ID cannot access protected APIs or read data
// --------------------------------------------------------------------------
await runTest("EXP-5: Public client_id alone cannot access protected APIs or read sensitive data", async () => {
  const testClientId = "public_client_" + crypto.randomBytes(4).toString("hex");
  await db.collection("oauthClient").insertOne({
    clientId: testClientId,
    name: "Public Client App",
    isPublic: true,
    redirectUris: ["https://example.com/callback"],
    allowedOrigins: ["https://example.com"],
    disabled: false,
    createdAt: new Date(),
  });

  // Attempt to call admin endpoints with client_id in query or header
  const adminRes = await app.request(`/api/admin/users?client_id=${testClientId}`, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.ok(adminRes.status === 401 || adminRes.status === 403, "client_id cannot grant admin access");

  const logsRes = await app.request(`/api/admin/logs?client_id=${testClientId}`, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.ok(logsRes.status === 401 || logsRes.status === 403, "client_id cannot grant audit logs access");

  // Attempt to mint token with client_credentials using public client (must be rejected)
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({ "content-type": "application/x-www-form-urlencoded" }),
    body: `grant_type=client_credentials&client_id=${testClientId}`,
  });
  assert.ok(tokenRes.status === 400 || tokenRes.status === 401, "Public client cannot mint tokens via client_credentials");
});

await closeDb();
await mongod.stop();

console.log("\n================================================================");
console.log(`  SESSION EXPIRY & ISOLATION RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
