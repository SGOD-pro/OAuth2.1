import assert from "node:assert/strict";
import crypto from "node:crypto";
import { getDb, closeDb } from "../src/db/mongo";
import { hashPassword } from "better-auth/crypto";
import { ObjectId } from "mongodb";
import { authProvider } from "../src/utils/auth";
import { validateRedirectUri, safeCallbackURL } from "../src/utils/security";

process.env.NODE_ENV = "test";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.TRUSTED_PROXY_CIDRS = "10.0.0.0/8";

const { default: app } = await import("../src/app");

console.log("================================================================");
console.log("  SWYRA AUTH -- PART B: WORST-CASE RED-TEAM AUDIT SUITE");
console.log("================================================================");

const db = await getDb();

// -------------------------------------------------------------
// B1. JWT algorithm/key confusion & header manipulation
// -------------------------------------------------------------
console.log("\n>>> B1. JWT Algorithm / Key Confusion Audit");
{
  // 1. Fetch JWKS
  const jwksRes = await app.request("/api/auth/jwks", {
    method: "GET",
    headers: { "Origin": "http://localhost:5174" },
  });
  console.log(`JWKS Endpoint Status: ${jwksRes.status}`);
  const jwks = await jwksRes.json() as { keys?: Array<any> };
  console.log(`JWKS Keys Returned: ${jwks.keys?.length ?? 0}`);

  // Test B1-a: Key confusion (HS256 signed with RSA public key / dummy HMAC)
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ sub: "attacker-user", role: "admin", exp: Math.floor(Date.now() / 1000) + 3600 })).toString("base64url");
  const secret = "dummy-rsa-public-key-as-hmac-secret";
  const hmac = crypto.createHmac("sha256", secret).update(`${header}.${payload}`).digest("base64url");
  const forgedHs256Jwt = `${header}.${payload}.${hmac}`;

  const resHs256 = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${forgedHs256Jwt}`,
      "Origin": "http://localhost:5174",
    },
  });
  console.log(`B1-a: HS256 Key Confusion Token -> Status: ${resHs256.status}`);
  const bodyHs256 = await resHs256.json();
  console.log(`B1-a Response: ${JSON.stringify(bodyHs256)}`);
  assert.equal(resHs256.status, 401, "HS256 Key Confusion must be rejected with 401");

  // Test B1-b: Embedded JWK in header (Self-signed key injection)
  const attackerKeyPair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const attackerJwk = attackerKeyPair.publicKey.export({ format: "jwk" });
  const attackerHeader = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", jwk: attackerJwk })).toString("base64url");
  const sign = crypto.createSign("SHA256").update(`${attackerHeader}.${payload}`).sign(attackerKeyPair.privateKey, "base64url");
  const embeddedJwkJwt = `${attackerHeader}.${payload}.${sign}`;

  const resJwk = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${embeddedJwkJwt}`,
      "Origin": "http://localhost:5174",
    },
  });
  console.log(`B1-b: Embedded JWK Token -> Status: ${resJwk.status}`);
  assert.equal(resJwk.status, 401, "Embedded JWK must be rejected with 401");

  // Test B1-c: KID Path Traversal / SSRF
  const kidHeader = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "../../etc/passwd" })).toString("base64url");
  const kidJwt = `${kidHeader}.${payload}.INVALIDSIG`;
  const resKid = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${kidJwt}`,
      "Origin": "http://localhost:5174",
    },
  });
  console.log(`B1-c: KID Traversal Token -> Status: ${resKid.status}`);
  assert.equal(resKid.status, 401, "KID traversal must be rejected with 401");
  console.log("[PASS] B1: All JWT confusion & header injection attacks rejected with 401.");
}

// -------------------------------------------------------------
// B2. Refresh token rotation / family reuse
// -------------------------------------------------------------
console.log("\n>>> B2. Refresh Token Rotation & Family Reuse Audit");
{
  // Check how Better Auth oauth-provider handles refresh token reuse
  // In OAuth 2.1 §4.3.3: "If a refresh token is compromised and subsequently used by both the legitimate client and the attacker, one of them will attempt to use an already-invalidated refresh token. Upon detecting such reuse, the authorization server MUST invalidate all refresh tokens issued to that client based on the authorization grant."
  const testClientId = "client-b2-" + Date.now();
  const testUserId = "user-b2-" + Date.now();
  const familyId = "fam-" + Date.now();

  // Create active client
  await db.collection("oauthClient").insertOne({
    _id: new ObjectId(),
    clientId: testClientId,
    clientSecret: "secret-b2-12345678",
    name: "Client B2",
    redirectUris: ["https://b2.example.com/cb"],
    allowedOrigins: ["https://b2.example.com"],
    disabled: false,
    skipConsent: true,
    enableEndSession: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Insert an initial refresh token
  const rt1 = "rt-1-" + Date.now();
  const rt2 = "rt-2-" + Date.now();
  await db.collection("oauthRefreshToken").insertOne({
    _id: new ObjectId(),
    token: rt1,
    clientId: testClientId,
    userId: testUserId,
    sessionId: "sess-b2",
    expiresAt: new Date(Date.now() + 86400_000),
    createdAt: new Date(),
  });

  // Attempt refresh with RT1 -> exchange
  const refreshRes1 = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: {
      "Origin": "https://b2.example.com",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `grant_type=refresh_token&refresh_token=${rt1}&client_id=${testClientId}&client_secret=secret-b2-12345678`,
  });
  console.log(`B2 Initial Refresh Status: ${refreshRes1.status}`);
  const refreshBody1 = await refreshRes1.json() as { refresh_token?: string; access_token?: string; error?: string };
  console.log(`B2 Initial Refresh Response: ${JSON.stringify(refreshBody1)}`);

  // Now attempt replay of the rotated-out RT1
  const replayRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: {
      "Origin": "https://b2.example.com",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `grant_type=refresh_token&refresh_token=${rt1}&client_id=${testClientId}&client_secret=secret-b2-12345678`,
  });
  console.log(`B2 Replay Rotated Token Status: ${replayRes.status}`);
  const replayBody = await replayRes.json();
  console.log(`B2 Replay Rotated Token Response: ${JSON.stringify(replayBody)}`);

  // Check if active tokens for this user/client were invalidated
  const remainingTokens = await db.collection("oauthRefreshToken").find({ clientId: testClientId }).toArray();
  console.log(`Remaining Refresh Tokens in DB for client after replay attack: ${remainingTokens.length}`);
  await db.collection("oauthClient").deleteOne({ clientId: testClientId });
}

// -------------------------------------------------------------
// B3. PKCE downgrade & public-client impersonation
// -------------------------------------------------------------
console.log("\n>>> B3. PKCE Downgrade & Client Type Toggle Audit");
{
  const testClientB3 = "client-b3-" + Date.now();
  await db.collection("oauthClient").insertOne({
    _id: new ObjectId(),
    clientId: testClientB3,
    clientSecret: "secret-b3-12345678",
    name: "Client B3",
    redirectUris: ["https://b3.example.com/cb"],
    allowedOrigins: ["https://b3.example.com"],
    disabled: false,
    skipConsent: true,
    enableEndSession: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // 1. Authorize without code_challenge (PKCE downgrade attempt)
  const authResNoPkce = await app.request(`/api/auth/oauth2/authorize?client_id=${testClientB3}&response_type=code&redirect_uri=https%3A%2F%2Fb3.example.com%2Fcb&state=validstate123`, {
    method: "GET",
    headers: { "Origin": "https://b3.example.com" },
  });
  console.log(`B3 Authorize without code_challenge Status: ${authResNoPkce.status}`);

  // 2. Authorize with code_challenge_method=plain
  const authResPlain = await app.request(`/api/auth/oauth2/authorize?client_id=${testClientB3}&response_type=code&redirect_uri=https%3A%2F%2Fb3.example.com%2Fcb&state=validstate123&code_challenge=testplain&code_challenge_method=plain`, {
    method: "GET",
    headers: { "Origin": "https://b3.example.com" },
  });
  console.log(`B3 Authorize with code_challenge_method=plain Status: ${authResPlain.status}`);
  await db.collection("oauthClient").deleteOne({ clientId: testClientB3 });
}

// -------------------------------------------------------------
// B5. Redirect URI / Open Redirect Edge Cases
// -------------------------------------------------------------
console.log("\n>>> B5. Redirect URI & safeCallbackURL Edge Cases Audit");
{
  const testCases = [
    { uri: "https://app.example.com\\@evil.com/", name: "Backslash userinfo confusion" },
    { uri: "https://app.example.com.evil.com/", name: "Subdomain suffix hijacking" },
    { uri: "/\\evil.com", name: "Backslash-as-slash relative bypass" },
    { uri: "/\\/evil.com", name: "Double backslash relative bypass" },
    { uri: "https://аpp.example.com/", name: "Cyrillic homograph spoofing" },
    { uri: "https://app.example.com/%2e%2e/", name: "URL-encoded path traversal" },
    { uri: "https://app.example.com./cb", name: "Trailing dot domain" },
    { uri: "javascript:alert(document.cookie)", name: "javascript: pseudo-protocol" },
    { uri: "data:text/html,<html>alert(1)</html>", name: "data: URI scheme" },
  ];

  for (const tc of testCases) {
    const isRedirectUriValid = validateRedirectUri(tc.uri, { isDev: false, env: "production" });
    const isSafeCbValid = safeCallbackURL(tc.uri);
    console.log(`[B5] ${tc.name} ("${tc.uri}") -> validateRedirectUri: ${isRedirectUriValid} | safeCallbackURL: ${isSafeCbValid}`);
  }
}

// -------------------------------------------------------------
// B7. Password reset abuse chain & timing oracle
// -------------------------------------------------------------
console.log("\n>>> B7. Password Reset Timing & Enumeration Audit");
{
  // Test timing difference for registered email vs nonexistent email
  const existingEmail = "admin-existing@swyra.test";
  const nonExistingEmail = "nonexistent-" + Date.now() + "@swyra.test";

  // Create user
  await db.collection("user").insertOne({
    _id: new ObjectId(),
    email: existingEmail,
    name: "Existing User",
    emailVerified: true,
    role: "user",
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const t0 = performance.now();
  const resExisting = await app.request("/api/auth/request-password-reset", {
    method: "POST",
    headers: {
      "Origin": "http://localhost:5174",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email: existingEmail, redirectTo: "http://localhost:5174/reset-password" }),
  });
  const tExisting = performance.now() - t0;

  const t1 = performance.now();
  const resNonExisting = await app.request("/api/auth/request-password-reset", {
    method: "POST",
    headers: {
      "Origin": "http://localhost:5174",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email: nonExistingEmail, redirectTo: "http://localhost:5174/reset-password" }),
  });
  const tNonExisting = performance.now() - t1;

  console.log(`B7 Registered Email Response Status: ${resExisting.status} (${tExisting.toFixed(1)}ms)`);
  console.log(`B7 Non-Registered Email Response Status: ${resNonExisting.status} (${tNonExisting.toFixed(1)}ms)`);
  console.log(`Registered Email Body: ${JSON.stringify(await resExisting.json().catch(() => ({})))}`);
  console.log(`Non-Registered Email Body: ${JSON.stringify(await resNonExisting.json().catch(() => ({})))}`);

  await db.collection("user").deleteOne({ email: existingEmail });
}

// -------------------------------------------------------------
// B8. Session fixation audit
// -------------------------------------------------------------
console.log("\n>>> B8. Session Fixation Audit");
{
  // Check if session token changes upon authentication
  const email = "fixation-test-" + Date.now() + "@swyra.test";
  const password = "FixationPassword@123!";

  await authProvider.api.signUpEmail({
    body: { email, password, name: "Fixation User" },
  });

  // Client starts with arbitrary pre-auth cookie
  const preAuthCookie = "better-auth.session_token=preauth-attacker-chosen-token-123456";

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: {
      "Origin": "http://localhost:5174",
      "Content-Type": "application/json",
      "Cookie": preAuthCookie,
    },
    body: JSON.stringify({ email, password }),
  });

  const postAuthSetCookie = loginRes.headers.get("set-cookie") || "";
  console.log(`B8 Post-Auth Set-Cookie Header Present: ${postAuthSetCookie.includes("better-auth.session_token=")}`);
  console.log(`B8 Pre-Auth Cookie Reused: ${postAuthSetCookie.includes("preauth-attacker-chosen-token-123456")}`);

  await db.collection("user").deleteOne({ email });
  await db.collection("account").deleteMany({ accountId: email });
}

// -------------------------------------------------------------
// B9. Injection sweep on NEW code from last remediation pass
// -------------------------------------------------------------
console.log("\n>>> B9. Injection Sweep on Recent Code");
{
  // 1. NoSQL operator injection on POST /admin/users
  const nosqlRes = await app.request("/api/admin/users", {
    method: "POST",
    headers: {
      "Origin": "http://localhost:5174",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email: { "$ne": null },
      password: { "$gt": "" },
      clientId: { "$ne": null },
    }),
  });
  console.log(`B9 NoSQL injection on /admin/users Status: ${nosqlRes.status}`);
  const nosqlBody = await nosqlRes.json();
  console.log(`B9 NoSQL Response: ${JSON.stringify(nosqlBody)}`);

  // 2. Cascade delete parameter validation (DELETE /api/admin/clients/:id)
  // Ensure non-string / operator-like route params don't corrupt MongoDB deleteMany
  const deleteRes = await app.request("/api/admin/clients/%24ne", {
    method: "DELETE",
    headers: { "Origin": "http://localhost:5174" },
  });
  console.log(`B9 Route param injection on DELETE /api/admin/clients/$ne Status: ${deleteRes.status}`);
}

// -------------------------------------------------------------
// B10. Account enumeration & timing on /admin/login
// -------------------------------------------------------------
console.log("\n>>> B10. Account Enumeration & Timing on /admin/login");
{
  const adminEmail = "admin-enum-test@swyra.test";
  const userEmail = "user-enum-test@swyra.test";
  const nonexistentEmail = "nobody-exists-" + Date.now() + "@swyra.test";
  const correctPass = "CorrectAdminPassword@123!";
  const wrongPass = "WrongPassword@123!";

  // Create admin user
  const adminId = new ObjectId();
  await db.collection("user").insertOne({
    _id: adminId,
    id: String(adminId),
    email: adminEmail,
    name: "Enum Admin",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  await db.collection("account").insertOne({
    _id: new ObjectId(),
    userId: adminId,
    accountId: String(adminId),
    providerId: "credential",
    password: await hashPassword(correctPass),
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Create standard non-admin user
  const userId = new ObjectId();
  await db.collection("user").insertOne({
    _id: userId,
    id: String(userId),
    email: userEmail,
    name: "Enum User",
    role: "user",
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  await db.collection("account").insertOne({
    _id: new ObjectId(),
    userId,
    accountId: String(userId),
    providerId: "credential",
    password: await hashPassword(correctPass),
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // 1. Valid Admin + Wrong Password
  const t0 = performance.now();
  const res1 = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: { "Origin": "http://localhost:5174", "Content-Type": "application/json" },
    body: JSON.stringify({ email: adminEmail, password: wrongPass }),
  });
  const t1 = performance.now() - t0;

  // 2. Valid Non-Admin User + Wrong Password
  const t2 = performance.now();
  const res2 = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: { "Origin": "http://localhost:5174", "Content-Type": "application/json" },
    body: JSON.stringify({ email: userEmail, password: wrongPass }),
  });
  const t3 = performance.now() - t2;

  // 3. Nonexistent Email
  const t4 = performance.now();
  const res3 = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: { "Origin": "http://localhost:5174", "Content-Type": "application/json" },
    body: JSON.stringify({ email: nonexistentEmail, password: wrongPass }),
  });
  const t5 = performance.now() - t4;

  console.log(`1. Valid Admin + Wrong Password: Status ${res1.status} (${t1.toFixed(1)}ms) - Body: ${JSON.stringify(await res1.json().catch(() => ({})))}`);
  console.log(`2. Valid Non-Admin + Wrong Password: Status ${res2.status} (${t3.toFixed(1)}ms) - Body: ${JSON.stringify(await res2.json().catch(() => ({})))}`);
  console.log(`3. Nonexistent Email: Status ${res3.status} (${t5.toFixed(1)}ms) - Body: ${JSON.stringify(await res3.json().catch(() => ({})))}`);

  await db.collection("user").deleteMany({ email: { $in: [adminEmail, userEmail] } });
  await db.collection("account").deleteMany({ userId: { $in: [adminId, userId] } });
}

await closeDb();
console.log("\n================================================================");
console.log("  PART B AUDIT COMPLETE");
console.log("================================================================");
