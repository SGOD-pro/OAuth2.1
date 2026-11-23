import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { Worker } from "node:worker_threads";
import { createRequire } from "node:module";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { generateKeyPair, SignJWT } from "jose";
import { createOTP } from "@better-auth/utils/otp";

const require = createRequire(import.meta.url);
const mongoPkgPath = require.resolve("mongodb");

console.log("================================================================");
console.log("  SWYRA AUTH -- OAUTH SECURITY HARDENING REGRESSION TEST SUITE");
console.log("================================================================\n");

const suite = await setupSuiteDatabase("oauth_hardening");
process.env.BETTER_AUTH_SECRET = "s".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
const GATEWAY_SECRET = "g".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = GATEWAY_SECRET;
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = "127.0.0.1/32,10.0.0.0/8";

const { getDb, closeDb } = await import("../../src/db/mongo");
const { default: app } = await import("../../src/app");
const { authProvider } = await import("../../src/utils/auth");
const {
  mintJwtAccessToken,
  setSigningKeyOverrideForTesting,
  setTokenBarrierHookForTesting,
  revokeUserTokensDurable,
} = await import("../../src/routes/auth");
const { hashToken } = await import("../../src/utils/security");
const { registerTokenFamily } = await import("../../src/db/state");
const { checkAccountEligibility } = await import(
  "../../src/utils/account-eligibility"
).catch(() => ({ checkAccountEligibility: null as any }));

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
function getTestHeaders(extra: Record<string, string> = {}): Headers {
  const h = new Headers();
  const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
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

function extractCookie(header: string | null, name: string): string {
  if (!header) return "";
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = header.match(new RegExp(`${escaped}=([^;,\\s]+)`));
  return match ? `${name}=${match[1]}` : "";
}

const db = await getDb();

// Seed test client
const testClientSecret = "test-sec-secret";
const hashedClientSecret = crypto.createHash("sha256").update(testClientSecret).digest("base64url");
const testClient = {
  id: "test-sec-client",
  clientId: "test-sec-client",
  clientSecret: hashedClientSecret,
  redirectUris: ["http://localhost:5174/callback"],
  allowedOrigins: ["http://localhost:5174"],
  isPublic: false,
  isDev: true,
  skipConsent: true,
  tokenEndpointAuthMethod: "client_secret_basic",
  createdAt: new Date(),
};
await db.collection("oauthClient").insertOne(testClient);
const basicAuth = Buffer.from(`test-sec-client:${testClientSecret}`).toString("base64");

const { getIdpSigningKey } = await import("../../src/routes/auth");
const { getIdpPublicKey } = await import("../../src/middleware/admin-auth");
const signingKeyInfo = await getIdpSigningKey();
assert.ok(signingKeyInfo, "IdP signing key must be initialized");
const idpPublicKey = await getIdpPublicKey(signingKeyInfo.kid);
assert.ok(idpPublicKey, "IdP public key must be resolvable");

async function mintAdminBearerToken(params: {
  sub: string;
  role?: string;
  scopedClientId?: string | null;
  mfa?: boolean;
  amr?: string[];
  mfaVerifiedAtSec?: number;
}): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT({
    sub: params.sub,
    role: params.role || "super-admin",
    scoped_client_id: params.scopedClientId === undefined ? null : params.scopedClientId,
    aud: "http://localhost:3000",
    mfa: params.mfa,
    amr: params.amr,
    mfa_verified_at: params.mfaVerifiedAtSec,
  })
    .setProtectedHeader({ alg: "RS256", kid: signingKeyInfo.kid })
    .setIssuer("http://localhost:3000")
    .setIssuedAt(nowSec)
    .setExpirationTime(nowSec + 900);

  return jwt.sign(signingKeyInfo.privateKey);
}

console.log("Running Slice 1: Account Eligibility & Token Lifecycle Probes...\n");

await runTest("SEC-01-A: checkAccountEligibility rejects missing, banned, disabled, inactive, deleting, deleted accounts", async () => {
  assert.ok(checkAccountEligibility, "checkAccountEligibility helper must be defined");
  assert.equal(checkAccountEligibility(null).eligible, false);
  assert.equal(checkAccountEligibility({ id: "u1", banned: true }).eligible, false);
  assert.equal(checkAccountEligibility({ id: "u2", disabled: true }).eligible, false);
  assert.equal(checkAccountEligibility({ id: "u3", isActive: false }).eligible, false);
  assert.equal(checkAccountEligibility({ id: "u4", status: "inactive" }).eligible, false);
  assert.equal(checkAccountEligibility({ id: "u5", status: "deleting" }).eligible, false);
  assert.equal(checkAccountEligibility({ id: "u6", deletedAt: new Date() }).eligible, false);
  assert.equal(checkAccountEligibility({ id: "u7", emailVerified: false }, { requireEmailVerified: true }).eligible, false);
  assert.equal(checkAccountEligibility({ id: "u8", emailVerified: true }).eligible, true);
});

await runTest("SEC-01-B: mintJwtAccessToken rejects ineligible accounts", async () => {
  // Test user that does not exist
  const tokenMissing = await mintJwtAccessToken({
    userId: "non-existent-user-id",
    clientId: "test-sec-client",
    scope: "openid",
  });
  assert.equal(tokenMissing, null, "Must return null for non-existent user");

  // Seed banned user
  await db.collection("user").insertOne({
    id: "banned-user-1",
    email: "banned@example.com",
    role: "user",
    banned: true,
    createdAt: new Date(),
  });
  const tokenBanned = await mintJwtAccessToken({
    userId: "banned-user-1",
    clientId: "test-sec-client",
    scope: "openid",
  });
  assert.equal(tokenBanned, null, "Must return null for banned user");

  // Seed disabled user
  await db.collection("user").insertOne({
    id: "disabled-user-1",
    email: "disabled@example.com",
    role: "user",
    disabled: true,
    createdAt: new Date(),
  });
  const tokenDisabled = await mintJwtAccessToken({
    userId: "disabled-user-1",
    clientId: "test-sec-client",
    scope: "openid",
  });
  assert.equal(tokenDisabled, null, "Must return null for disabled user");
});

await runTest("SEC-01-C: mintJwtAccessToken rejects tokens revoked before issue time", async () => {
  await db.collection("user").insertOne({
    id: "revoked-user-1",
    email: "revoked@example.com",
    role: "user",
    tokensRevokedBefore: new Date(Date.now() + 60000), // future revocation timestamp
    createdAt: new Date(),
  });
  const token = await mintJwtAccessToken({
    userId: "revoked-user-1",
    clientId: "test-sec-client",
    scope: "openid",
  });
  assert.equal(token, null, "Must return null when tokens are revoked");
});

await runTest("SEC-01-J: Same-second credential issuance and revocation handling with millisecond precision and durable token versions", async () => {
  const nowSec = Math.floor(Date.now() / 1000);
  const baseMs = nowSec * 1000;
  const revokedDate = new Date(baseMs + 500);

  // 1. Same-second token issued 300ms before revocation (rejected)
  const u1 = { id: "same-sec-u1", tokensRevokedBefore: revokedDate, tokenVersion: 3 };
  const resBefore = checkAccountEligibility(u1, { tokenIssuedAtMs: baseMs + 200, tokenVersion: 3 });
  assert.equal(resBefore.eligible, false, "Token issued before revocation in same second must be rejected");
  assert.equal(resBefore.reason, "tokens_revoked");

  // 2. Same-second token issued 200ms after revocation (accepted)
  const resAfter = checkAccountEligibility(u1, { tokenIssuedAtMs: baseMs + 700, tokenVersion: 3 });
  assert.equal(resAfter.eligible, true, "Token issued after revocation in same second must be accepted");

  // 3. Same-second token issued at exact millisecond of revocation (accepted)
  const resExact = checkAccountEligibility(u1, { tokenIssuedAtMs: baseMs + 500, tokenVersion: 3 });
  assert.equal(resExact.eligible, true, "Token issued at exact millisecond of revocation is accepted");

  // 4. Same-second password change handling
  const u2 = { id: "same-sec-u2", passwordChangedAt: new Date(baseMs + 500) };
  const resPwBefore = checkAccountEligibility(u2, { tokenIssuedAtMs: baseMs + 200 });
  assert.equal(resPwBefore.eligible, false, "Token issued before password change in same second must be rejected");
  assert.equal(resPwBefore.reason, "tokens_revoked");

  const resPwAfter = checkAccountEligibility(u2, { tokenIssuedAtMs: baseMs + 700 });
  assert.equal(resPwAfter.eligible, true, "Token issued after password change in same second must be accepted");

  // 5. Monotonic tokenVersion enforcement
  const u3 = { id: "same-sec-u3", tokenVersion: 4 };
  const resOldVersion = checkAccountEligibility(u3, { tokenVersion: 3 });
  assert.equal(resOldVersion.eligible, false, "Token with older version must be rejected");
  assert.equal(resOldVersion.reason, "tokens_revoked");

  const resMatchingVersion = checkAccountEligibility(u3, { tokenVersion: 4 });
  assert.equal(resMatchingVersion.eligible, true, "Token with matching version must be accepted");

  // 6. Safe legacy handling: token with only integer second equal to revocation second fails closed
  const u4 = { id: "same-sec-u4", tokensRevokedBefore: new Date(baseMs + 500) };
  const resLegacySameSec = checkAccountEligibility(u4, { tokenIssuedAtSec: nowSec });
  assert.equal(resLegacySameSec.eligible, false, "Legacy integer second token within revocation second must fail closed");
  assert.equal(resLegacySameSec.reason, "tokens_revoked");

  const resLegacyNextSec = checkAccountEligibility(u4, { tokenIssuedAtSec: nowSec + 1 });
  assert.equal(resLegacyNextSec.eligible, true, "Legacy integer second token in subsequent second is accepted");

  // 7. Safe legacy records handling without versions
  // 7a. User without tokenVersion is treated as effective version 1
  const legacyUser1 = { id: "legacy-u1" };
  const resLegacyUserV1Token = checkAccountEligibility(legacyUser1, { tokenVersion: 1 });
  assert.equal(resLegacyUserV1Token.eligible, true, "Legacy user without tokenVersion accepts version 1 token");

  const resLegacyUserV0Token = checkAccountEligibility(legacyUser1, { tokenVersion: 0 });
  assert.equal(resLegacyUserV0Token.eligible, false, "Legacy user rejects token with version < 1");
  assert.equal(resLegacyUserV0Token.reason, "tokens_revoked");

  // 7b. Unversioned legacy token accepted when user is at version 1 (or unversioned)
  const resLegacyTokenV1User = checkAccountEligibility(legacyUser1, {});
  assert.equal(resLegacyTokenV1User.eligible, true, "Unversioned legacy token is accepted when user is at version 1");

  // 7c. Unversioned legacy token fails closed when user version has advanced past 1 (was revoked)
  const versionedUser2 = { id: "versioned-u2", tokenVersion: 2 };
  const resLegacyTokenRevokedUser = checkAccountEligibility(versionedUser2, {});
  assert.equal(resLegacyTokenRevokedUser.eligible, false, "Unversioned legacy token must fail closed when user version > 1");
  assert.equal(resLegacyTokenRevokedUser.reason, "tokens_revoked");

  // 8. Real route verification for same-second issuance
  const sameSecUserId = "same-sec-route-user-" + crypto.randomBytes(4).toString("hex");
  await db.collection("user").insertOne({
    id: sameSecUserId,
    email: "samesec@example.com",
    role: "user",
    tokenVersion: 1,
    createdAt: new Date(),
  });

  // Mint older version token and token issued at T0 (before revocation)
  const tokenOldVersion = await mintJwtAccessToken({
    userId: sameSecUserId,
    clientId: "test-sec-client",
    scope: "openid",
    tokenIssuedAtMs: baseMs + 200,
    tokenVersion: 1,
  });
  assert.ok(tokenOldVersion, "Token with older version must be minted");

  const tokenBefore = await mintJwtAccessToken({
    userId: sameSecUserId,
    clientId: "test-sec-client",
    scope: "openid",
    tokenIssuedAtMs: baseMs + 200,
    tokenVersion: 2,
  });
  assert.ok(tokenBefore, "Token before revocation must be minted");

  // Revoke credentials at T1 (revokedDate = baseMs + 500) and increment tokenVersion in DB
  await db.collection("user").updateOne(
    { id: sameSecUserId },
    { $set: { tokensRevokedBefore: revokedDate, tokenVersion: 2 } }
  );

  // Mint token at T2 (baseMs + 700) after revocation in the exact same second
  const tokenAfter = await mintJwtAccessToken({
    userId: sameSecUserId,
    clientId: "test-sec-client",
    scope: "openid",
    tokenIssuedAtMs: baseMs + 700,
    tokenVersion: 2,
  });
  assert.ok(tokenAfter, "Token after revocation in same second must be minted");

  // Record tokens in oauthAccessToken for introspection state verification
  await db.collection("oauthAccessToken").insertOne({
    token: tokenBefore,
    clientId: "test-sec-client",
    userId: sameSecUserId,
    createdAt: new Date(baseMs + 200),
    expiresAt: new Date(Date.now() + 900000),
  });

  await db.collection("oauthAccessToken").insertOne({
    token: tokenAfter,
    clientId: "test-sec-client",
    userId: sameSecUserId,
    createdAt: new Date(baseMs + 700),
    expiresAt: new Date(Date.now() + 900000),
  });

  // Userinfo with token issued before revocation in same second -> 401
  const userInfoResBefore = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: { Authorization: `Bearer ${tokenBefore}` },
  });
  assert.equal(userInfoResBefore.status, 401, "Userinfo must reject token issued before revocation in same second");

  // Userinfo with token issued after revocation in same second -> 200
  const userInfoResAfter = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: { Authorization: `Bearer ${tokenAfter}` },
  });
  assert.equal(userInfoResAfter.status, 200, "Userinfo must accept token issued after revocation in same second");

  // Userinfo with token with older version -> 401
  const userInfoResOldVer = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: { Authorization: `Bearer ${tokenOldVersion}` },
  });
  assert.equal(userInfoResOldVer.status, 401, "Userinfo must reject token with older version");

  // Introspection with token before revocation in same second -> active: false
  const introResBefore = await app.request("/api/auth/oauth2/introspect", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    },
    body: `token=${tokenBefore}`,
  });
  assert.equal(introResBefore.status, 200);
  const introBodyBefore = await introResBefore.json();
  assert.equal(introBodyBefore.active, false, "Introspection must report active: false for token before revocation in same second");

  // Introspection with token after revocation in same second -> active: true
  const introResAfter = await app.request("/api/auth/oauth2/introspect", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    },
    body: `token=${tokenAfter}`,
  });
  assert.equal(introResAfter.status, 200);
  const introBodyAfter = await introResAfter.json();
  assert.equal(introBodyAfter.active, true, "Introspection must report active: true for token after revocation in same second");
});

console.log("\nRunning Slice 2: Scope & Privacy Enforcement Probes...\n");

await runTest("SEC-05-A: mintJwtAccessToken minimizes claims to granted scopes", async () => {
  await db.collection("user").insertOne({
    id: "scope-user-1",
    email: "scopeuser@example.com",
    name: "Scope User",
    role: "user",
    emailVerified: true,
    createdAt: new Date(),
  });

  // Mint with scope 'openid' only (no email, no profile)
  const tokenOpenIdOnly = await mintJwtAccessToken({
    userId: "scope-user-1",
    clientId: "test-sec-client",
    scope: "openid",
  });
  assert.ok(tokenOpenIdOnly, "Token should be minted for eligible user");
  const { jwtVerify } = await import("jose");
  const { payload: p1 } = await jwtVerify(tokenOpenIdOnly, idpPublicKey, {
    issuer: process.env.BETTER_AUTH_URL,
    audience: "test-sec-client",
    algorithms: ["RS256"],
  });
  assert.equal(p1.email, undefined, "Email must not be included without email scope");
  assert.equal(p1.name, undefined, "Name must not be included without profile scope");
  assert.equal(p1.sub, "scope-user-1", "Subject claim must be preserved");

  // Mint with scope 'openid email'
  const tokenWithEmail = await mintJwtAccessToken({
    userId: "scope-user-1",
    clientId: "test-sec-client",
    scope: "openid email",
  });
  assert.ok(tokenWithEmail);
  const { payload: p2 } = await jwtVerify(tokenWithEmail, idpPublicKey, {
    issuer: process.env.BETTER_AUTH_URL,
    audience: "test-sec-client",
    algorithms: ["RS256"],
  });
  assert.equal(p2.email, "scopeuser@example.com", "Email must be included when email scope granted");
  assert.equal(p2.name, undefined, "Name must not be included without profile scope");
});

await runTest("SEC-01-D: /oauth2/authorize rejects session of banned account with access_denied", async () => {
  const bannedUserEmail = "banned_auth_" + crypto.randomBytes(4).toString("hex") + "@example.com";
  const userPass = "Password1234!@#";

  const { authProvider } = await import("../../src/utils/auth");
  await authProvider.api.signUpEmail({
    body: { email: bannedUserEmail, password: userPass, name: "Banned User" },
  });

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: bannedUserEmail, password: userPass }),
  });
  assert.equal(loginRes.status, 200, "Sign in must succeed before banning");
  const cookie = (loginRes.headers.get("set-cookie") || "").split(";")[0];

  // Now ban user in DB
  await db.collection("user").updateOne({ email: bannedUserEmail }, { $set: { banned: true } });

  const res = await app.request(
    "/api/auth/oauth2/authorize?client_id=test-sec-client&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&scope=openid&state=teststate123",
    {
      method: "GET",
      headers: {
        Cookie: cookie,
      },
    }
  );

  assert.equal(res.status, 302, "Must redirect with error");
  const location = res.headers.get("location") || "";
  assert.ok(location.includes("error=access_denied"), `Redirect must contain error=access_denied, got: ${location}`);
});

await runTest("SEC-01-E: /oauth2/userinfo rejects tokens for banned or revoked accounts", async () => {
  const victimUserId = "victim-user-" + crypto.randomBytes(4).toString("hex");
  await db.collection("user").insertOne({
    id: victimUserId,
    email: "victim@example.com",
    role: "user",
    banned: false,
    createdAt: new Date(),
  });

  // Mint valid token
  const token = await mintJwtAccessToken({
    userId: victimUserId,
    clientId: "test-sec-client",
    scope: "openid email",
  });
  assert.ok(token);

  // Userinfo should succeed initially
  const res1 = await app.request("/api/auth/oauth2/userinfo", {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  assert.equal(res1.status, 200, "Valid token must access userinfo");

  // Now ban user
  await db.collection("user").updateOne({ id: victimUserId }, { $set: { banned: true } });

  // Userinfo must now fail closed
  const res2 = await app.request("/api/auth/oauth2/userinfo", {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  assert.equal(res2.status, 401, "Banned user token must be rejected with 401");
});

await runTest("SEC-02-A: Introspection rejects banned, disabled, revoked or missing users", async () => {
  const introUserId = "intro-user-" + crypto.randomBytes(4).toString("hex");
  await db.collection("user").insertOne({
    id: introUserId,
    email: "intro@example.com",
    role: "user",
    banned: false,
    createdAt: new Date(),
  });

  const token = await mintJwtAccessToken({
    userId: introUserId,
    clientId: "test-sec-client",
    scope: "openid",
  });
  assert.ok(token);

  await db.collection("oauthAccessToken").insertOne({
    token,
    clientId: "test-sec-client",
    userId: introUserId,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 900000),
  });

  // Introspect active user
  const resActive = await app.request("/api/auth/oauth2/introspect", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    },
    body: `token=${token}`,
  });
  assert.equal(resActive.status, 200);
  const bodyActive = await resActive.json();
  assert.equal(bodyActive.active, true, "Active user token must introspect as active: true");

  // Ban user and introspect again
  await db.collection("user").updateOne({ id: introUserId }, { $set: { banned: true } });
  const resBanned = await app.request("/api/auth/oauth2/introspect", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    },
    body: `token=${token}`,
  });
  assert.equal(resBanned.status, 200);
  const bodyBanned = await resBanned.json();
  assert.equal(bodyBanned.active, false, "Banned user token must introspect as active: false");
});

await runTest("SEC-05-B: UserInfo claim release minimizes claims strictly according to granted scope", async () => {
  const claimUserId = "claim-user-" + crypto.randomBytes(4).toString("hex");
  await db.collection("user").insertOne({
    id: claimUserId,
    email: "claims@example.com",
    name: "Claim Tester",
    role: "user",
    emailVerified: true,
    createdAt: new Date(),
  });

  // Scope: openid only
  const tokenOpenId = await mintJwtAccessToken({
    userId: claimUserId,
    clientId: "test-sec-client",
    scope: "openid",
  });
  const resOpenId = await app.request("/api/auth/oauth2/userinfo", {
    headers: { Authorization: `Bearer ${tokenOpenId}` },
  });
  assert.equal(resOpenId.status, 200);
  const bodyOpenId = await resOpenId.json();
  assert.equal(bodyOpenId.sub, claimUserId);
  assert.equal(bodyOpenId.email, undefined, "Email must be omitted without email scope");
  assert.equal(bodyOpenId.name, undefined, "Name must be omitted without profile scope");

  // Scope: openid profile
  const tokenProfile = await mintJwtAccessToken({
    userId: claimUserId,
    clientId: "test-sec-client",
    scope: "openid profile",
  });
  const resProfile = await app.request("/api/auth/oauth2/userinfo", {
    headers: { Authorization: `Bearer ${tokenProfile}` },
  });
  assert.equal(resProfile.status, 200);
  const bodyProfile = await resProfile.json();
  assert.equal(bodyProfile.sub, claimUserId);
  assert.equal(bodyProfile.name, "Claim Tester", "Name must be included with profile scope");
  assert.equal(bodyProfile.email, undefined, "Email must be omitted without email scope");
});

console.log("\nRunning Slice 3: Administrative MFA Probes...\n");

await runTest("SEC-04-A: Unenrolled administrator is denied privileged access and restricted to setup", async () => {
  const unenrolledAdminId = new (await import("mongodb")).ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new (await import("mongodb")).ObjectId(unenrolledAdminId),
    id: unenrolledAdminId,
    email: "unenrolled-admin@example.com",
    role: "super-admin",
    scopedClientId: null,
    twoFactorEnabled: false,
    emailVerified: true,
    createdAt: new Date(),
  });

  const bearerToken = await mintAdminBearerToken({
    sub: unenrolledAdminId,
    role: "super-admin",
  });

  // Attempt to access privileged admin route: GET /api/admin/clients
  const res = await app.request("/api/admin/clients", {
    headers: getTestHeaders({
      Authorization: `Bearer ${bearerToken}`,
    }),
  });
  assert.equal(res.status, 403, "Unenrolled admin must be denied privileged access with 403");
  const body = await res.json();
  assert.equal(body.code, "ERR_MFA_ENROLLMENT_REQUIRED");

  // Setup route /api/admin/me must succeed (setup-only authority)
  const resSetup = await app.request("/api/admin/me", {
    headers: getTestHeaders({
      Authorization: `Bearer ${bearerToken}`,
    }),
  });
  assert.equal(resSetup.status, 200, "Setup route must be accessible for unenrolled admin");
});

await runTest("SEC-04-B: Enrolled admin with unverified session is blocked until completed", async () => {
  const enrolledAdminId = new (await import("mongodb")).ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new (await import("mongodb")).ObjectId(enrolledAdminId),
    id: enrolledAdminId,
    email: "enrolled-admin@example.com",
    role: "super-admin",
    scopedClientId: null,
    twoFactorEnabled: true,
    emailVerified: true,
    createdAt: new Date(),
  });

  const bearerToken = await mintAdminBearerToken({
    sub: enrolledAdminId,
    role: "super-admin",
    mfa: false,
  });

  const res = await app.request("/api/admin/clients", {
    headers: getTestHeaders({
      Authorization: `Bearer ${bearerToken}`,
    }),
  });
  assert.equal(res.status, 403, "Enrolled admin without verified session must receive 403");
  const body = await res.json();
  assert.equal(body.code, "ERR_MFA_REQUIRED");
});

await runTest("SEC-04-C: Sensitive administrative operations require recent MFA (<15 min)", async () => {
  const stepUpAdminId = new (await import("mongodb")).ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new (await import("mongodb")).ObjectId(stepUpAdminId),
    id: stepUpAdminId,
    email: "stepup-admin@example.com",
    role: "super-admin",
    scopedClientId: null,
    twoFactorEnabled: true,
    emailVerified: true,
    createdAt: new Date(),
  });

  // Token with stale MFA (> 15 minutes ago, e.g. 30 mins ago)
  const staleToken = await mintAdminBearerToken({
    sub: stepUpAdminId,
    role: "super-admin",
    mfa: true,
    amr: ["mfa"],
    mfaVerifiedAtSec: Math.floor(Date.now() / 1000) - 1800,
  });

  // Seed a target client for deletion
  const clientToDeleteId = "client-delete-target-" + crypto.randomBytes(4).toString("hex");
  await db.collection("oauthClient").insertOne({
    clientId: clientToDeleteId,
    name: "Client To Delete",
    redirectUris: ["http://localhost:5174/callback"],
    allowedOrigins: ["http://localhost:5174"],
    isPublic: true,
    isDev: true,
    createdAt: new Date(),
  });

  // Attempt sensitive operation: DELETE /clients/:id
  const resStale = await app.request(`/api/admin/clients/${clientToDeleteId}`, {
    method: "DELETE",
    headers: getTestHeaders({
      Authorization: `Bearer ${staleToken}`,
    }),
  });
  assert.equal(resStale.status, 403, "Stale MFA must be rejected on sensitive route");
  const staleBody = await resStale.json();
  assert.equal(staleBody.code, "ERR_MFA_STEP_UP_REQUIRED");

  // Token with fresh MFA (1 minute ago)
  const freshToken = await mintAdminBearerToken({
    sub: stepUpAdminId,
    role: "super-admin",
    mfa: true,
    amr: ["mfa"],
    mfaVerifiedAtSec: Math.floor(Date.now() / 1000) - 60,
  });

  const resFresh = await app.request(`/api/admin/clients/${clientToDeleteId}`, {
    method: "DELETE",
    headers: getTestHeaders({
      Authorization: `Bearer ${freshToken}`,
    }),
  });
  assert.equal(resFresh.status, 200, "Fresh MFA must allow sensitive administrative deletion");
});

console.log("\nRunning Slice 4: Verification & Abuse Control Probes...\n");

await runTest("SEC-03-A: Email verification safe rollout policy", async () => {
  const rolloutDate = new Date("2026-06-01T00:00:00.000Z");
  process.env.AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE = "enforce_new";
  process.env.AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER = rolloutDate.toISOString();

  // Existing user created prior to rollout date
  const preExistingUser = {
    id: "pre-rollout-user",
    emailVerified: false,
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
  };
  const preCheck = checkAccountEligibility(preExistingUser, { requireEmailVerified: true });
  assert.equal(preCheck.eligible, true, "Pre-existing account must be allowed under rollout grace");

  // New user created after rollout date
  const postRolloutUser = {
    id: "post-rollout-user",
    emailVerified: false,
    createdAt: new Date("2026-07-01T00:00:00.000Z"),
  };
  const postCheck = checkAccountEligibility(postRolloutUser, { requireEmailVerified: true });
  assert.equal(postCheck.eligible, false, "Post-rollout unverified account must be rejected");
  assert.equal(postCheck.reason, "email_not_verified");

  // Cutoff timestamps missing explicit timezone must fail closed
  process.env.AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER = "2026-06-01";
  const invalidDateCheck = checkAccountEligibility(preExistingUser, { requireEmailVerified: true });
  assert.equal(invalidDateCheck.eligible, false, "Cutoff missing explicit timezone must fail closed");

  process.env.AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER = "2026-06-01T00:00:00";
  const noTzCheck = checkAccountEligibility(preExistingUser, { requireEmailVerified: true });
  assert.equal(noTzCheck.eligible, false, "Cutoff without timezone indicator must fail closed");

  delete process.env.AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE;
  delete process.env.AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER;
});

await runTest("SEC-06-A: Dual-store rate limiter outage fails closed for sensitive auth operations", async () => {
  const { createRateLimiter } = await import("../../src/middleware/rate-limit");
  const stateModule = await import("../../src/db/state");
  const authLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    limit: 5,
    prefix: "auth_sensitive_test",
    limiterName: "authTest",
    sensitivity: "auth",
  });

  let handlerExecuted = false;
  const testHono = new (await import("hono")).Hono();
  testHono.use("*", authLimiter);
  testHono.get("/test", (c) => {
    handlerExecuted = true;
    return c.text("ok");
  });

  stateModule.__simulateRateLimitStoreFailure(true);
  try {
    const res = await testHono.request("/test", {
      headers: { "x-forwarded-for": "198.51.100.99, 10.0.0.1" },
    });
    assert.equal(res.status, 429, "Auth rate limiter must immediately fail closed (429) when backing stores fail");
    assert.equal(handlerExecuted, false, "Protected handler must never execute under store failure");
    const data = await res.json();
    assert.equal(data.error, "too_many_requests");
  } finally {
    stateModule.__simulateRateLimitStoreFailure(false);
  }
});

await runTest("SEC-05-C: Admin user listing enforces server-side privacy projection", async () => {
  const adminId = new (await import("mongodb")).ObjectId().toString();
  await db.collection("user").insertOne({
    _id: new (await import("mongodb")).ObjectId(adminId),
    id: adminId,
    email: "superadmin-list@swyra.com",
    role: "super-admin",
    scopedClientId: null,
    twoFactorEnabled: true,
    emailVerified: true,
    createdAt: new Date(),
  });

  const bearerToken = await mintAdminBearerToken({
    sub: adminId,
    role: "super-admin",
    mfa: true,
    amr: ["mfa"],
  });

  const res = await app.request("/api/admin/users", {
    headers: getTestHeaders({
      Authorization: `Bearer ${bearerToken}`,
    }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(Array.isArray(body), "Must return users array");
  assert.ok(body.length > 0, "Must have users");

  // Verify that all returned users have masked display labels and plain email is completely removed
  for (const u of body) {
    assert.equal(u.email, undefined, "Plain email field must be stripped from admin user listing");
    assert.ok(u.displayLabel, "Must provide displayLabel");
    if (u.displayLabel.includes("@")) {
      assert.ok(
        u.displayLabel.includes("*"),
        `Email display label must be masked, got plain: ${u.displayLabel}`
      );
    }
  }
});

await runTest("SEC-01-F: Token introspection enforces immutable subject check without email fallback", async () => {
  const userAId = "user-immutable-a-" + crypto.randomBytes(4).toString("hex");
  const userBId = "user-immutable-b-" + crypto.randomBytes(4).toString("hex");

  // User A has immutable ID userAId and is banned
  await db.collection("user").insertOne({
    id: userAId,
    email: "alpha-real@example.com",
    role: "user",
    banned: true,
    createdAt: new Date(),
  });

  // User B maliciously uses userAId as their email, but is active
  await db.collection("user").insertOne({
    id: userBId,
    email: userAId,
    role: "user",
    banned: false,
    createdAt: new Date(),
  });

  // Token is minted for User A (sub = userAId)
  const token = await mintJwtAccessToken({
    userId: userAId,
    clientId: "test-sec-client",
    scope: "openid",
  });
  // Since User A is banned, minting was rejected (ineligible)
  assert.equal(token, null, "Minting must reject banned subject even if another user has matching email");
});

await runTest("SEC-01-G: Refresh token exchange rejects banned or disabled users", async () => {
  const refreshUserId = "user-refresh-" + crypto.randomBytes(4).toString("hex");
  await db.collection("user").insertOne({
    id: refreshUserId,
    email: "refresh-user@example.com",
    role: "user",
    banned: true, // Ineligible user
    createdAt: new Date(),
  });

  const refreshToken = "rt-" + crypto.randomBytes(16).toString("hex");
  const { hashToken } = await import("../../src/utils/security");
  const incomingHash = hashToken(refreshToken, "hex");

  await db.collection("oauthRefreshToken").insertOne({
    token: refreshToken,
    clientId: "test-sec-client",
    userId: refreshUserId,
    expiresAt: new Date(Date.now() + 86400000),
    createdAt: new Date(),
  });

  await db.collection("oauth_token_families").insertOne({
    familyId: crypto.randomUUID(),
    clientId: "test-sec-client",
    userId: refreshUserId,
    activeTokenHash: incomingHash,
    status: "active",
    createdAt: new Date(),
  });

  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    }),
    body: `grant_type=refresh_token&refresh_token=${refreshToken}`,
  });

  // Must reject ineligible account with 401
  assert.equal(res.status, 401, "Refresh token for banned account must be rejected with 401");
  const body = await res.json();
  assert.ok(body.error === "invalid_grant" || body.error === "access_denied", `Expected error invalid_grant/access_denied, got: ${body.error}`);
});

await runTest("SEC-03-B: Verification grace window never skips revocation, password change, or account status", async () => {
  const origRollout = process.env.AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE;
  const origAfter = process.env.AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER;

  try {
    process.env.AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE = "enforce_new";
    process.env.AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER = new Date(Date.now() + 1000000).toISOString();

    const baseGraceUser = {
      id: "grace-user-1",
      email: "grace@example.com",
      emailVerified: false,
      createdAt: new Date(Date.now() - 500000),
      status: "active",
    };

    // 1. In grace window, but tokensRevokedBefore is newer than token issued time
    const revokedUser = {
      ...baseGraceUser,
      tokensRevokedBefore: new Date(Date.now() - 10000),
    };
    const resRevoked = checkAccountEligibility(revokedUser, {
      requireEmailVerified: true,
      tokenIssuedAtSec: Math.floor((Date.now() - 20000) / 1000),
    });
    assert.equal(resRevoked.eligible, false, "Grace window must NOT bypass tokensRevokedBefore check");
    assert.equal(resRevoked.reason, "tokens_revoked");

    // 2. In grace window, but passwordChangedAt is newer than token issued time
    const pwChangedUser = {
      ...baseGraceUser,
      passwordChangedAt: new Date(Date.now() - 10000),
    };
    const resPw = checkAccountEligibility(pwChangedUser, {
      requireEmailVerified: true,
      tokenIssuedAtSec: Math.floor((Date.now() - 20000) / 1000),
    });
    assert.equal(resPw.eligible, false, "Grace window must NOT bypass passwordChangedAt check");
    assert.equal(resPw.reason, "tokens_revoked");

    // 3. In grace window, but account is banned
    const bannedUser = {
      ...baseGraceUser,
      banned: true,
    };
    const resBanned = checkAccountEligibility(bannedUser, {
      requireEmailVerified: true,
    });
    assert.equal(resBanned.eligible, false, "Grace window must NOT bypass banned check");
    assert.equal(resBanned.reason, "account_banned");

    // 4. In grace window, but account is disabled
    const disabledUser = {
      ...baseGraceUser,
      disabled: true,
    };
    const resDisabled = checkAccountEligibility(disabledUser, {
      requireEmailVerified: true,
    });
    assert.equal(resDisabled.eligible, false, "Grace window must NOT bypass disabled check");
    assert.equal(resDisabled.reason, "account_disabled");
  } finally {
    if (origRollout) process.env.AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE = origRollout;
    else delete process.env.AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE;
    if (origAfter) process.env.AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER = origAfter;
    else delete process.env.AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER;
  }
});

await runTest("SEC-01-H: Revocation wins code exchange and refresh with older credentials", async () => {
  const userId = "user-rev-wins-" + crypto.randomBytes(4).toString("hex");
  const t0 = new Date(Date.now() - 15000); // Credential issued at T0
  const t1 = new Date(Date.now() - 8000);  // Tokens revoked at T1 (T0 < T1)

  await db.collection("user").insertOne({
    id: userId,
    email: "rev-wins@example.com",
    role: "user",
    tokensRevokedBefore: t1,
    createdAt: new Date(Date.now() - 30000),
  });

  // 1. Authorization Code issued at T0 cannot be exchanged at T2
  const authCode = "code-rev-wins-" + crypto.randomBytes(8).toString("hex");
  await db.collection("oauthAuthorizationCode").insertOne({
    code: authCode,
    clientId: "test-sec-client",
    userId: userId,
    redirectUri: "https://example.com/callback",
    createdAt: t0,
    expiresAt: new Date(Date.now() + 60000),
  });

  const codeRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    }),
    body: `grant_type=authorization_code&code=${authCode}&redirect_uri=https://example.com/callback&client_id=test-sec-client`,
  });
  assert.equal(codeRes.status, 400, "Older authorization code must be rejected when tokens were revoked prior to exchange");
  const codeBody = await codeRes.json();
  assert.equal(codeBody.error, "invalid_grant");

  // 2. Refresh Token issued at T0 cannot be refreshed at T2
  const refToken = "rt-rev-wins-" + crypto.randomBytes(16).toString("hex");
  const { hashToken } = await import("../../src/utils/security");
  const refHash = hashToken(refToken, "hex");

  await db.collection("oauthRefreshToken").insertOne({
    token: refToken,
    clientId: "test-sec-client",
    userId: userId,
    createdAt: t0,
    expiresAt: new Date(Date.now() + 86400000),
  });

  await db.collection("oauth_token_families").insertOne({
    familyId: crypto.randomUUID(),
    clientId: "test-sec-client",
    userId: userId,
    activeTokenHash: refHash,
    status: "active",
    createdAt: t0,
  });

  const refRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    }),
    body: `grant_type=refresh_token&refresh_token=${refToken}`,
  });
  assert.equal(refRes.status, 401, "Older refresh token must be rejected when tokens were revoked prior to refresh");
  const refBody = await refRes.json();
  assert.equal(refBody.error, "invalid_grant");
});

await runTest("SEC-01-I: Revocation wins overlapping code exchange and refresh under concurrent multi-worker race with deterministic barrier", async () => {
  const workerCode = `
    const { parentPort, workerData } = require("node:worker_threads");
    const { MongoClient } = require(workerData.mongoPkgPath);
    let client = null;
    parentPort.on("message", async (msg) => {
      try {
        if (msg.action === "connect") {
          client = new MongoClient(workerData.mongoUri);
          await client.connect();
          parentPort.postMessage({ status: "connected" });
        } else if (msg.action === "revoke") {
          const db = client.db();
          await db.collection("user").updateOne(
            { id: msg.userId },
            { $inc: { tokenVersion: 1 }, $set: { tokensRevokedBefore: new Date(), banned: true } }
          );
          await db.collection("oauth_token_families").updateMany(
            { userId: msg.userId },
            { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
          );
          await db.collection("oauthAccessToken").deleteMany({ userId: msg.userId });
          await db.collection("oauthRefreshToken").deleteMany({ userId: msg.userId });
          parentPort.postMessage({ status: "revoked" });
        } else if (msg.action === "close") {
          if (client) await client.close();
          parentPort.postMessage({ status: "closed" });
        }
      } catch (err) {
        parentPort.postMessage({ status: "error", error: err.message });
      }
    });
  `;

  const worker = new Worker(workerCode, {
    eval: true,
    workerData: { mongoUri: suite.uri, mongoPkgPath },
  });

  await new Promise<void>((resolve, reject) => {
    worker.once("message", (m) => {
      if (m.status === "connected") resolve();
      else reject(new Error("Worker connect failed: " + m.error));
    });
    worker.postMessage({ action: "connect" });
  });

  const { authProvider } = await import("../../src/utils/auth");

  try {
    // 1. Authorization Code Exchange - Ordering 1: Revocation wins before issuance commits (interval after final read)
    const raceCodeEmail = `race-code-${crypto.randomBytes(4).toString("hex")}@platform.local`;
    const raceCodePassword = "Password@1234!";

    const raceCodeSignUp = await authProvider.api.signUpEmail({
      body: { email: raceCodeEmail, password: raceCodePassword, name: "Race Code User" },
    });
    const raceCodeUserId = String(raceCodeSignUp.user.id);

    await db.collection("user").updateOne(
      { email: raceCodeEmail },
      { $set: { id: raceCodeUserId, role: "user", tokenVersion: 1 } }
    );

    // Grant application registration and consent for private test-sec-client
    await db.collection("user_app_registrations").insertOne({
      userId: raceCodeUserId,
      clientId: "test-sec-client",
      appRole: "member",
      status: "active",
      isActive: true,
      registeredAt: new Date(),
    });
    await db.collection("oauthConsent").insertOne({
      clientId: "test-sec-client",
      userId: raceCodeUserId,
      scopes: ["openid"],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // Sign in to get session cookie for authorize
    const codeLoginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ email: raceCodeEmail, password: raceCodePassword }),
    });
    assert.equal(codeLoginRes.status, 200);
    const codeSessionCookie = (codeLoginRes.headers.get("set-cookie") || "").split(";")[0];

    // Authorize to get genuine authorization code
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=test-sec-client&response_type=code&code_challenge=${codeChallenge}&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&scope=openid&state=teststate123`,
      {
        method: "GET",
        headers: getTestHeaders({ Cookie: codeSessionCookie }),
      }
    );
    assert.equal(authRes.status, 302, "Authorize must redirect with authorization code");
    const authLocation = authRes.headers.get("location") || "";
    const authUrl = new URL(authLocation);
    const raceAuthCode = authUrl.searchParams.get("code")!;
    assert.ok(raceAuthCode, "Must extract genuine authorization code");

    let codeBarrierFired = false;
    setTokenBarrierHookForTesting(async (stage, userId) => {
      if ((stage === "before_issuance_commit" || stage === "before_fence_code") && userId === raceCodeUserId) {
        codeBarrierFired = true;
        await new Promise<void>((resolve, reject) => {
          worker.once("message", (m) => {
            if (m.status === "revoked") resolve();
            else reject(new Error("Worker revocation failed: " + m.error));
          });
          worker.postMessage({ action: "revoke", userId: raceCodeUserId });
        });
      }
    });

    const codeRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: `grant_type=authorization_code&code=${raceAuthCode}&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&code_verifier=${codeVerifier}&client_id=test-sec-client`,
    });

    assert.equal(codeBarrierFired, true, "Deterministic barrier must fire before issuance commit");
    assert.equal(codeRes.status, 400, "Conditional state transition must reject code exchange when user revoked concurrently");
    const codeBody = await codeRes.json();
    assert.equal(codeBody.error, "invalid_grant");
    assert.ok(codeBody.error_description.includes("revoked or version transitioned"), "Error description must identify concurrent revocation");

    // Assert zero active tokens survive in database
    const survivingAccessTokens = await db.collection("oauthAccessToken").countDocuments({ userId: raceCodeUserId });
    const survivingRefreshTokens = await db.collection("oauthRefreshToken").countDocuments({ userId: raceCodeUserId });
    assert.equal(survivingAccessTokens, 0, "No access token may survive atomic authorization fence purge");
    assert.equal(survivingRefreshTokens, 0, "No refresh token may survive atomic authorization fence purge");

    // 2. Authorization Code Exchange - Ordering 2: Issuance commits first, then revocation runs
    const raceCommitCodeEmail = `race-commit-code-${crypto.randomBytes(4).toString("hex")}@platform.local`;
    const raceCommitCodePassword = "Password@1234!";

    const raceCommitCodeSignUp = await authProvider.api.signUpEmail({
      body: { email: raceCommitCodeEmail, password: raceCommitCodePassword, name: "Race Commit Code User" },
    });
    const raceCommitCodeUserId = String(raceCommitCodeSignUp.user.id);

    await db.collection("user").updateOne(
      { email: raceCommitCodeEmail },
      { $set: { id: raceCommitCodeUserId, role: "user", tokenVersion: 1 } }
    );

    await db.collection("user_app_registrations").insertOne({
      userId: raceCommitCodeUserId,
      clientId: "test-sec-client",
      appRole: "member",
      status: "active",
      isActive: true,
      registeredAt: new Date(),
    });
    await db.collection("oauthConsent").insertOne({
      clientId: "test-sec-client",
      userId: raceCommitCodeUserId,
      scopes: ["openid", "offline_access"],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const commitCodeLoginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ email: raceCommitCodeEmail, password: raceCommitCodePassword }),
    });
    assert.equal(commitCodeLoginRes.status, 200);
    const commitCodeSessionCookie = (commitCodeLoginRes.headers.get("set-cookie") || "").split(";")[0];

    const commitCodeVerifier = crypto.randomBytes(32).toString("base64url");
    const commitCodeChallenge = crypto.createHash("sha256").update(commitCodeVerifier).digest("base64url");

    const commitCodeAuthRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=test-sec-client&response_type=code&code_challenge=${commitCodeChallenge}&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&scope=openid%20offline_access&state=commitcodestate`,
      {
        method: "GET",
        headers: getTestHeaders({ Cookie: commitCodeSessionCookie }),
      }
    );
    assert.equal(commitCodeAuthRes.status, 302);
    const commitCodeAuthUrl = new URL(commitCodeAuthRes.headers.get("location") || "");
    const commitAuthCode = commitCodeAuthUrl.searchParams.get("code")!;
    assert.ok(commitAuthCode);

    let commitCodeBarrierFired = false;
    setTokenBarrierHookForTesting(async (stage, userId) => {
      if (stage === "after_issuance_commit" && userId === raceCommitCodeUserId) {
        commitCodeBarrierFired = true;
        await new Promise<void>((resolve, reject) => {
          worker.once("message", (m) => {
            if (m.status === "revoked") resolve();
            else reject(new Error("Worker revocation failed: " + m.error));
          });
          worker.postMessage({ action: "revoke", userId: raceCommitCodeUserId });
        });
      }
    });

    const commitCodeExchangeRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: `grant_type=authorization_code&code=${commitAuthCode}&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&code_verifier=${commitCodeVerifier}&client_id=test-sec-client`,
    });

    assert.equal(commitCodeBarrierFired, true, "after_issuance_commit barrier must fire");
    assert.equal(commitCodeExchangeRes.status, 200, "Issuance that committed first must return 200");
    const commitTokens = await commitCodeExchangeRes.json();
    assert.ok(commitTokens.access_token);
    assert.ok(commitTokens.refresh_token);

    // Online denial verification: token issued before revocation cannot be used
    const postCommitUserInfo = await app.request("/api/auth/oauth2/userinfo", {
      method: "GET",
      headers: getTestHeaders({ Authorization: `Bearer ${commitTokens.access_token}` }),
    });
    assert.equal(postCommitUserInfo.status, 401, "Subsequent UserInfo access must be denied after revocation");

    const postCommitIntrospect = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: `token=${commitTokens.access_token}`,
    });
    assert.equal(postCommitIntrospect.status, 200);
    const postCommitIntroBody = await postCommitIntrospect.json();
    assert.equal(postCommitIntroBody.active, false, "Subsequent introspection must return active: false");

    // Attempt refresh: must be denied and prevent credential resurrection
    const postCommitRefresh = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: `grant_type=refresh_token&refresh_token=${commitTokens.refresh_token}`,
    });
    assert.equal(postCommitRefresh.status, 401, "Subsequent refresh must fail closed without resurrecting credentials");

    // 3. Refresh Token Rotation - Ordering 1: Revocation wins before issuance commits (interval after final read)
    const raceRefreshEmail = `race-ref-${crypto.randomBytes(4).toString("hex")}@platform.local`;
    const raceRefreshPassword = "Password@1234!";

    const raceRefreshSignUp = await authProvider.api.signUpEmail({
      body: { email: raceRefreshEmail, password: raceRefreshPassword, name: "Race Refresh User" },
    });
    const raceRefreshUserId = String(raceRefreshSignUp.user.id);

    await db.collection("user").updateOne(
      { email: raceRefreshEmail },
      { $set: { id: raceRefreshUserId, role: "user", tokenVersion: 1 } }
    );

    // Grant application registration and consent for private test-sec-client
    await db.collection("user_app_registrations").insertOne({
      userId: raceRefreshUserId,
      clientId: "test-sec-client",
      appRole: "member",
      status: "active",
      isActive: true,
      registeredAt: new Date(),
    });
    await db.collection("oauthConsent").insertOne({
      clientId: "test-sec-client",
      userId: raceRefreshUserId,
      scopes: ["openid", "offline_access"],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const refLoginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ email: raceRefreshEmail, password: raceRefreshPassword }),
    });
    assert.equal(refLoginRes.status, 200);
    const refSessionCookie = (refLoginRes.headers.get("set-cookie") || "").split(";")[0];

    // Authorize & exchange code to establish initial genuine token family
    const refVerifier = crypto.randomBytes(32).toString("base64url");
    const refChallenge = crypto.createHash("sha256").update(refVerifier).digest("base64url");

    const refAuthRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=test-sec-client&response_type=code&code_challenge=${refChallenge}&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&scope=openid%20offline_access&state=refstate123`,
      {
        method: "GET",
        headers: getTestHeaders({ Cookie: refSessionCookie }),
      }
    );
    assert.equal(refAuthRes.status, 302);
    const refAuthLocation = refAuthRes.headers.get("location") || "";
    const refAuthUrl = new URL(refAuthLocation);
    const initialCode = refAuthUrl.searchParams.get("code")!;

    // Perform initial exchange WITHOUT barrier to establish genuine token family
    setTokenBarrierHookForTesting(null);
    const initialExchangeRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: `grant_type=authorization_code&code=${initialCode}&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&code_verifier=${refVerifier}&client_id=test-sec-client`,
    });
    assert.equal(initialExchangeRes.status, 200, "Initial code exchange must establish genuine token family");
    const initialTokens = await initialExchangeRes.json();
    const genuineRefreshToken = initialTokens.refresh_token;
    assert.ok(genuineRefreshToken, "Must obtain genuine refresh token");

    let refreshBarrierFired = false;
    setTokenBarrierHookForTesting(async (stage, userId) => {
      if ((stage === "before_issuance_commit" || stage === "before_fence_refresh") && userId === raceRefreshUserId) {
        refreshBarrierFired = true;
        await new Promise<void>((resolve, reject) => {
          worker.once("message", (m) => {
            if (m.status === "revoked") resolve();
            else reject(new Error("Worker revocation failed: " + m.error));
          });
          worker.postMessage({ action: "revoke", userId: raceRefreshUserId });
        });
      }
    });

    const refRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: `grant_type=refresh_token&refresh_token=${genuineRefreshToken}`,
    });

    assert.equal(refreshBarrierFired, true, "Deterministic barrier must fire before refresh commit");
    assert.equal(refRes.status, 401, "Conditional state transition must reject token refresh when user revoked concurrently");
    const refBody = await refRes.json();
    assert.equal(refBody.error, "invalid_grant");
    assert.ok(refBody.error_description.includes("revoked or version transitioned"), "Error description must identify concurrent revocation");

    // Assert zero active tokens survive in database and family is marked revoked
    const survivingRefAccess = await db.collection("oauthAccessToken").countDocuments({ userId: raceRefreshUserId });
    const survivingRefTokens = await db.collection("oauthRefreshToken").countDocuments({ userId: raceRefreshUserId });
    const familyDoc = await db.collection("oauth_token_families").findOne({ userId: raceRefreshUserId });
    assert.equal(survivingRefAccess, 0, "No access token may survive atomic refresh fence purge");
    assert.equal(survivingRefTokens, 0, "No refresh token may survive atomic refresh fence purge");
    assert.equal(familyDoc?.status, "revoked", "Token family must be marked revoked");

    // 4. Refresh Token Rotation - Ordering 2: Refresh token rotation commits first, then revocation runs
    const raceCommitRefEmail = `race-commit-ref-${crypto.randomBytes(4).toString("hex")}@platform.local`;
    const raceCommitRefPassword = "Password@1234!";

    const raceCommitRefSignUp = await authProvider.api.signUpEmail({
      body: { email: raceCommitRefEmail, password: raceCommitRefPassword, name: "Race Commit Ref User" },
    });
    const raceCommitRefUserId = String(raceCommitRefSignUp.user.id);

    await db.collection("user").updateOne(
      { email: raceCommitRefEmail },
      { $set: { id: raceCommitRefUserId, role: "user", tokenVersion: 1 } }
    );

    await db.collection("user_app_registrations").insertOne({
      userId: raceCommitRefUserId,
      clientId: "test-sec-client",
      appRole: "member",
      status: "active",
      isActive: true,
      registeredAt: new Date(),
    });
    await db.collection("oauthConsent").insertOne({
      clientId: "test-sec-client",
      userId: raceCommitRefUserId,
      scopes: ["openid", "offline_access"],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const commitRefLoginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ email: raceCommitRefEmail, password: raceCommitRefPassword }),
    });
    assert.equal(commitRefLoginRes.status, 200);
    const commitRefSessionCookie = (commitRefLoginRes.headers.get("set-cookie") || "").split(";")[0];

    const commitRefVerifier = crypto.randomBytes(32).toString("base64url");
    const commitRefChallenge = crypto.createHash("sha256").update(commitRefVerifier).digest("base64url");

    const commitRefAuthRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=test-sec-client&response_type=code&code_challenge=${commitRefChallenge}&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&scope=openid%20offline_access&state=refstatecommit`,
      {
        method: "GET",
        headers: getTestHeaders({ Cookie: commitRefSessionCookie }),
      }
    );
    assert.equal(commitRefAuthRes.status, 302);
    const commitRefAuthUrl = new URL(commitRefAuthRes.headers.get("location") || "");
    const commitRefInitialCode = commitRefAuthUrl.searchParams.get("code")!;

    setTokenBarrierHookForTesting(null);
    const commitRefInitialExchange = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: `grant_type=authorization_code&code=${commitRefInitialCode}&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&code_verifier=${commitRefVerifier}&client_id=test-sec-client`,
    });
    assert.equal(commitRefInitialExchange.status, 200);
    const commitRefInitialTokens = await commitRefInitialExchange.json();
    const commitRefreshToken = commitRefInitialTokens.refresh_token;
    assert.ok(commitRefreshToken);

    let refCommitBarrierFired = false;
    setTokenBarrierHookForTesting(async (stage, userId) => {
      if (stage === "after_issuance_commit" && userId === raceCommitRefUserId) {
        refCommitBarrierFired = true;
        await new Promise<void>((resolve, reject) => {
          worker.once("message", (m) => {
            if (m.status === "revoked") resolve();
            else reject(new Error("Worker revocation failed: " + m.error));
          });
          worker.postMessage({ action: "revoke", userId: raceCommitRefUserId });
        });
      }
    });

    const commitRefRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: `grant_type=refresh_token&refresh_token=${commitRefreshToken}`,
    });

    assert.equal(refCommitBarrierFired, true, "after_issuance_commit barrier must fire for refresh");
    assert.equal(commitRefRes.status, 200, "Refresh rotation that committed first must return 200");
    const rotatedCommitTokens = await commitRefRes.json();
    assert.ok(rotatedCommitTokens.access_token);
    assert.ok(rotatedCommitTokens.refresh_token);

    // Online denial verification: rotated tokens cannot be used after subsequent revocation
    const postRotUserInfo = await app.request("/api/auth/oauth2/userinfo", {
      method: "GET",
      headers: getTestHeaders({ Authorization: `Bearer ${rotatedCommitTokens.access_token}` }),
    });
    assert.equal(postRotUserInfo.status, 401, "Rotated access token must be denied after revocation");

    const postRotIntrospect = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: `token=${rotatedCommitTokens.access_token}`,
    });
    assert.equal(postRotIntrospect.status, 200);
    const postRotIntroBody = await postRotIntrospect.json();
    assert.equal(postRotIntroBody.active, false, "Rotated token introspection must return active: false");

    const postRotRefresh = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      }),
      body: `grant_type=refresh_token&refresh_token=${rotatedCommitTokens.refresh_token}`,
    });
    assert.equal(postRotRefresh.status, 401, "Rotated refresh token must fail closed without resurrecting credentials");
  } finally {
    setTokenBarrierHookForTesting(null);
    await new Promise<void>((resolve) => {
      worker.once("message", () => resolve());
      worker.postMessage({ action: "close" });
    });
    await worker.terminate();
  }
});

await runTest("SEC-04-D: Better Auth admin/plugin routes enforce mandatory MFA and sensitive-action freshness with genuine enrollment and challenges", async () => {
  const { authProvider } = await import("../../src/utils/auth");
  const adminEmail = `super-mfa-${crypto.randomBytes(4).toString("hex")}@platform.local`;
  const adminPassword = "Password@1234!";

  // 1. Initial user sign up
  await authProvider.api.signUpEmail({
    body: { email: adminEmail, password: adminPassword, name: "Super MFA Admin" },
  });

  // 2. Initial password sign in
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ "content-type": "application/json" }),
    body: JSON.stringify({ email: adminEmail, password: adminPassword }),
  });
  assert.equal(loginRes.status, 200, "Admin login must succeed");
  const initialSessionCookie = loginRes.headers.get("set-cookie") || "";
  assert.ok(initialSessionCookie.includes("better-auth.session_token="), "Must set session cookie");

  // Upgrade user in DB to super-admin (unenrolled: twoFactorEnabled is false or missing)
  await db.collection("user").updateOne(
    { email: adminEmail },
    { $set: { role: "super-admin" } }
  );

  // 3. Unenrolled admin cannot access privileged admin routes (setup-only authority)
  const unenrolledHeaders = getTestHeaders({ Cookie: initialSessionCookie });
  const unenrolledClientsRes = await app.request("/api/admin/clients", {
    method: "GET",
    headers: unenrolledHeaders,
  });
  assert.equal(unenrolledClientsRes.status, 403, "Unenrolled super-admin must be blocked from clients endpoint");
  const unenrolledClientsBody = await unenrolledClientsRes.json();
  assert.equal(unenrolledClientsBody.code, "ERR_MFA_ENROLLMENT_REQUIRED");

  const unenrolledUsersRes = await app.request("/api/auth/admin/list-users", {
    method: "GET",
    headers: unenrolledHeaders,
  });
  assert.equal(unenrolledUsersRes.status, 403, "Unenrolled super-admin must be blocked from Better Auth admin list-users");
  const unenrolledUsersBody = await unenrolledUsersRes.json();
  assert.equal(unenrolledUsersBody.code, "ERR_MFA_ENROLLMENT_REQUIRED");

  // 4. Real 2FA Enrollment: call POST /api/auth/two-factor/enable
  const enableRes = await app.request("/api/auth/two-factor/enable", {
    method: "POST",
    headers: unenrolledHeaders,
    body: JSON.stringify({ password: adminPassword }),
  });
  assert.equal(enableRes.status, 200, "2FA enable must succeed");
  const enableData = await enableRes.json();
  assert.ok(enableData.totpURI, "Must return totpURI");
  assert.ok(Array.isArray(enableData.backupCodes) && enableData.backupCodes.length > 0, "Must return backupCodes");

  const totpSecretParam = new URL(enableData.totpURI).searchParams.get("secret");
  assert.ok(totpSecretParam, "TOTP URI must contain secret");
  const { base32 } = await import("@better-auth/utils/base32");
  const decodedSecret = Buffer.from(base32.decode(totpSecretParam)).toString();

  // Compute RFC 6238 TOTP and finalize enrollment via POST /api/auth/two-factor/verify-totp
  const enrollOtp = await createOTP(decodedSecret, { digits: 6, period: 30 }).totp();
  const verifyEnrollRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: unenrolledHeaders,
    body: JSON.stringify({ code: enrollOtp }),
  });
  assert.equal(verifyEnrollRes.status, 200, "Verify TOTP enrollment must succeed");
  const verifyEnrollData = await verifyEnrollRes.json();
  assert.ok(verifyEnrollData.user || verifyEnrollData.token, "Enrollment must be confirmed");

  // Verify DB reflects twoFactorEnabled: true
  const enrolledUserDoc = await db.collection("user").findOne({ email: adminEmail });
  assert.equal(enrolledUserDoc?.twoFactorEnabled, true, "User must have twoFactorEnabled: true in DB");

  // 5. Subsequent sign-in returns 2FA challenge (twoFactorRedirect: true) and challenge cookie
  const challengeLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ "content-type": "application/json" }),
    body: JSON.stringify({ email: adminEmail, password: adminPassword }),
  });
  assert.equal(challengeLoginRes.status, 200, "Login with 2FA enabled returns 200");
  const challengeBody = await challengeLoginRes.json();
  assert.equal(challengeBody.twoFactorRedirect, true, "Must require 2FA redirect");

  const challengeCookieHeader = challengeLoginRes.headers.get("set-cookie") || "";
  assert.ok(challengeCookieHeader.includes("better-auth.two_factor="), "Must set two_factor challenge cookie");
  const hasActiveSession = challengeCookieHeader.split(",").some((part: string) => {
    const trimmed = part.trim();
    if (!trimmed.startsWith("better-auth.session_token=")) return false;
    const val = trimmed.split(";")[0].split("=")[1];
    return Boolean(val && !trimmed.includes("Max-Age=0") && !trimmed.includes("Thu, 01 Jan 1970"));
  });
  assert.equal(hasActiveSession, false, "Must NOT set active session_token cookie on password-only stage");

  const challengeCookie = extractCookie(challengeCookieHeader, "better-auth.two_factor");

  // 6. Password-only stage rejection: challenge cookie alone cannot access admin endpoints
  const pwOnlyHeaders = getTestHeaders({ Cookie: challengeCookie });
  const pwOnlyRes = await app.request("/api/auth/admin/list-users", {
    method: "GET",
    headers: pwOnlyHeaders,
  });
  assert.ok(pwOnlyRes.status === 401 || pwOnlyRes.status === 403, "Password-only stage must be rejected");
  if (pwOnlyRes.status === 403) {
    const pwOnlyBody = await pwOnlyRes.json();
    assert.equal(pwOnlyBody.code, "ERR_MFA_REQUIRED");
  }

  // 7. Complete genuine TOTP challenge via POST /api/auth/two-factor/verify-totp
  const challengeOtp = await createOTP(decodedSecret, { digits: 6, period: 30 }).totp();
  const verifyTotpRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: challengeCookie }),
    body: JSON.stringify({ code: challengeOtp }),
  });
  assert.equal(verifyTotpRes.status, 200, "TOTP challenge verification must succeed");
  const verifiedCookieHeader = verifyTotpRes.headers.get("set-cookie") || "";
  assert.ok(verifiedCookieHeader.includes("better-auth.session_token="), "Must issue session_token cookie upon successful TOTP verification");

  const verifiedSessionCookie = extractCookie(verifiedCookieHeader, "better-auth.session_token");
  const verifiedHeaders = getTestHeaders({ Cookie: verifiedSessionCookie });

  // 8. Genuine completed MFA session allows privileged admin access (Strictly 200, NEVER 404)
  const adminClientsRes = await app.request("/api/admin/clients", {
    method: "GET",
    headers: verifiedHeaders,
  });
  assert.equal(adminClientsRes.status, 200, "Completed MFA session must access admin clients with HTTP 200");

  const adminUsersRes = await app.request("/api/auth/admin/list-users", {
    method: "GET",
    headers: verifiedHeaders,
  });
  assert.equal(adminUsersRes.status, 200, "Completed MFA session must access Better Auth admin list-users with HTTP 200");
  const adminUsersData = await adminUsersRes.json();
  assert.ok(Array.isArray(adminUsersData.users), "Must return users array with privacy projection");

  // 9. Stale MFA session (> 15 minutes old) is rejected with ERR_MFA_STEP_UP_REQUIRED on mutations
  const rawCookie = (verifiedSessionCookie.split("better-auth.session_token=")[1] || "").split(";")[0];
  const tokenVal = decodeURIComponent(rawCookie.split(".")[0]);
  const staleDate = new Date(Date.now() - 25 * 60 * 1000);
  await db.collection("session").updateMany(
    {
      $or: [
        { token: rawCookie },
        { token: tokenVal },
        { token: decodeURIComponent(rawCookie) },
        { userId: enrolledUserDoc?.id },
      ],
    },
    {
      $set: {
        mfaVerifiedAt: staleDate,
        createdAt: staleDate,
      },
    }
  );

  const staleMutationRes = await app.request("/api/auth/admin/set-role", {
    method: "POST",
    headers: verifiedHeaders,
    body: JSON.stringify({ userId: "target-user", role: "admin" }),
  });
  assert.equal(staleMutationRes.status, 403, "Stale MFA session must be rejected with step-up required");
  const staleBody = await staleMutationRes.json();
  assert.equal(staleBody.code, "ERR_MFA_STEP_UP_REQUIRED");

  // 10. Recovery backup code challenge verification & single-use enforcement
  const recoveryLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ "content-type": "application/json" }),
    body: JSON.stringify({ email: adminEmail, password: adminPassword }),
  });
  assert.equal(recoveryLoginRes.status, 200);
  const recoveryChallengeCookie = extractCookie(recoveryLoginRes.headers.get("set-cookie"), "better-auth.two_factor");

  const backupCodeToUse = enableData.backupCodes[0];
  const verifyBackupRes = await app.request("/api/auth/two-factor/verify-backup-code", {
    method: "POST",
    headers: getTestHeaders({ Cookie: recoveryChallengeCookie }),
    body: JSON.stringify({ code: backupCodeToUse }),
  });
  assert.equal(verifyBackupRes.status, 200, "Recovery code verification must succeed");
  const recoverySessionCookie = extractCookie(verifyBackupRes.headers.get("set-cookie"), "better-auth.session_token");
  assert.ok(recoverySessionCookie, "Must issue session cookie after recovery verification");

  const recoveryClientsRes = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: recoverySessionCookie }),
  });
  assert.equal(recoveryClientsRes.status, 200, "Session from recovery code must access admin clients with HTTP 200");

  // Single-use enforcement: Attempting to reuse the exact same backup code must be rejected
  const replayLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ "content-type": "application/json" }),
    body: JSON.stringify({ email: adminEmail, password: adminPassword }),
  });
  const replayChallengeCookie = extractCookie(replayLoginRes.headers.get("set-cookie"), "better-auth.two_factor");

  const replayBackupRes = await app.request("/api/auth/two-factor/verify-backup-code", {
    method: "POST",
    headers: getTestHeaders({ Cookie: replayChallengeCookie }),
    body: JSON.stringify({ code: backupCodeToUse }),
  });
  assert.ok(replayBackupRes.status >= 400, "Reused recovery code must be rejected");
});

await runTest("SEC-03-C: Email verification delivery transport validation, typed config, timeout, non-2xx, and secret-free logging", async () => {
  const { authProvider } = await import("../../src/utils/auth");
  const sendVerificationEmail = (authProvider.options as any).emailVerification?.sendVerificationEmail;
  assert.ok(typeof sendVerificationEmail === "function", "sendVerificationEmail must be configured");

  // Capture console logs to prove zero secrets are leaked
  const capturedLogs: string[] = [];
  const origWarn = console.warn;
  const origError = console.error;
  const origLog = console.log;
  console.warn = (...args: any[]) => capturedLogs.push(args.map(String).join(" "));
  console.error = (...args: any[]) => capturedLogs.push(args.map(String).join(" "));
  console.log = (...args: any[]) => capturedLogs.push(args.map(String).join(" "));

  const secretToken = "super-secret-verification-token-xyz789";
  const secretUrl = `https://oauth21.vercel.app/api/auth/verify-email?token=${secretToken}`;

  const origEnv = process.env.NODE_ENV;
  const origWebhook = process.env.EMAIL_DELIVERY_WEBHOOK_URL;
  const origEnforce = process.env.AUTH_EMAIL_VERIFICATION_ENABLED;

  try {
    // 1. Verification enabled but EMAIL_DELIVERY_WEBHOOK_URL is missing: throws explicit error
    process.env.AUTH_EMAIL_VERIFICATION_ENABLED = "true";
    delete process.env.EMAIL_DELIVERY_WEBHOOK_URL;

    await assert.rejects(
      async () => {
        await sendVerificationEmail({
          user: { email: "test-delivery@example.com" },
          url: secretUrl,
          token: secretToken,
        });
      },
      /Email verification is enabled but EMAIL_DELIVERY_WEBHOOK_URL is not configured/,
      "Missing webhook when verification enabled must fail explicitly"
    );

    // 2. Invalid webhook URL configuration: throws controlled error
    process.env.EMAIL_DELIVERY_WEBHOOK_URL = "not-a-valid-url";
    await assert.rejects(
      async () => {
        await sendVerificationEmail({
          user: { email: "test-delivery@example.com" },
          url: secretUrl,
          token: secretToken,
        });
      },
      /Invalid email delivery webhook transport configuration/,
      "Invalid transport URL must throw controlled error"
    );

    // 3. Production transport: non-HTTPS URL must be rejected
    process.env.NODE_ENV = "production";
    process.env.EMAIL_DELIVERY_WEBHOOK_URL = "http://email.corp.internal/webhook";
    await assert.rejects(
      async () => {
        await sendVerificationEmail({
          user: { email: "test-delivery@example.com" },
          url: secretUrl,
          token: secretToken,
        });
      },
      /EMAIL_DELIVERY_WEBHOOK_URL must use HTTPS in production/,
      "Non-HTTPS transport in production must be rejected"
    );

    // 4. Production transport: loopback address must be rejected
    process.env.EMAIL_DELIVERY_WEBHOOK_URL = "https://127.0.0.1:8443/webhook";
    await assert.rejects(
      async () => {
        await sendVerificationEmail({
          user: { email: "test-delivery@example.com" },
          url: secretUrl,
          token: secretToken,
        });
      },
      /EMAIL_DELIVERY_WEBHOOK_URL cannot be a loopback address in production/,
      "Loopback address in production must be rejected"
    );

    process.env.NODE_ENV = "test";

    // 5. Non-2xx response from delivery endpoint: throws controlled HTTP error without leaking secrets
    const errorServer = http.createServer((req, res) => {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal Gateway Error" }));
    });
    await new Promise<void>((resolve) => errorServer.listen(0, resolve));
    const errorPort = (errorServer.address() as any).port;
    process.env.EMAIL_DELIVERY_WEBHOOK_URL = `http://127.0.0.1:${errorPort}/webhook`;

    await assert.rejects(
      async () => {
        await sendVerificationEmail({
          user: { email: "test-delivery@example.com" },
          url: secretUrl,
          token: secretToken,
        });
      },
      /Email delivery webhook failed with HTTP 500/,
      "Non-2xx response must throw controlled error"
    );
    errorServer.close();

    // 6. Delivery endpoint timeout (>5000ms): throws controlled timeout error without leaking secrets
    const timeoutServer = http.createServer((_req, _res) => {
      // Deliberately hold request open to trigger client timeout
    });
    await new Promise<void>((resolve) => timeoutServer.listen(0, resolve));
    const timeoutPort = (timeoutServer.address() as any).port;
    process.env.EMAIL_DELIVERY_WEBHOOK_URL = `http://127.0.0.1:${timeoutPort}/webhook`;

    await assert.rejects(
      async () => {
        await sendVerificationEmail({
          user: { email: "test-delivery@example.com" },
          url: secretUrl,
          token: secretToken,
        });
      },
      /Email delivery timed out/,
      "Webhook timeout after 5000ms must throw controlled error"
    );
    timeoutServer.close();

    // Verify ZERO secrets or tokens leaked across all test cases
    for (const log of capturedLogs) {
      assert.ok(!log.includes(secretToken), `Verification token leaked in logs: ${log}`);
      assert.ok(!log.includes(secretUrl), `Verification URL leaked in logs: ${log}`);
    }
  } finally {
    console.warn = origWarn;
    console.error = origError;
    console.log = origLog;
    if (origEnv) process.env.NODE_ENV = origEnv;
    if (origWebhook) process.env.EMAIL_DELIVERY_WEBHOOK_URL = origWebhook;
    else delete process.env.EMAIL_DELIVERY_WEBHOOK_URL;
    if (origEnforce) process.env.AUTH_EMAIL_VERIFICATION_ENABLED = origEnforce;
    else delete process.env.AUTH_EMAIL_VERIFICATION_ENABLED;
  }
});

await runTest("SEC-05-D: Admin privacy projections: app-admin listings and email-shaped name fields", async () => {
  const { toApprovedDisplayLabel, isEmailShaped } = await import("../../src/utils/security");

  // 1. Verify isEmailShaped helper
  assert.equal(isEmailShaped("user@example.com"), true);
  assert.equal(isEmailShaped("john.doe@sub.corp.internal"), true);
  assert.equal(isEmailShaped("John Doe"), false);
  assert.equal(isEmailShaped("User"), false);
  assert.equal(isEmailShaped(null), false);

  // 2. Verify toApprovedDisplayLabel masks email-shaped name
  assert.equal(toApprovedDisplayLabel("user@example.com", "user@example.com"), "us***@example.com");
  assert.equal(toApprovedDisplayLabel(null, "leaked.name@example.com"), "le***@example.com");
  assert.equal(toApprovedDisplayLabel("user@example.com", "Alice Smith"), "Alice Smith");

  // 3. Verify app-admin listing privacy projection in real route
  const appAdminEmail = "scoped-admin@specialist.internal";
  await db.collection("app_admins").insertOne({
    clientId: "test-sec-client",
    email: appAdminEmail,
    name: appAdminEmail, // Email-shaped name field
    redirectUrl: "https://example.com/admin",
    isActive: true,
    totpEnabled: true,
    loginCount: 3,
    createdAt: new Date(),
  });

  // Call GET /api/admin/clients/test-sec-client/app-admins with platform admin token
  const testSuperAdminId = "test-super-admin-" + crypto.randomBytes(4).toString("hex");
  await db.collection("user").insertOne({
    id: testSuperAdminId,
    email: "super-admin-projection@example.com",
    role: "super-admin",
    scopedClientId: null,
    twoFactorEnabled: true,
    emailVerified: true,
    createdAt: new Date(),
  });

  const platformAdminJwt = await mintAdminBearerToken({
    sub: testSuperAdminId,
    role: "super-admin",
    mfa: true,
    amr: ["mfa"],
    mfaVerifiedAtSec: Math.floor(Date.now() / 1000),
  });

  const res = await app.request("/api/admin/clients/test-sec-client/app-admins", {
    method: "GET",
    headers: getTestHeaders({
      Authorization: `Bearer ${platformAdminJwt}`,
    }),
  });

  assert.equal(res.status, 200, "App admin listing must return 200");
  const data = await res.json();
  assert.ok(Array.isArray(data.admins), "Must return admins array");
  const foundAdmin = data.admins.find((a: any) => a.redirectUrl === "https://example.com/admin");
  assert.ok(foundAdmin, "Created app admin must be in listing");

  // Full cleartext email MUST NOT appear in email, name, or displayLabel
  assert.ok(!foundAdmin.email.includes("scoped-admin@specialist.internal"), `App admin email must be masked: ${foundAdmin.email}`);
  assert.ok(!foundAdmin.name.includes("scoped-admin@specialist.internal"), `App admin name must be masked: ${foundAdmin.name}`);
  assert.ok(foundAdmin.displayLabel, "displayLabel must be present");
  assert.ok(!foundAdmin.displayLabel.includes("scoped-admin@specialist.internal"), `App admin displayLabel must be masked: ${foundAdmin.displayLabel}`);
});

// ==============================================================================
// Slice 7: Revocation Authorization, Monotonicity & Client Scoping
// ==============================================================================

console.log("Running Slice 7: Revocation Authorization, Monotonicity & Client Scoping...\n");

await runTest("SEC-07-A: Provider authentication failure on /oauth2/revoke causes zero revocation mutations", async () => {
  const victimUserId = "victim-user-07-a";
  const famId = "fam-sec-07-a";
  const victimToken = "rt-sec-07-a-secret-value";

  await db.collection("oauth_token_families").insertOne({
    familyId: famId,
    clientId: "test-sec-client",
    userId: victimUserId,
    status: "active",
    createdAt: new Date(),
  });
  await db.collection("oauthRefreshToken").insertOne({
    token: victimToken,
    clientId: "test-sec-client",
    userId: victimUserId,
    familyId: famId,
    expiresAt: new Date(Date.now() + 86400000),
  });

  // Call /oauth2/revoke with invalid Basic auth credentials
  const badAuth = Buffer.from("test-sec-client:wrong-password").toString("base64");
  const revokeRes = await app.request("/api/auth/oauth2/revoke", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${badAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: `token=${encodeURIComponent(victimToken)}&token_type_hint=refresh_token`,
  });

  assert.equal(revokeRes.status, 401, "Invalid client credentials must be rejected with 401");

  // Verify zero mutations: family remains active, token still exists
  const familyAfter = await db.collection("oauth_token_families").findOne({ familyId: famId });
  assert.equal(familyAfter?.status, "active", "Token family must remain active after failed client auth");

  const tokenAfter = await db.collection("oauthRefreshToken").findOne({ token: victimToken });
  assert.ok(tokenAfter, "Refresh token document must not be deleted after failed client auth");
});

await runTest("SEC-07-B: Cross-client token substitution causes zero mutations on victim client family", async () => {
  // Setup Client B
  const clientBSecret = "client-b-secret-12345";
  const hashedClientBSecret = crypto.createHash("sha256").update(clientBSecret).digest("base64url");
  const clientB = {
    id: "test-sec-client-b",
    clientId: "test-sec-client-b",
    clientSecret: hashedClientBSecret,
    redirectUris: ["http://localhost:5174/callback-b"],
    allowedOrigins: ["http://localhost:5174"],
    isPublic: false,
    isDev: true,
    skipConsent: true,
    tokenEndpointAuthMethod: "client_secret_basic",
    createdAt: new Date(),
  };
  await db.collection("oauthClient").updateOne(
    { clientId: "test-sec-client-b" },
    { $set: clientB },
    { upsert: true }
  );
  const basicAuthB = Buffer.from(`test-sec-client-b:${clientBSecret}`).toString("base64");

  // Create victim token owned by Client A
  const victimUserId = "victim-user-07-b";
  const famIdA = "fam-sec-07-b-client-a";
  const tokenA = "rt-sec-07-b-client-a-token";

  await db.collection("oauth_token_families").insertOne({
    familyId: famIdA,
    clientId: "test-sec-client",
    userId: victimUserId,
    status: "active",
    createdAt: new Date(),
  });
  await db.collection("oauthRefreshToken").insertOne({
    token: tokenA,
    clientId: "test-sec-client",
    userId: victimUserId,
    familyId: famIdA,
    expiresAt: new Date(Date.now() + 86400000),
  });

  // Client B attempts to revoke Client A's token
  const attackRes = await app.request("/api/auth/oauth2/revoke", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicAuthB}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: `token=${encodeURIComponent(tokenA)}&token_type_hint=refresh_token`,
  });

  // Per RFC 7009, server returns 200 OK so attacker cannot probe token existence
  assert.equal(attackRes.status, 200, "Revoke endpoint must return 200 per RFC 7009");

  // Verify zero mutations on Client A's token family and records
  const famDoc = await db.collection("oauth_token_families").findOne({ familyId: famIdA });
  assert.equal(famDoc?.status, "active", "Victim token family status must remain active");

  const tokenDoc = await db.collection("oauthRefreshToken").findOne({ token: tokenA });
  assert.ok(tokenDoc, "Victim token document must not be deleted by cross-client request");
});

await runTest("SEC-07-C: Unrelated-client session preservation: revoking Client A does not sign out Client B or IdP session cookie", async () => {
  const multiEmail = `multi_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const multiPass = "MultiPass@1234!";
  const signUpRes = await authProvider.api.signUpEmail({
    body: { email: multiEmail, password: multiPass, name: "Multi Client User" },
    asResponse: true,
  });
  const sessionCookie = (signUpRes.headers.get("set-cookie") || "").split(";")[0];
  const multiUserDoc = await db.collection("user").findOne({ email: multiEmail });
  const multiUserId = String(multiUserDoc?.id || multiUserDoc?._id);

  await db.collection("user").updateOne(
    { _id: multiUserDoc._id },
    { $set: { tokenVersion: 2, tokensRevokedBefore: new Date(Date.now() - 60000) } }
  );

  // Client A and Client B tokens
  const tokenA = "at-client-a-token-07-c";
  const tokenB = "at-client-b-token-07-c";
  const famA = "fam-07-c-a";
  const famB = "fam-07-c-b";

  await db.collection("oauth_token_families").insertMany([
    { familyId: famA, clientId: "test-sec-client", userId: multiUserId, status: "active", createdAt: new Date() },
    { familyId: famB, clientId: "test-sec-client-b", userId: multiUserId, status: "active", createdAt: new Date() },
  ]);
  await db.collection("oauthAccessToken").insertMany([
    { token: tokenA, clientId: "test-sec-client", userId: multiUserId, expiresAt: new Date(Date.now() + 3600000) },
    { token: tokenB, clientId: "test-sec-client-b", userId: multiUserId, expiresAt: new Date(Date.now() + 3600000) },
  ]);

  // Client A revokes Client A's token
  const revokeRes = await app.request("/api/auth/oauth2/revoke", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: `token=${encodeURIComponent(tokenA)}&token_type_hint=access_token`,
  });
  assert.equal(revokeRes.status, 200, "Client A token revocation must return 200");

  // Client A's token is deleted
  const tokenADoc = await db.collection("oauthAccessToken").findOne({ token: tokenA });
  assert.equal(tokenADoc, null, "Targeted Client A token must be deleted");

  // Client B's family and token MUST remain active and untampered
  const famBDoc = await db.collection("oauth_token_families").findOne({ familyId: famB });
  assert.equal(famBDoc?.status, "active", "Client B token family must remain active");

  const tokenBDoc = await db.collection("oauthAccessToken").findOne({ token: tokenB });
  assert.ok(tokenBDoc, "Client B token must not be deleted");

  // User's tokenVersion MUST NOT be bumped for ordinary single-token revocation
  const userDoc = await db.collection("user").findOne({ email: multiEmail });
  assert.equal(userDoc?.tokenVersion, 2, "User tokenVersion must remain 2 (not account-wide signout)");

  // IdP session cookie MUST remain valid
  const sessionCheck = await app.request("/api/auth/get-session", {
    method: "GET",
    headers: getTestHeaders({
      Cookie: sessionCookie,
    }),
  });
  assert.equal(sessionCheck.status, 200, "IdP session must remain valid after single-client revocation");
  const sessionData = await sessionCheck.json();
  assert.ok(sessionData?.session, "Session data must be returned");
});

await runTest("SEC-07-D: Overlapping revokers with delayed writes against real storage verify monotonic advancement and non-decreasing timestamps", async () => {
  const raceUserId = "user-race-atomic-07-d";
  const initialTime = new Date(Date.now() - 50000);
  await db.collection("user").insertOne({
    id: raceUserId,
    email: "race-atomic@example.com",
    role: "user",
    tokensRevokedBefore: initialTime,
    emailVerified: true,
    createdAt: new Date(),
  });

  // 1. Run 5 concurrent overlapping calls to revokeUserTokensDurable
  const concurrentCalls = Array.from({ length: 5 }, () =>
    revokeUserTokensDurable(db, raceUserId)
  );
  const versions = await Promise.all(concurrentCalls);

  assert.equal(versions.length, 5);
  for (const v of versions) {
    assert.ok(typeof v === "number" && v >= 2, `Version must be at least 2: ${v}`);
  }

  // Final document must have advanced by exactly 5 (legacy 1 + 5 = 6)
  const userAfter = await db.collection("user").findOne({ id: raceUserId });
  assert.equal(userAfter?.tokenVersion, 6, "Legacy account must monotonically advance to 6 with 5 revokers");
  assert.ok(
    new Date(userAfter.tokensRevokedBefore).getTime() >= initialTime.getTime(),
    "Revocation timestamp must not decrease"
  );

  // 2. Call with an older timestamp: tokensRevokedBefore must NEVER decrease
  const olderTime = new Date(Date.now() - 1000000);
  const finalVer = await revokeUserTokensDurable(db, raceUserId, olderTime);
  assert.equal(finalVer, 7, "Version must advance to 7");

  const userFinal = await db.collection("user").findOne({ id: raceUserId });
  assert.equal(userFinal?.tokenVersion, 7);
  assert.ok(
    new Date(userFinal.tokensRevokedBefore).getTime() >= initialTime.getTime(),
    "Older timestamp must not regress tokensRevokedBefore"
  );
});

await runTest("SEC-07-E: Concurrent revocation plus issuance: conditional state transition coordinates with revocation", async () => {
  const coordUserId = "user-coord-07-e";
  await db.collection("user").insertOne({
    id: coordUserId,
    email: "coord-issuance@example.com",
    role: "user",
    tokenVersion: 3,
    emailVerified: true,
    createdAt: new Date(),
  });

  // Ordering 1: Revocation advances tokenVersion before issuance final conditional commit
  // Mint token before revocation: bound to tokenVersion 3
  const tokenPreRevoke = await mintJwtAccessToken({
    userId: coordUserId,
    clientId: "test-sec-client",
    scope: "openid profile",
  });
  assert.ok(tokenPreRevoke, "Initial minting must succeed");

  // Revoke user tokens: advances tokenVersion to 4
  const vAfterRevoke = await revokeUserTokensDurable(db, coordUserId);
  assert.equal(vAfterRevoke, 4, "Revocation must advance version to 4");

  // Verify online validation of pre-revoke token (version 3) is denied against user at version 4
  const userinfoRes = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: getTestHeaders({
      Authorization: `Bearer ${tokenPreRevoke}`,
    }),
  });
  assert.equal(userinfoRes.status, 401, "Token with older tokenVersion must be denied at online validation (401)");

  // Ordering 2: Issuance after revocation commits with the new version (version 4)
  const tokenPostRevoke = await mintJwtAccessToken({
    userId: coordUserId,
    clientId: "test-sec-client",
    scope: "openid profile",
  });
  assert.ok(tokenPostRevoke, "Post-revocation minting must succeed with new version");

  const userinfoRes2 = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: getTestHeaders({
      Authorization: `Bearer ${tokenPostRevoke}`,
    }),
  });
  assert.equal(userinfoRes2.status, 200, "Token with matching current tokenVersion must succeed (200)");
});

await runTest("SEC-07-F: Protocol regression: two independent token families for SAME user and SAME client", async () => {
  const userEmail = `multi_fam_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const userPass = "MultiFamPass123!Aa";
  const signUpRes = await authProvider.api.signUpEmail({
    body: { email: userEmail, password: userPass, name: "Multi Fam User" },
    asResponse: true,
  });
  const sessionCookie = (signUpRes.headers.get("set-cookie") || "").split(";")[0];
  const userDoc = await db.collection("user").findOne({ email: userEmail });
  const userId = String(userDoc?.id || userDoc?._id);

  // Register user for private application
  await db.collection("user_app_registrations").insertOne({
    userId: userId,
    clientId: "test-sec-client",
    appRole: "member",
    status: "active",
    isActive: true,
    registeredAt: new Date(),
  });

  // Verify IdP session is valid initially
  const preCheckSession = await app.request("/api/auth/get-session", {
    method: "GET",
    headers: getTestHeaders({ Cookie: sessionCookie }),
  });
  assert.equal(preCheckSession.status, 200, "IdP session must be active initially");

  // Create Family A genuinely via authorization_code flow
  const verifierA = crypto.randomBytes(32).toString("base64url");
  const challengeA = crypto.createHash("sha256").update(verifierA).digest("base64url");
  const authResA = await app.request(
    `/api/auth/oauth2/authorize?client_id=test-sec-client&response_type=code&code_challenge=${challengeA}&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&scope=openid%20offline_access&state=state_fam_a`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: sessionCookie }),
    }
  );
  assert.equal(authResA.status, 302);
  const codeA = new URL(authResA.headers.get("location") || "").searchParams.get("code")!;
  assert.ok(codeA, "Auth code A must be issued");

  const tokenResA = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    }),
    body: `grant_type=authorization_code&code=${codeA}&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&code_verifier=${verifierA}&client_id=test-sec-client`,
  });
  assert.equal(tokenResA.status, 200);
  const tokensA = await tokenResA.json();
  const atA = tokensA.access_token;
  const rtA = tokensA.refresh_token;
  assert.ok(atA && rtA, "Tokens A must be returned");

  // Create Family B genuinely via authorization_code flow for SAME user and SAME client
  const verifierB = crypto.randomBytes(32).toString("base64url");
  const challengeB = crypto.createHash("sha256").update(verifierB).digest("base64url");
  const authResB = await app.request(
    `/api/auth/oauth2/authorize?client_id=test-sec-client&response_type=code&code_challenge=${challengeB}&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&scope=openid%20offline_access&state=state_fam_b`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: sessionCookie }),
    }
  );
  assert.equal(authResB.status, 302);
  const codeB = new URL(authResB.headers.get("location") || "").searchParams.get("code")!;
  assert.ok(codeB, "Auth code B must be issued");

  const tokenResB = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    }),
    body: `grant_type=authorization_code&code=${codeB}&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback&code_verifier=${verifierB}&client_id=test-sec-client`,
  });
  assert.equal(tokenResB.status, 200);
  const tokensB = await tokenResB.json();
  const atB = tokensB.access_token;
  const rtB = tokensB.refresh_token;
  assert.ok(atB && rtB, "Tokens B must be returned");

  // Both families are initially valid
  const preUserInfoA = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${atA}` }),
  });
  assert.equal(preUserInfoA.status, 200, "Token A must succeed at UserInfo initially");

  const preUserInfoB = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${atB}` }),
  });
  assert.equal(preUserInfoB.status, 200, "Token B must succeed at UserInfo initially");

  // Step 1: Revoke Family A
  const revokeRes = await app.request("/api/auth/oauth2/revoke", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: `token=${encodeURIComponent(rtA)}&token_type_hint=refresh_token`,
  });
  assert.equal(revokeRes.status, 200, "Family A revocation must return 200");

  // Step 2: A's credentials are rejected
  // A's refresh token is rejected on /oauth2/token
  const refreshARes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(rtA)}`,
  });
  assert.equal(refreshARes.status, 401, "Revoked Family A refresh token must be rejected with 401");

  // A's access token is rejected on /oauth2/userinfo
  const userInfoARes = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${atA}` }),
  });
  assert.equal(userInfoARes.status, 401, "Revoked Family A access token must be rejected at UserInfo (401)");

  // A's access token is rejected on /oauth2/introspect
  const introspectARes = await app.request("/api/auth/oauth2/introspect", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: `token=${encodeURIComponent(atA)}`,
  });
  assert.equal(introspectARes.status, 200);
  const introBodyA = await introspectARes.json();
  assert.equal(introBodyA.active, false, "Revoked Family A access token must introspect as active: false");

  // Step 3: B's access and refresh remain usable
  // B's access token succeeds on /oauth2/userinfo
  const userInfoBRes = await app.request("/api/auth/oauth2/userinfo", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${atB}` }),
  });
  assert.equal(userInfoBRes.status, 200, "Unrevoked Family B access token must succeed at UserInfo (200)");

  // B's access token succeeds on /oauth2/introspect
  const introspectBRes = await app.request("/api/auth/oauth2/introspect", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: `token=${encodeURIComponent(atB)}`,
  });
  assert.equal(introspectBRes.status, 200);
  const introBodyB = await introspectBRes.json();
  assert.equal(introBodyB.active, true, "Unrevoked Family B access token must introspect as active: true");

  // B's refresh token succeeds on /oauth2/token
  const refreshBRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(rtB)}`,
  });
  assert.equal(refreshBRes.status, 200, "Unrevoked Family B refresh token must succeed (200)");
  const rotatedTokensB = await refreshBRes.json();
  assert.ok(rotatedTokensB.access_token, "Rotated token B must contain access_token");
  assert.ok(rotatedTokensB.refresh_token, "Rotated token B must contain refresh_token");

  // Step 4: The IdP session remains valid
  const postCheckSession = await app.request("/api/auth/get-session", {
    method: "GET",
    headers: getTestHeaders({ Cookie: sessionCookie }),
  });
  assert.equal(postCheckSession.status, 200, "IdP session must remain valid after Family A revocation");
  const sessionData = await postCheckSession.json();
  assert.equal(sessionData?.user?.id, userId, "Session must match the original user");
});

await closeDb();
await suite.cleanup();

console.log(`\n================================================================`);
console.log(`  OAUTH SECURITY HARDENING TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log(`================================================================\n`);
if (failed > 0) process.exit(1);
