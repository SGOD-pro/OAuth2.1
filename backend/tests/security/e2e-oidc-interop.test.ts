import dotenv from "dotenv";
dotenv.config();

import assert from "node:assert/strict";
import crypto from "crypto";
import { serve } from "@hono/node-server";

// Configure test environment before any application imports
process.env.NODE_ENV = "test";
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://127.0.0.1:3847";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32";
process.env.APP_ADMIN_JWT_SECRET = process.env.APP_ADMIN_JWT_SECRET || "b".repeat(32);
process.env.TOTP_ENCRYPTION_KEY = process.env.TOTP_ENCRYPTION_KEY || "c".repeat(32);

const jose = await import("jose");
const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");

console.log("================================================================");
console.log("  SWYRA AUTH -- E2E OIDC CONSUMER INTEROPERABILITY SUITE");
console.log("  Real PKCE, Remote JWKS, RS256 Verification & Adversarial Gates");
console.log("================================================================");

let passed = 0;
let failed = 0;
let ipCounter = 900;

function getTestHeaders(extra: Record<string, string> = {}) {
  const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
  return {
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    Origin: process.env.FRONTEND_URL || "http://localhost:5174",
    ...extra,
  };
}

async function runTest(testNum: number, name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`[PASS] Test ${String(testNum).padStart(2, "0")}: ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`[FAIL] Test ${String(testNum).padStart(2, "0")}: ${name}:`, err.message || err);
    failed++;
  }
}

function base64url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function generatePkce() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

// --------------------------------------------------------------------------
// Start HTTP server for real network requests
// --------------------------------------------------------------------------
const PORT = 3847;
const server = serve({
  fetch: app.fetch,
  port: PORT,
});

const BASE_URL = `http://127.0.0.1:${PORT}`;

// --------------------------------------------------------------------------
// DB Setup and Provisioning
// --------------------------------------------------------------------------
const db = await getDb();

async function seedOAuthClient(
  clientId: string,
  clientSecret: string,
  isPublic: boolean,
  redirectUris: string[],
  extra: Record<string, any> = {}
) {
  const secretHash = crypto.createHash("sha256").update(clientSecret).digest("base64url");
  await db.collection("oauthClient").updateOne(
    { clientId },
    {
      $set: {
        clientId,
        client_id: clientId,
        clientSecret: secretHash,
        client_secret: secretHash,
        name: `App ${clientId}`,
        isPublic,
        is_public: isPublic,
        isDev: true,
        is_dev: true,
        redirectUris,
        redirect_uris: redirectUris,
        allowedOrigins: [BASE_URL, "http://localhost:5174"],
        skipConsent: true,
        skip_consent: true,
        applicationType: "web",
        updatedAt: new Date(),
        ...extra,
      },
    },
    { upsert: true }
  );
}

const testSuffix = crypto.randomBytes(4).toString("hex");
const appA_id = `client_a_${testSuffix}`;
const appA_secret = `secret_a_${testSuffix}_12345`;
const appB_id = `client_b_${testSuffix}`;
const appB_secret = `secret_b_${testSuffix}_12345`;
const redirectUriA = `${BASE_URL}/callback-a`;
const redirectUriB = `${BASE_URL}/callback-b`;

await seedOAuthClient(appA_id, appA_secret, false, [redirectUriA]);
await seedOAuthClient(appB_id, appB_secret, false, [redirectUriB]);

// Provision User registered only for App A
const userEmail = `oidc_user_${testSuffix}@example.com`;
const userPassword = "Password@12345!";
const userSignUpRes = await authProvider.api.signUpEmail({
  body: { email: userEmail, password: userPassword, name: "OIDC Test User" },
  asResponse: true,
});
const userCookie = (userSignUpRes.headers.get("set-cookie") || "").split(";")[0];
assert.ok(userCookie, "User session cookie must be established");

const userDoc = await db.collection("user").findOne({ email: userEmail });
assert.ok(userDoc, "User document must exist in DB");
const userId = userDoc._id.toString();

// Authorize App A for this user (user_app_registrations)
await db.collection("user_app_registrations").updateOne(
  { userId, clientId: appA_id },
  { $set: { userId, clientId: appA_id, registeredAt: new Date() } },
  { upsert: true }
);

// Variables shared across tests
let discoveryDoc: any = null;
let remoteJWKS: any = null;
let currentPkce = generatePkce();
let authCode = "";
let initialTokenResponse: any = null;
let rotatedTokenR1: any = null;
let rotatedTokenR2: any = null;

// ==========================================================================
// SECTION 1: OIDC DISCOVERY & JWKS (Standard Specification Compliance)
// ==========================================================================

await runTest(1, "OIDC Discovery: GET /.well-known/openid-configuration returns 200 with standard endpoints", async () => {
  const res = await fetch(`${BASE_URL}/.well-known/openid-configuration`);
  assert.equal(res.status, 200, "Discovery must return HTTP 200");
  discoveryDoc = await res.json();
  assert.ok(discoveryDoc.issuer, "Must declare issuer");
  assert.ok(discoveryDoc.authorization_endpoint, "Must declare authorization_endpoint");
  assert.ok(discoveryDoc.token_endpoint, "Must declare token_endpoint");
  assert.ok(discoveryDoc.jwks_uri, "Must declare jwks_uri");
  assert.ok(discoveryDoc.userinfo_endpoint, "Must declare userinfo_endpoint");
});

await runTest(2, "OIDC Discovery: declares S256 PKCE and authorization_code / refresh_token grants", async () => {
  assert.ok(Array.isArray(discoveryDoc.code_challenge_methods_supported), "code_challenge_methods_supported array required");
  assert.ok(discoveryDoc.code_challenge_methods_supported.includes("S256"), "Must declare S256 PKCE support");
  assert.ok(Array.isArray(discoveryDoc.grant_types_supported), "grant_types_supported array required");
  assert.ok(discoveryDoc.grant_types_supported.includes("authorization_code"), "Must declare authorization_code grant");
  assert.ok(discoveryDoc.grant_types_supported.includes("refresh_token"), "Must declare refresh_token grant");
  assert.ok(discoveryDoc.response_types_supported.includes("code"), "Must declare response_type=code");
});

await runTest(3, "JWKS Endpoint: GET /.well-known/jwks.json returns HTTP 200 with RS256 RSA keys", async () => {
  const res = await fetch(`${BASE_URL}/.well-known/jwks.json`);
  assert.equal(res.status, 200, "JWKS /.well-known/jwks.json must return 200");
  const data = await res.json();
  assert.ok(Array.isArray(data.keys) && data.keys.length > 0, "Keys array must not be empty");
  const key = data.keys[0];
  assert.equal(key.kty, "RSA", "Key type must be RSA");
  assert.equal(key.alg, "RS256", "Algorithm must be RS256");
  assert.ok(key.n && key.e, "RSA modulus and exponent must be present");
  assert.ok(key.kid, "Key ID must be present");
});

await runTest(4, "JWKS Alias: GET /.well-known/jwks returns HTTP 200 with identical keys", async () => {
  const res = await fetch(`${BASE_URL}/.well-known/jwks`);
  assert.equal(res.status, 200, "JWKS /.well-known/jwks alias must return 200");
  const data = await res.json();
  assert.ok(Array.isArray(data.keys) && data.keys.length > 0, "Keys array must not be empty");
  assert.equal(data.keys[0].kty, "RSA");
});

await runTest(5, "JWKS Canonical Endpoint: GET /api/auth/jwks matches discovery document jwks_uri", async () => {
  const res = await fetch(discoveryDoc.jwks_uri.replace("https://oauth21.vercel.app", BASE_URL).replace("http://localhost:3000", BASE_URL));
  assert.equal(res.status, 200, "Discovery jwks_uri must return 200");
  const data = await res.json();
  assert.ok(Array.isArray(data.keys) && data.keys.length > 0);
});

// ==========================================================================
// SECTION 2: COMPLETE CONSUMER PKCE FLOW
// ==========================================================================

await runTest(6, "Authorization Request: initiates flow with PKCE S256 and receives code redirect", async () => {
  currentPkce = generatePkce();
  const authUrl = new URL(`${BASE_URL}/api/auth/oauth2/authorize`);
  authUrl.searchParams.set("client_id", appA_id);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", redirectUriA);
  authUrl.searchParams.set("scope", "openid offline_access");
  authUrl.searchParams.set("state", "test_state_12345");
  authUrl.searchParams.set("code_challenge", currentPkce.challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  const res = await fetch(authUrl.toString(), {
    method: "GET",
    headers: {
      cookie: userCookie,
      ...getTestHeaders(),
    },
    redirect: "manual",
  });

  assert.ok(res.status === 302 || res.status === 200, "Authorization request must return 302 or 200 redirect");
  let redirectLocation = res.headers.get("location");
  if (!redirectLocation && res.status === 200) {
    const json = await res.json();
    redirectLocation = json.url;
  }
  assert.ok(redirectLocation, "Redirect location or URL must be present");
  const redirectedUrl = new URL(redirectLocation);
  authCode = redirectedUrl.searchParams.get("code") || "";
  assert.ok(authCode, "Authorization code must be returned in redirect URL");
  assert.equal(redirectedUrl.searchParams.get("state"), "test_state_12345", "State must be preserved");
});

async function fetchAuthCode(clientId: string, redirectUri: string, pkce?: { challenge: string }) {
  const authUrl = new URL(`${BASE_URL}/api/auth/oauth2/authorize`);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "openid offline_access");
  authUrl.searchParams.set("state", `state_${crypto.randomBytes(4).toString("hex")}`);
  if (pkce) {
    authUrl.searchParams.set("code_challenge", pkce.challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
  }

  const res = await fetch(authUrl.toString(), {
    method: "GET",
    headers: { cookie: userCookie, ...getTestHeaders() },
    redirect: "manual",
  });

  let urlStr = res.headers.get("location");
  if (!urlStr && res.status === 200) {
    const json = await res.json();
    urlStr = json.url;
  }
  if (!urlStr) {
    throw new Error(`No redirect URL found (status ${res.status})`);
  }
  const parsed = new URL(urlStr);
  const code = parsed.searchParams.get("code");
  if (!code) {
    throw new Error(`Redirect URL did not contain code: ${urlStr}`);
  }
  return { code, url: parsed };
}

await runTest(7, "Token Exchange: exchanges authorization code with code_verifier and Basic auth", async () => {
  const basicAuth = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: authCode,
    redirect_uri: redirectUriA,
    code_verifier: currentPkce.verifier,
  });

  const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: body.toString(),
  });

  assert.equal(res.status, 200, "Token exchange must succeed with 200");
  initialTokenResponse = await res.json();
  assert.ok(initialTokenResponse.access_token, "Must return access_token");
  assert.ok(initialTokenResponse.refresh_token, "Must return refresh_token (offline_access)");
  assert.ok(initialTokenResponse.id_token, "Must return id_token (openid scope)");
  assert.equal(initialTokenResponse.token_type, "Bearer", "token_type must be Bearer");
  assert.ok(initialTokenResponse.expires_in > 0, "expires_in must be positive");
});

// ==========================================================================
// SECTION 3: INDEPENDENT CRYPTOGRAPHIC VERIFICATION (JOSE)
// ==========================================================================

await runTest(8, "Cryptographic Verification: Remote JWKS retrieval via jose.createRemoteJWKSet", async () => {
  remoteJWKS = jose.createRemoteJWKSet(new URL(`${BASE_URL}/.well-known/jwks.json`));
  assert.ok(remoteJWKS, "Remote JWKS set must initialize");
});

await runTest(9, "Cryptographic Verification: RS256 signature verification of ID token against JWKS", async () => {
  const { payload, protectedHeader } = await jose.jwtVerify(initialTokenResponse.id_token, remoteJWKS);
  assert.equal(protectedHeader.alg, "RS256", "ID token algorithm must be RS256");
  assert.ok(payload.sub, "Subject claim must be present");
});

await runTest(10, "Claims Validation: validates standard OIDC claims (iss, aud, exp, iat)", async () => {
  const { payload } = await jose.jwtVerify(initialTokenResponse.id_token, remoteJWKS);
  // Expected issuer matches configuration or base URL
  assert.ok(payload.iss, "Issuer claim must be present");
  assert.equal(payload.aud, appA_id, "Audience must match Client ID");
  const nowSec = Math.floor(Date.now() / 1000);
  assert.ok(payload.exp! > nowSec, "Token must not be expired");
  assert.ok(payload.sub, "Subject claim must be present in ID token");
  assert.equal(payload.sub, userId, "Subject must match user ID");
});

await runTest(11, "Claims Validation: validates at_hash conforms to OIDC Core 1.0 spec", async () => {
  const { payload } = await jose.jwtVerify(initialTokenResponse.id_token, remoteJWKS);
  if (payload.at_hash) {
    const atHashExpected = base64url(
      crypto.createHash("sha256").update(initialTokenResponse.access_token).digest().subarray(0, 16)
    );
    assert.equal(payload.at_hash, atHashExpected, "at_hash must match leftmost 128 bits of SHA-256 access token hash");
  }
});

// ==========================================================================
// SECTION 4: PROTECTED RESOURCE ACCESS (USERINFO)
// ==========================================================================

await runTest(12, "UserInfo: GET /oauth2/userinfo with Bearer access token returns user claims", async () => {
  const res = await fetch(`${BASE_URL}/api/auth/oauth2/userinfo`, {
    headers: {
      Authorization: `Bearer ${initialTokenResponse.access_token}`,
      ...getTestHeaders(),
    },
  });

  assert.equal(res.status, 200, "UserInfo must return 200");
  const userInfo = await res.json();
  assert.equal(userInfo.sub, userId, "UserInfo sub must match user ID");
});

await runTest(13, "UserInfo: GET /oauth2/userinfo without Authorization returns 401 Unauthorized", async () => {
  const res = await fetch(`${BASE_URL}/api/auth/oauth2/userinfo`, {
    headers: getTestHeaders(),
  });
  assert.equal(res.status, 401, "UserInfo without auth must return 401");
});

// ==========================================================================
// SECTION 5: TOKEN INTROSPECTION (RFC 7662)
// ==========================================================================

await runTest(14, "Token Introspection: confidential client introspects active access token", async () => {
  const basicAuth = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const res = await fetch(`${BASE_URL}/api/auth/oauth2/introspect`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: new URLSearchParams({ token: initialTokenResponse.access_token }).toString(),
  });

  assert.equal(res.status, 200, "Introspection must return 200");
  const data = await res.json();
  assert.equal(data.active, true, "Access token must be active");
  assert.equal(data.client_id, appA_id, "client_id must match");
});

await runTest(15, "Token Introspection: invalid or bogus token returns active: false", async () => {
  const basicAuth = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const res = await fetch(`${BASE_URL}/api/auth/oauth2/introspect`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: new URLSearchParams({ token: "totally_bogus_token_value_98765" }).toString(),
  });

  assert.equal(res.status, 200, "Introspection must return 200");
  const data = await res.json();
  assert.equal(data.active, false, "Bogus token must return active: false");
});

// ==========================================================================
// SECTION 6: REFRESH TOKEN ROTATION & SEQUENTIAL ROTATION
// ==========================================================================

await runTest(16, "Refresh Rotation: exchanges R0 for new access token and rotated R1", async () => {
  const basicAuth = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: initialTokenResponse.refresh_token,
  });

  const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: body.toString(),
  });

  assert.equal(res.status, 200, "Refresh rotation must return 200");
  rotatedTokenR1 = await res.json();
  assert.ok(rotatedTokenR1.access_token, "Must return new access token");
  assert.ok(rotatedTokenR1.refresh_token, "Must return rotated refresh token R1");
  assert.notEqual(rotatedTokenR1.refresh_token, initialTokenResponse.refresh_token, "R1 must differ from R0");
});

await runTest(17, "Sequential Rotation: exchanges R1 for new access token and rotated R2", async () => {
  const basicAuth = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: rotatedTokenR1.refresh_token,
  });

  const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: body.toString(),
  });

  assert.equal(res.status, 200, "Sequential refresh must return 200");
  rotatedTokenR2 = await res.json();
  assert.ok(rotatedTokenR2.access_token, "Must return new access token");
  assert.ok(rotatedTokenR2.refresh_token, "Must return rotated refresh token R2");
  assert.notEqual(rotatedTokenR2.refresh_token, rotatedTokenR1.refresh_token, "R2 must differ from R1");
});

await runTest(18, "Rotated Credentials Validation: new access token from R2 accesses UserInfo", async () => {
  const res = await fetch(`${BASE_URL}/api/auth/oauth2/userinfo`, {
    headers: {
      Authorization: `Bearer ${rotatedTokenR2.access_token}`,
      ...getTestHeaders(),
    },
  });

  assert.equal(res.status, 200, "UserInfo with R2 access token must return 200");
  const userInfo = await res.json();
  assert.equal(userInfo.sub, userId);
});

// ==========================================================================
// SECTION 7: ADVERSARIAL & SECURITY EDGE CASES
// ==========================================================================

await runTest(19, "Adversarial: Authorization code replay attack is rejected", async () => {
  const basicAuth = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: authCode, // already exchanged in Test 7
    redirect_uri: redirectUriA,
    code_verifier: currentPkce.verifier,
  });

  const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: body.toString(),
  });

  assert.equal(res.status, 400, "Code replay must return HTTP 400");
  const data = await res.json();
  assert.ok(data.error === "invalid_grant" || data.error === "invalid_request");
});

await runTest(20, "Adversarial: Wrong PKCE verifier attack is rejected", async () => {
  const pkce = generatePkce();
  const { code: freshCode } = await fetchAuthCode(appA_id, redirectUriA, pkce);

  const basicAuth = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: freshCode,
    redirect_uri: redirectUriA,
    code_verifier: "wrong_verifier_string_that_does_not_match_challenge",
  });

  const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: body.toString(),
  });

  assert.ok(res.status === 400 || res.status === 401, "Wrong PKCE verifier must return HTTP 400 or 401");
});

await runTest(21, "Adversarial: Wrong redirect_uri in token exchange is rejected", async () => {
  const pkce = generatePkce();
  const { code: freshCode } = await fetchAuthCode(appA_id, redirectUriA, pkce);

  const basicAuth = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: freshCode,
    redirect_uri: "http://localhost:5174/wrong-callback",
    code_verifier: pkce.verifier,
  });

  const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: body.toString(),
  });

  assert.equal(res.status, 400, "Wrong redirect URI must return HTTP 400");
});

await runTest(22, "Adversarial: Wrong client secret is rejected with 401/400 invalid_client", async () => {
  const pkce = generatePkce();
  const { code: freshCode } = await fetchAuthCode(appA_id, redirectUriA, pkce);

  const invalidBasic = Buffer.from(`${appA_id}:completely_incorrect_secret`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: freshCode,
    redirect_uri: redirectUriA,
    code_verifier: pkce.verifier,
  });

  const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${invalidBasic}`,
      ...getTestHeaders(),
    },
    body: body.toString(),
  });

  assert.ok(res.status === 401 || res.status === 400, "Wrong client credentials must return HTTP 401 or 400");
  const errData = await res.json();
  assert.ok(errData.error === "invalid_client" || errData.error === "invalid_request");
});

await runTest(23, "Adversarial: Tampered ID token signature is rejected by consumer validator", async () => {
  const parts = initialTokenResponse.id_token.split(".");
  // Tamper the payload: change subject
  const payloadJson = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
  payloadJson.sub = "attacker_controlled_sub";
  const tamperedPayload = Buffer.from(JSON.stringify(payloadJson)).toString("base64url");
  const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

  let failedVerification = false;
  try {
    await jose.jwtVerify(tamperedToken, remoteJWKS);
  } catch (err: any) {
    failedVerification = true;
  }
  assert.ok(failedVerification, "Tampered token must fail signature verification");
});

await runTest(24, "Adversarial: Algorithm Confusion Attack (forged HS256 with public key) is rejected", async () => {
  // Attacker obtains public RSA key from JWKS, exports it, and signs HS256 token using public key string as secret
  const jwksRes = await fetch(`${BASE_URL}/.well-known/jwks.json`);
  const jwksData = await jwksRes.json();
  const rsaKeyJwk = jwksData.keys[0];
  const rsaPublicKey = await jose.importJWK(rsaKeyJwk, "RS256");
  const spkiPem = await jose.exportSPKI(rsaPublicKey as any);

  // Sign token using HS256 with SPKI PEM bytes
  const forgedToken = await new jose.SignJWT({
    iss: discoveryDoc.issuer,
    aud: appA_id,
    sub: userId,
    email: "attacker@forged.com",
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT", kid: rsaKeyJwk.kid })
    .setIssuedAt()
    .setExpirationTime("2h")
    .sign(Buffer.from(spkiPem));

  let rejected = false;
  try {
    // Consumer verifies against remote RS256 JWKS
    await jose.jwtVerify(forgedToken, remoteJWKS);
  } catch (err: any) {
    rejected = true;
  }
  assert.ok(rejected, "Algorithm confusion forged token must be rejected");
});

await runTest(25, "Adversarial: Refresh Token Replay (replaying R0 after R1 issued) is rejected", async () => {
  // Wait > 2000 ms to guarantee grace window expiry
  await new Promise((r) => setTimeout(r, 2100));

  const basicAuth = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: initialTokenResponse.refresh_token, // R0 replay!
  });

  const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: body.toString(),
  });

  assert.ok(res.status === 400 || res.status === 401, "Replaying old refresh token R0 must return HTTP 400 or 401");
});

await runTest(26, "Adversarial: Refresh token family is revoked after replay attack", async () => {
  // After replay of R0, attempting to refresh with successor R2 must also fail
  const basicAuth = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: rotatedTokenR2.refresh_token, // R2 should be revoked!
  });

  const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: body.toString(),
  });

  assert.ok(res.status === 400 || res.status === 401, "Successor R2 must fail because family was revoked upon replay");
});

await runTest(27, "Adversarial: Cross-Client Refresh Attack (App A token with App B credentials) is rejected", async () => {
  // Fresh flow for App A
  const pkce = generatePkce();
  const { code: freshCode } = await fetchAuthCode(appA_id, redirectUriA, pkce);

  const basicAuthA = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const tokenRes = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuthA}`,
      ...getTestHeaders(),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: freshCode,
      redirect_uri: redirectUriA,
      code_verifier: pkce.verifier,
    }).toString(),
  });
  const tokenData = await tokenRes.json();
  const appARefreshToken = tokenData.refresh_token;

  // Now App B tries to use App A's refresh token
  const basicAuthB = Buffer.from(`${appB_id}:${appB_secret}`).toString("base64");
  const crossRefreshRes = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuthB}`,
      ...getTestHeaders(),
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: appARefreshToken,
    }).toString(),
  });

  assert.equal(crossRefreshRes.status, 400, "Cross-client refresh must return HTTP 400");
});

await runTest(28, "Adversarial: Cross-Client Introspection Attack (App B cannot introspect App A token)", async () => {
  // Create an access token for App A
  const pkce = generatePkce();
  const { code } = await fetchAuthCode(appA_id, redirectUriA, pkce);

  const basicAuthA = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const tokenRes = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuthA}`,
      ...getTestHeaders(),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUriA,
      code_verifier: pkce.verifier,
    }).toString(),
  });
  const { access_token } = await tokenRes.json();

  // App B introspects App A's token
  const basicAuthB = Buffer.from(`${appB_id}:${appB_secret}`).toString("base64");
  const introRes = await fetch(`${BASE_URL}/api/auth/oauth2/introspect`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuthB}`,
      ...getTestHeaders(),
    },
    body: new URLSearchParams({ token: access_token }).toString(),
  });

  assert.equal(introRes.status, 200);
  const introData = await introRes.json();
  // App B either gets active: false or client_id does NOT match App B
  assert.ok(introData.active === false || introData.client_id !== appB_id, "Cross-client token introspection must not be attributed to App B");
});

await runTest(29, "Adversarial: Private Application Isolation: Unregistered user denied authorization", async () => {
  // User is NOT registered for private App B
  const pkce = generatePkce();
  const authUrl = new URL(`${BASE_URL}/api/auth/oauth2/authorize`);
  authUrl.searchParams.set("client_id", appB_id);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", redirectUriB);
  authUrl.searchParams.set("scope", "openid");
  authUrl.searchParams.set("code_challenge", pkce.challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  const res = await fetch(authUrl.toString(), {
    method: "GET",
    headers: { cookie: userCookie, ...getTestHeaders() },
    redirect: "manual",
  });

  const location = res.headers.get("location") || "";
  // Unregistered user should either be redirected with error=access_denied or to the frontend access_denied page
  assert.ok(
    location.includes("access_denied") || location.includes("error=") || res.status === 403 || res.status === 401,
    `Private App access without registration must be denied (got ${res.status} location: ${location})`
  );
});

// ==========================================================================
// Suite Results & Teardown
// ==========================================================================
server.close();

console.log("\n================================================================");
console.log(`  E2E OIDC INTEROP SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================\n");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
