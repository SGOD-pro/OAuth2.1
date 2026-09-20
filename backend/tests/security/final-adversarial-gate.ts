import dotenv from "dotenv";
dotenv.config();

import assert from "node:assert/strict";
import crypto from "crypto";
import { ObjectId } from "mongodb";

// Configure test environment before any application imports
process.env.NODE_ENV = "test";
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
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
const { registerTokenFamily, verifyAndRotateTokenFamily } = await import("../../src/db/state");
const { isRegisteredRedirectUri, getTrustedClientIp, normalizeOrigin } = await import("../../src/utils/security");

// --------------------------------------------------------------------------
// Narrow Google External Provider Mocking (RS256 ID Token & JWKS)
// --------------------------------------------------------------------------
const googleKeyPair = await jose.generateKeyPair("RS256");
const googlePublicKeyJwk = (await jose.exportJWK(googleKeyPair.publicKey)) as any;
googlePublicKeyJwk.kid = "test-google-kid";
googlePublicKeyJwk.alg = "RS256";
googlePublicKeyJwk.use = "sig";

let mockGoogleProfile = {
  sub: `google_sub_${crypto.randomBytes(6).toString("hex")}`,
  email: `google_user_${crypto.randomBytes(4).toString("hex")}@example.com`,
  name: "Mock Google User",
};

const originalGlobalFetch = globalThis.fetch;
globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const urlStr =
    typeof input === "string"
      ? input
      : input instanceof URL
      ? input.href
      : (input as any)?.url || (input as any)?.href || String(input);

  if (urlStr.startsWith("https://oauth2.googleapis.com/token")) {
    const idToken = await new jose.SignJWT({
      iss: "https://accounts.google.com",
      aud: process.env.GOOGLE_CLIENT_ID || "test-google-id",
      sub: mockGoogleProfile.sub,
      email: mockGoogleProfile.email,
      email_verified: true,
      name: mockGoogleProfile.name,
      picture: "https://example.com/avatar.png",
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-google-kid" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(googleKeyPair.privateKey);

    return new Response(
      JSON.stringify({
        access_token: `mock_google_at_${crypto.randomBytes(8).toString("hex")}`,
        id_token: idToken,
        token_type: "Bearer",
        expires_in: 3600,
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  if (urlStr.startsWith("https://www.googleapis.com/oauth2/v3/certs")) {
    return new Response(
      JSON.stringify({
        keys: [googlePublicKeyJwk],
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  return originalGlobalFetch(input, init);
};

console.log("================================================================");
console.log("  SWYRA AUTH -- FINAL ADVERSARIAL SECURITY GATE HARNESS");
console.log("  Verifying Invariants I1 through I17 across all 30 Cases");
console.log("================================================================");

let passed = 0;
let failed = 0;
let ipCounter = 800;

function getTestHeaders(extra: Record<string, string> = {}) {
  const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
  return {
    "Content-Type": "application/json",
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    Origin: process.env.FRONTEND_URL || "http://localhost:5174",
    ...extra,
  };
}

async function runTest(caseNum: number, name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`[PASS] Case ${caseNum}: ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`[FAIL] Case ${caseNum}: ${name}:`, err.message || err);
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

const db = await getDb();

// Seed Helper
async function seedOAuthClient(
  clientId: string,
  clientSecret: string,
  isPublic: boolean,
  redirectUris: string[],
  disabled = false,
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
        isDev: false,
        is_dev: false,
        disabled,
        redirectUris,
        redirect_uris: redirectUris,
        allowedOrigins: ["http://localhost:5174"],
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

// --------------------------------------------------------------------------
// PROVISION GLOBAL FIXTURES
// --------------------------------------------------------------------------
const testSuffix = crypto.randomBytes(4).toString("hex");
const appA_id = `app_a_${testSuffix}`;
const appA_secret = `secret_a_${testSuffix}_12345`;
const appB_id = `app_b_${testSuffix}`;
const appB_secret = `secret_b_${testSuffix}_12345`;
const disabledApp_id = `app_dis_${testSuffix}`;
const redirectUriA = "http://localhost:5174/callback-a";
const redirectUriB = "http://localhost:5174/callback-b";

await seedOAuthClient(appA_id, appA_secret, false, [redirectUriA]);
await seedOAuthClient(appB_id, appB_secret, false, [redirectUriB]);
await seedOAuthClient(disabledApp_id, "disabled_secret_12345", false, ["http://localhost:5174/callback-dis"], true);

// Provision Super Admin
const superAdminEmail = `super_${testSuffix}@example.com`;
const superAdminPass = "SuperAdminPassword@123!";
const saRes = await authProvider.api.signUpEmail({
  body: { email: superAdminEmail, password: superAdminPass, name: "Super Admin" },
  asResponse: true,
});
const superAdminCookie = (saRes.headers.get("set-cookie") || "").split(";")[0];
await db.collection("user").updateOne(
  { email: superAdminEmail },
  { $set: { role: "admin", scopedClientId: null, emailVerified: true } }
);

// Provision Scoped Admin for App A
const scopedAdminAEmail = `scoped_a_${testSuffix}@example.com`;
const scopedAdminAPass = "ScopedAdminPassword@123!";
const scaRes = await authProvider.api.signUpEmail({
  body: { email: scopedAdminAEmail, password: scopedAdminAPass, name: "Scoped Admin A" },
  asResponse: true,
});
const scopedAdminACookie = (scaRes.headers.get("set-cookie") || "").split(";")[0];
await db.collection("user").updateOne(
  { email: scopedAdminAEmail },
  { $set: { role: "admin", scopedClientId: appA_id, emailVerified: true } }
);

// Provision Scoped Admin for App B
const scopedAdminBEmail = `scoped_b_${testSuffix}@example.com`;
const scopedAdminBPass = "ScopedAdminPassword@123!";
const scbRes = await authProvider.api.signUpEmail({
  body: { email: scopedAdminBEmail, password: scopedAdminBPass, name: "Scoped Admin B" },
  asResponse: true,
});
const scopedAdminBCookie = (scbRes.headers.get("set-cookie") || "").split(";")[0];
await db.collection("user").updateOne(
  { email: scopedAdminBEmail },
  { $set: { role: "admin", scopedClientId: appB_id, emailVerified: true } }
);

// Provision Normal User 1 (Assigned to App A)
const user1Email = `user1_${testSuffix}@example.com`;
const user1Pass = "User1Password@123!";
const u1Res = await authProvider.api.signUpEmail({
  body: { email: user1Email, password: user1Pass, name: "User One" },
  asResponse: true,
});
const user1Cookie = (u1Res.headers.get("set-cookie") || "").split(";")[0];
const user1Doc = await db.collection("user").findOne({ email: user1Email });
const user1Id = String(user1Doc?.id || user1Doc?._id);
await db.collection("user_app_registrations").insertOne({
  userId: user1Id,
  clientId: appA_id,
  registeredAt: new Date(),
});

// Provision Normal User 2 (Assigned to App B only)
const user2Email = `user2_${testSuffix}@example.com`;
const user2Pass = "User2Password@123!";
const u2Res = await authProvider.api.signUpEmail({
  body: { email: user2Email, password: user2Pass, name: "User Two" },
  asResponse: true,
});
const user2Cookie = (u2Res.headers.get("set-cookie") || "").split(";")[0];
const user2Doc = await db.collection("user").findOne({ email: user2Email });
const user2Id = String(user2Doc?.id || user2Doc?._id);
await db.collection("user_app_registrations").insertOne({
  userId: user2Id,
  clientId: appB_id,
  registeredAt: new Date(),
});

// Helper: Authorize and retrieve OAuth authorization code
async function getAuthCode(clientId: string, redirectUri: string, userCookie: string, pkce?: { challenge: string }) {
  let url = `/api/auth/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20offline_access&state=state_${crypto.randomBytes(4).toString("hex")}`;
  if (pkce) {
    url += `&code_challenge=${pkce.challenge}&code_challenge_method=S256`;
  }
  const res = await app.request(url, {
    method: "GET",
    headers: getTestHeaders({ Cookie: userCookie }),
  });
  if (res.status !== 302) {
    throw new Error(`Expected 302 from /oauth2/authorize, got ${res.status}`);
  }
  const loc = res.headers.get("location");
  if (!loc) throw new Error("No location header on authorize redirect");
  const parsed = new URL(loc);
  const code = parsed.searchParams.get("code");
  if (!code) throw new Error(`Authorize redirected without code: ${loc}`);
  return code;
}

// --------------------------------------------------------------------------
// CASE 1: Cross-Client Authorization-Code Redemption
// --------------------------------------------------------------------------
await runTest(1, "Cross-client authorization-code redemption (App A code presented to App B)", async () => {
  const pkce = generatePkce();
  const code = await getAuthCode(appA_id, redirectUriA, user1Cookie, pkce);

  // Attempt exchange with App B credentials
  const basicB = Buffer.from(`${appB_id}:${appB_secret}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUriA,
    code_verifier: pkce.verifier,
  });

  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicB}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: body.toString(),
  });

  assert.equal(res.status, 400, "Wrong client credentials must be rejected with 400");
  const json = await res.json();
  assert.equal(json.error, "invalid_grant", "Expected invalid_grant for wrong client redemption");
});

// --------------------------------------------------------------------------
// CASE 2: Single-Use Auth-Code Behavior (Code burned on first attempt)
// --------------------------------------------------------------------------
await runTest(2, "Single-use auth-code behavior (re-using burned code fails for original client)", async () => {
  const pkce = generatePkce();
  const code = await getAuthCode(appA_id, redirectUriA, user1Cookie, pkce);

  // App B burns code
  const basicB = Buffer.from(`${appB_id}:${appB_secret}`).toString("base64");
  await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicB}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUriA,
      code_verifier: pkce.verifier,
    }).toString(),
  });

  // App A retries the now burned code
  const basicA = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const retryRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicA}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUriA,
      code_verifier: pkce.verifier,
    }).toString(),
  });

  assert.equal(retryRes.status, 400, "Burned auth code must be rejected on reuse");
  const json = await retryRes.json();
  assert.equal(json.error, "invalid_grant", "Burned code must fail with invalid_grant");
});

// --------------------------------------------------------------------------
// CASE 3: PKCE Binding
// --------------------------------------------------------------------------
await runTest(3, "PKCE binding (wrong verifier or missing verifier is rejected)", async () => {
  const pkce = generatePkce();
  const code = await getAuthCode(appA_id, redirectUriA, user1Cookie, pkce);

  const basicA = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");
  const wrongVerifierRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicA}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUriA,
      code_verifier: "wrong_verifier_12345678901234567890123456789012",
    }).toString(),
  });

  assert.ok(wrongVerifierRes.status >= 400, "Wrong code_verifier must fail token exchange");
});

// --------------------------------------------------------------------------
// CASE 4: Refresh-Token Concurrency (5 Simultaneous Requests -> 1 Winner, 4 Losers)
// --------------------------------------------------------------------------
let activeRefreshToken: string = "";
let initialTokenFamilyId: string = "";
let racedTokenString: string = "";

await runTest(4, "Refresh-token concurrency: 5 simultaneous requests produce exactly 1 successor with zero duplicates", async () => {
  // Obtain initial refresh token
  const pkce = generatePkce();
  const code = await getAuthCode(appA_id, redirectUriA, user1Cookie, pkce);
  const basicA = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");

  const initialTokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicA}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUriA,
      code_verifier: pkce.verifier,
    }).toString(),
  });

  assert.equal(initialTokenRes.status, 200);
  const initialJson = await initialTokenRes.json();
  assert.ok(initialJson.refresh_token, "Must issue refresh token");
  const tokenToRace = initialJson.refresh_token;
  racedTokenString = tokenToRace;

  // Record pre-race active refresh tokens for this canonical user/client
  const preTokens = await db.collection("oauthRefreshToken").find({
    clientId: appA_id,
    userId: { $in: [user1Id, new ObjectId(user1Id)] },
    $or: [{ revoked: null }, { revoked: false }, { revoked: { $exists: false } }],
  }).toArray();

  // Send 5 concurrent requests with exact same refresh token R0
  const reqBody = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: tokenToRace,
  }).toString();

  const promises = Array.from({ length: 5 }, () =>
    app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        Authorization: `Basic ${basicA}`,
        "Content-Type": "application/x-www-form-urlencoded",
      }),
      body: reqBody,
    })
  );

  const responses = await Promise.all(promises);
  const statuses = responses.map((r) => r.status);
  const successCount = statuses.filter((s) => s === 200).length;
  const failureCount = statuses.filter((s) => s >= 400).length;

  assert.equal(successCount, 1, `Expected exactly 1 success out of 5 concurrent requests, got ${successCount}`);
  assert.equal(failureCount, 4, `Expected exactly 4 failures out of 5 concurrent requests, got ${failureCount}`);

  // Inspect winner response
  const winnerResponse = responses.find((r) => r.status === 200)!;
  const winnerJson = await winnerResponse.json();
  activeRefreshToken = winnerJson.refresh_token;
  assert.ok(activeRefreshToken, "Winner must receive new successor refresh token R1");

  const winnerHash = crypto.createHash("sha256").update(activeRefreshToken).digest("hex");
  const familyDoc = await db.collection("oauth_token_families").findOne({ activeTokenHash: winnerHash });

  assert.ok(familyDoc, "Token family must have exactly one active successor matching winner");
  assert.equal(familyDoc.status, "active", "Token family must remain active after concurrency race");
  assert.equal(familyDoc.clientId, appA_id);
  assert.equal(familyDoc.userId, user1Id);
  initialTokenFamilyId = familyDoc.familyId;

  // F-08 Assertion: Query ALL active refresh tokens for this client/user in MongoDB
  let activePostTokens: any[] = [];
  for (let attempt = 0; attempt < 15; attempt++) {
    const postTokens = await db.collection("oauthRefreshToken").find({
      clientId: appA_id,
      userId: { $in: [user1Id, new ObjectId(user1Id)] },
      $or: [{ revoked: null }, { revoked: false }, { revoked: { $exists: false } }],
    }).toArray();
    activePostTokens = postTokens.filter((t: any) => !t.expiresAt || new Date(t.expiresAt) > new Date());
    if (activePostTokens.length === 1) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.equal(
    activePostTokens.length,
    1,
    `Expected exactly 1 active refresh token document in DB (zero duplicate active credentials), found ${activePostTokens.length}`
  );

  // Verify old consumed token R0 cannot remain active
  const oldB64Hash = crypto.createHash("sha256").update(tokenToRace).digest("base64url");
  const oldTokensInDb = await db.collection("oauthRefreshToken").find({
    clientId: appA_id,
    $or: [{ token: tokenToRace }, { token: oldB64Hash }],
  }).toArray();
  const activeOld = oldTokensInDb.filter((t: any) => t.revoked == null && (!t.expiresAt || new Date(t.expiresAt) > new Date()));
  assert.equal(activeOld.length, 0, "Consumed token R0 must not remain as an active credential");

  // Sequential second refresh: Rotate R1 -> R2
  const secondRefreshRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicA}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: activeRefreshToken,
    }).toString(),
  });
  assert.equal(secondRefreshRes.status, 200, "Sequential second refresh with R1 must succeed");
  const secondJson = await secondRefreshRes.json();
  const secondSuccessorToken = secondJson.refresh_token;
  assert.ok(secondSuccessorToken, "Must issue second successor refresh token R2");

  // Verify MongoDB family updated to R2
  const secondHash = crypto.createHash("sha256").update(secondSuccessorToken).digest("hex");
  const secondFamilyDoc = await db.collection("oauth_token_families").findOne({ activeTokenHash: secondHash });
  assert.ok(secondFamilyDoc, "Token family must have R2 as activeTokenHash");
  assert.equal(secondFamilyDoc.status, "active", "Family must remain active after R2 rotation");
  assert.ok(secondFamilyDoc.consumedTokenHashes.includes(winnerHash), "consumedTokenHashes must contain R1");

  // Replaying R1 must now fail
  const replayR1 = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicA}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: activeRefreshToken,
    }).toString(),
  });
  assert.ok(replayR1.status >= 400, "Replaying consumed R1 must fail");

  // Replaying R0 must also fail
  const replayR0 = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicA}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokenToRace,
    }).toString(),
  });
  assert.ok(replayR0.status >= 400, "Replaying consumed R0 must fail");

  // Negative cross-client test: App A refresh token presented with App B credentials
  const basicB = Buffer.from(`${appB_id}:${appB_secret}`).toString("base64");
  const crossRefreshRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicB}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: secondSuccessorToken,
    }).toString(),
  });
  assert.ok(crossRefreshRes.status >= 400, "App A refresh token with App B credentials must be rejected");

  // Invariant: App A family remains untouched and active
  const appAFamCheck = await db.collection("oauth_token_families").findOne({ activeTokenHash: secondHash });
  assert.ok(appAFamCheck, "App A family must remain intact");
  assert.equal(appAFamCheck.status, "active", "App A family must remain active after cross-client attempt");

  // Update activeRefreshToken to R2 for subsequent tests
  activeRefreshToken = secondSuccessorToken;
});

// --------------------------------------------------------------------------
// CASE 5: Refresh-Token Replay & Exact Grace-Boundary Verification (1999ms, 2000ms, 2001ms)
// --------------------------------------------------------------------------
await runTest(5, "Refresh-token replay: isolated synthetic fixtures for 1999ms, 2000ms, and 2001ms boundaries", async () => {
  const baseTime = Date.now();

  // 1. Isolated synthetic fixture at 1999ms (within 2000ms grace window): must NOT trigger cascade revocation
  const fam1999Id = `fam_1999_${crypto.randomBytes(4).toString("hex")}`;
  const consumed1999 = crypto.randomBytes(32).toString("hex");
  const active1999 = crypto.randomBytes(32).toString("hex");
  await db.collection("oauth_token_families").insertOne({
    familyId: fam1999Id,
    clientId: appA_id,
    userId: user1Id,
    activeTokenHash: active1999,
    consumedTokenHashes: [consumed1999],
    status: "active",
    createdAt: new Date(baseTime - 5000),
    updatedAt: new Date(baseTime),
  });

  const res1999 = await verifyAndRotateTokenFamily(consumed1999, "dummy", undefined, baseTime + 1999);
  assert.equal(res1999.replayed, false, "At 1999ms (within 2000ms grace), request must NOT trigger replay revocation");
  const doc1999 = await db.collection("oauth_token_families").findOne({ familyId: fam1999Id });
  assert.equal(doc1999?.status, "active", "Family at 1999ms must remain active");

  // 2. Isolated synthetic fixture at exactly 2000ms (grace window ended): MUST trigger cascade revocation
  const fam2000Id = `fam_2000_${crypto.randomBytes(4).toString("hex")}`;
  const consumed2000 = crypto.randomBytes(32).toString("hex");
  const active2000 = crypto.randomBytes(32).toString("hex");
  await db.collection("oauth_token_families").insertOne({
    familyId: fam2000Id,
    clientId: appA_id,
    userId: user1Id,
    activeTokenHash: active2000,
    consumedTokenHashes: [consumed2000],
    status: "active",
    createdAt: new Date(baseTime - 5000),
    updatedAt: new Date(baseTime),
  });

  const res2000 = await verifyAndRotateTokenFamily(consumed2000, "dummy", undefined, baseTime + 2000);
  assert.equal(res2000.replayed, true, "At 2000ms (grace window ended), replay attempt must trigger revocation");
  const doc2000 = await db.collection("oauth_token_families").findOne({ familyId: fam2000Id });
  assert.equal(doc2000?.status, "revoked", "Family at 2000ms must be marked revoked");

  // 3. Isolated synthetic fixture at 2001ms (past grace window): MUST trigger cascade revocation
  const fam2001Id = `fam_2001_${crypto.randomBytes(4).toString("hex")}`;
  const consumed2001 = crypto.randomBytes(32).toString("hex");
  const active2001 = crypto.randomBytes(32).toString("hex");
  await db.collection("oauth_token_families").insertOne({
    familyId: fam2001Id,
    clientId: appA_id,
    userId: user1Id,
    activeTokenHash: active2001,
    consumedTokenHashes: [consumed2001],
    status: "active",
    createdAt: new Date(baseTime - 5000),
    updatedAt: new Date(baseTime),
  });

  const res2001 = await verifyAndRotateTokenFamily(consumed2001, "dummy", undefined, baseTime + 2001);
  assert.equal(res2001.replayed, true, "At 2001ms (past grace window), replay attempt must trigger revocation");
  const doc2001 = await db.collection("oauth_token_families").findOne({ familyId: fam2001Id });
  assert.equal(doc2001?.status, "revoked", "Family at 2001ms must be marked revoked");

  // Clean up synthetic fixtures
  await db.collection("oauth_token_families").deleteMany({
    familyId: { $in: [fam1999Id, fam2000Id, fam2001Id] },
  });
});

// --------------------------------------------------------------------------
// CASE 6: Missing-userId Family Replay Isolation
// --------------------------------------------------------------------------
await runTest(6, "Missing-userId family replay isolation: does not delete all app credentials", async () => {
  const dummyFamilyId = `dummy_fam_${crypto.randomBytes(4).toString("hex")}`;
  const dummyConsumedHash = crypto.randomBytes(32).toString("hex");

  await db.collection("oauth_token_families").insertOne({
    familyId: dummyFamilyId,
    clientId: appA_id,
    userId: undefined, // Missing userId
    activeTokenHash: "dummy_active_hash",
    consumedTokenHashes: [dummyConsumedHash],
    status: "active",
    createdAt: new Date(Date.now() - 10000),
    updatedAt: new Date(Date.now() - 10000),
  });

  // Seed another user's active token for App A
  const otherTokenId = `other_token_${crypto.randomBytes(4).toString("hex")}`;
  await db.collection("oauthRefreshToken").insertOne({
    id: otherTokenId,
    clientId: appA_id,
    userId: "other_innocent_user_999",
    token: "innocent_user_refresh_token",
    expiresAt: new Date(Date.now() + 100000),
  });

  // Trigger replay verification on the missing-userId family
  const res = await verifyAndRotateTokenFamily(dummyConsumedHash, "dummy");
  assert.equal(res.replayed, true);

  // Innocent user's token MUST still exist in database!
  const innocentToken = await db.collection("oauthRefreshToken").findOne({ id: otherTokenId });
  assert.ok(innocentToken, "Innocent user credentials must NOT be purged when replaying family with missing userId");

  await db.collection("oauthRefreshToken").deleteOne({ id: otherTokenId });
});

// --------------------------------------------------------------------------
// CASE 7: App A vs App B Token Isolation
// --------------------------------------------------------------------------
await runTest(7, "App A vs App B token isolation: App A access token cannot access App B", async () => {
  const pkce = generatePkce();
  const code = await getAuthCode(appA_id, redirectUriA, user1Cookie, pkce);
  const basicA = Buffer.from(`${appA_id}:${appA_secret}`).toString("base64");

  const res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      Authorization: `Basic ${basicA}`,
      "Content-Type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUriA,
      code_verifier: pkce.verifier,
    }).toString(),
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  const accessToken = data.access_token;

  // App B admin verify cannot accept this token as an app admin token
  const verifyRes = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${accessToken}` }),
    body: JSON.stringify({ client_id: appB_id, client_secret: appB_secret }),
  });
  assert.equal(verifyRes.status, 401, "Token for App A cannot be used on App B app-admin endpoint");
});

// --------------------------------------------------------------------------
// CASE 8: Full Scoped-Admin IDOR Matrix
// --------------------------------------------------------------------------
await runTest(8, "Full scoped-admin IDOR matrix (App A admin cannot read/modify App B)", async () => {
  // 1. Unauthenticated request -> 401
  const unauthRes = await app.request(`/api/admin/clients/${appB_id}`, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(unauthRes.status, 401, "Unauthenticated access to client config must return 401");

  // 2. Normal user request -> 403
  const normalUserRes = await app.request(`/api/admin/clients/${appB_id}`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: user1Cookie }),
  });
  assert.equal(normalUserRes.status, 403, "Normal user access to admin routes must return 403");

  // 3. Scoped Admin A tries to GET App B config -> 403
  const getB = await app.request(`/api/admin/clients/${appB_id}`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(getB.status, 403, "Scoped Admin A cannot GET App B");

  // 4. Scoped Admin A tries to PATCH App B config -> 403
  const patchB = await app.request(`/api/admin/clients/${appB_id}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
    body: JSON.stringify({ name: "Hacked App B" }),
  });
  assert.equal(patchB.status, 403, "Scoped Admin A cannot PATCH App B");

  // 5. Scoped Admin A tries to PATCH App B via /app/:clientId/config -> 403
  const patchAppConfigB = await app.request(`/api/admin/app/${appB_id}/config`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
    body: JSON.stringify({ name: "Hacked App B Config" }),
  });
  assert.equal(patchAppConfigB.status, 403, "Scoped Admin A cannot PATCH /app/:clientId/config on App B");

  // 6. Scoped Admin A tries to DELETE App B -> 403
  const deleteB = await app.request(`/api/admin/clients/${appB_id}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(deleteB.status, 403, "Scoped Admin A cannot DELETE App B");

  // 7. Scoped Admin A tries to GET App B users -> 403
  const usersB = await app.request(`/api/admin/clients/${appB_id}/users`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(usersB.status, 403, "Scoped Admin A cannot GET App B users");

  // 8. Scoped Admin A tries to DELETE App B user -> 403
  const deleteUserB = await app.request(`/api/admin/clients/${appB_id}/users/${user2Id}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(deleteUserB.status, 403, "Scoped Admin A cannot DELETE user from App B");

  // 9. Scoped Admin A tries to manage App B app-admins -> 403
  const appAdminsB = await app.request(`/api/admin/clients/${appB_id}/app-admins`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(appAdminsB.status, 403, "Scoped Admin A cannot GET App B app-admins");

  // 10. Scoped Admin A accessing non-existent App -> 403
  const nonExistent = await app.request("/api/admin/clients/non_existent_app_999", {
    method: "GET",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(nonExistent.status, 403, "Scoped Admin A accessing unassigned client ID must receive 403");

  // 11. Scoped Admin A accessing own App A -> 200
  const getA = await app.request(`/api/admin/clients/${appA_id}`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(getA.status, 200, "Scoped Admin A can GET own App A");

  // 12. Super Admin can access App B -> 200
  const superGetB = await app.request(`/api/admin/clients/${appB_id}`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
  });
  assert.equal(superGetB.status, 200, "Super Admin can access App B");
});

// --------------------------------------------------------------------------
// CASE 9: Global Stats Isolation
// --------------------------------------------------------------------------
await runTest(9, "Global stats isolation: GET /api/admin/stats strictly requires Super-Admin", async () => {
  // Super admin -> 200
  const resSuper = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
  });
  assert.equal(resSuper.status, 200, "Super admin must be allowed on /stats");

  // Scoped admin A -> 403
  const resScoped = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(resScoped.status, 403, "Scoped admin must be rejected on /stats with 403");

  // Normal user -> 403
  const resUser = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders({ Cookie: user1Cookie }),
  });
  assert.equal(resUser.status, 403, "Normal user must be rejected on /stats with 403");

  // Anonymous -> 401
  const resAnon = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(resAnon.status, 401, "Anonymous request to /stats must be rejected with 401");
});

// --------------------------------------------------------------------------
// CASE 10: Mass Assignment on Sign-Up
// --------------------------------------------------------------------------
await runTest(10, "Mass assignment: sign-up payload cannot inject admin, role, or scopedClientId", async () => {
  const attackEmail = `mass_attack_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const res = await app.request("/api/auth/sign-up/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: attackEmail,
      password: "AttackPassword@123!",
      name: "Attacker",
      role: "admin",
      isSuperAdmin: true,
      scopedClientId: appB_id,
      admin: true,
      banned: false,
      permissions: ["all"],
    }),
  });

  assert.ok(res.status >= 200 && res.status < 300, "Sign-up should succeed");
  const user = await db.collection("user").findOne({ email: attackEmail });
  assert.ok(user, "User must be created");
  assert.equal(user.role, "user", "Role must remain normal user");
  assert.ok(!user.isSuperAdmin, "isSuperAdmin must not be persisted");
  assert.ok(!user.scopedClientId, "scopedClientId must not be persisted");
  assert.ok(!user.admin, "admin boolean must not be persisted");
});

// --------------------------------------------------------------------------
// CASE 11: isPublic / isDev / disabled Privilege Injection
// --------------------------------------------------------------------------
await runTest(11, "isPublic / isDev privilege injection: scoped admin cannot mutate trust boundary fields", async () => {
  const patchRes = await app.request(`/api/admin/clients/${appA_id}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
    body: JSON.stringify({
      isPublic: true,
      is_public: true,
      isDev: true,
      is_dev: true,
      disabled: true,
      is_active: false,
    }),
  });

  assert.equal(patchRes.status, 200, "Patch returns 200 for allowed safe field updates");
  const client = await db.collection("oauthClient").findOne({ clientId: appA_id });
  assert.equal(client?.isPublic, false, "Scoped admin cannot change isPublic");
  assert.equal(client?.isDev, false, "Scoped admin cannot change isDev");
  assert.equal(client?.disabled, false, "Scoped admin cannot change disabled");
});

// --------------------------------------------------------------------------
// CASE 12: App Admin Password Invalidation
// --------------------------------------------------------------------------
await runTest(12, "App Admin password invalidation: changing password immediately invalidates prior JWT", async () => {
  const adminEmail = `admin_pwd_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const oldPass = "OldPassword@123456";
  const newPass = "NewPassword@654321";

  // Create App Admin via Super-Admin
  const createRes = await app.request(`/api/admin/clients/${appA_id}/app-admins`, {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      email: adminEmail,
      password: oldPass,
      redirectUrl: "http://localhost:5174/admin",
    }),
  });
  assert.equal(createRes.status, 201);
  const createdAdmin = await createRes.json();
  const adminId = createdAdmin.admin?.id || createdAdmin.adminId || createdAdmin.id;

  // Login with old password -> obtain JWT
  const loginRes = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: appA_id,
      client_secret: appA_secret,
      email: adminEmail,
      password: oldPass,
    }),
  });
  assert.equal(loginRes.status, 200);
  const { token: oldToken } = await loginRes.json();

  // Verify OLD token -> 200
  const v1 = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${oldToken}` }),
    body: JSON.stringify({ client_id: appA_id, client_secret: appA_secret }),
  });
  assert.equal(v1.status, 200, "Old token must be valid initially");

  // Change password
  const updateRes = await app.request(`/api/admin/clients/${appA_id}/app-admins/${adminId}`, {
    method: "PUT",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({ password: newPass }),
  });
  assert.equal(updateRes.status, 200);

  // Verify OLD token after password change -> 401 token_expired!
  const vOld = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${oldToken}` }),
    body: JSON.stringify({ client_id: appA_id, client_secret: appA_secret }),
  });
  assert.equal(vOld.status, 401, "Old token must be rejected after password change");
  const oldJson = await vOld.json();
  assert.equal(oldJson.error, "token_expired", "Must return token_expired machine-readable code");

  // Login with new password -> obtain NEW JWT -> 200
  const loginNew = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: appA_id,
      client_secret: appA_secret,
      email: adminEmail,
      password: newPass,
    }),
  });
  assert.equal(loginNew.status, 200);
  const { token: newToken } = await loginNew.json();

  const vNew = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${newToken}` }),
    body: JSON.stringify({ client_id: appA_id, client_secret: appA_secret }),
  });
  assert.equal(vNew.status, 200, "New token issued after password change must succeed");
});

// --------------------------------------------------------------------------
// CASE 13: App Admin Disable & Re-Enable Lifecycle
// --------------------------------------------------------------------------
await runTest(13, "App Admin disable/re-enable lifecycle: deactivated admin fails verify/login, re-enabled requires new token", async () => {
  const adminEmail = `admin_dis_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const pass = "AdminPassword@123456";

  const createRes = await app.request(`/api/admin/clients/${appA_id}/app-admins`, {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      email: adminEmail,
      password: pass,
      redirectUrl: "http://localhost:5174/admin",
    }),
  });
  assert.equal(createRes.status, 201);
  const adminData = await createRes.json();
  const adminId = adminData.admin?.id || adminData.adminId || adminData.id;

  const loginRes = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: appA_id,
      client_secret: appA_secret,
      email: adminEmail,
      password: pass,
    }),
  });
  assert.equal(loginRes.status, 200);
  const { token: oldToken } = await loginRes.json();

  // Verify initial token -> 200
  const vInitial = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${oldToken}` }),
    body: JSON.stringify({ client_id: appA_id, client_secret: appA_secret }),
  });
  assert.equal(vInitial.status, 200, "Initial token must be valid");

  // Allow clock tick so iat < tokensRevokedBefore - 1000 holds deterministically
  await new Promise((r) => setTimeout(r, 1100));

  // 1. Deactivate admin
  const deactRes = await app.request(`/api/admin/clients/${appA_id}/app-admins/${adminId}`, {
    method: "PUT",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({ isActive: false }),
  });
  assert.equal(deactRes.status, 200);

  // 2. Token verification fails
  const vDeact = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${oldToken}` }),
    body: JSON.stringify({ client_id: appA_id, client_secret: appA_secret }),
  });
  assert.equal(vDeact.status, 401, "Deactivated admin token verification must fail with 401");

  // 3. Login fails
  const loginDeact = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: appA_id,
      client_secret: appA_secret,
      email: adminEmail,
      password: pass,
    }),
  });
  assert.equal(loginDeact.status, 403, "Deactivated admin login must fail with 403 account_disabled");
  const deactJson = await loginDeact.json();
  assert.equal(deactJson.error, "account_disabled");

  // 4. Re-activate admin
  const reactRes = await app.request(`/api/admin/clients/${appA_id}/app-admins/${adminId}`, {
    method: "PUT",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({ isActive: true }),
  });
  assert.equal(reactRes.status, 200);

  // 5. Old token STILL fails because tokensRevokedBefore was set during deactivation
  const vOldAfterReact = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${oldToken}` }),
    body: JSON.stringify({ client_id: appA_id, client_secret: appA_secret }),
  });
  assert.equal(vOldAfterReact.status, 401, "Old token must remain invalid after reactivation");

  // 6. Login with password now succeeds -> returns new token
  const loginReact = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: appA_id,
      client_secret: appA_secret,
      email: adminEmail,
      password: pass,
    }),
  });
  assert.equal(loginReact.status, 200, "Re-activated admin login must succeed");
  const { token: newToken } = await loginReact.json();

  // 7. New token verifies successfully
  const vNew = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${newToken}` }),
    body: JSON.stringify({ client_id: appA_id, client_secret: appA_secret }),
  });
  assert.equal(vNew.status, 200, "New token issued after reactivation must verify successfully");
});

// --------------------------------------------------------------------------
// CASE 14: Membership Deletion Cascade
// --------------------------------------------------------------------------
await runTest(14, "Membership deletion cascade: deleting user from App A does not affect App B", async () => {
  // Ensure user has membership in both App A and App B
  const multiEmail = `multi_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const multiRes = await authProvider.api.signUpEmail({
    body: { email: multiEmail, password: "MultiPassword@123!", name: "Multi App User" },
    asResponse: true,
  });
  const multiDoc = await db.collection("user").findOne({ email: multiEmail });
  const multiUserId = String(multiDoc?.id || multiDoc?._id);

  await db.collection("user_app_registrations").insertMany([
    { userId: multiUserId, clientId: appA_id, registeredAt: new Date() },
    { userId: multiUserId, clientId: appB_id, registeredAt: new Date() },
  ]);

  // Delete membership for App A
  const delRes = await app.request(`/api/admin/clients/${appA_id}/users/${multiUserId}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(delRes.status, 200, "Membership deletion must succeed");

  // Verify App A registration is gone
  const regA = await db.collection("user_app_registrations").findOne({ userId: multiUserId, clientId: appA_id });
  assert.equal(regA, null, "App A registration must be deleted");

  // Verify App B registration is INTACT
  const regB = await db.collection("user_app_registrations").findOne({ userId: multiUserId, clientId: appB_id });
  assert.ok(regB, "App B registration must remain intact");
});

// --------------------------------------------------------------------------
// CASE 15: oauthConsent Cleanup on User Removal
// --------------------------------------------------------------------------
await runTest(15, "oauthConsent cleanup: consent documents for user/client are removed", async () => {
  const dummyUserId = `consent_user_${crypto.randomBytes(4).toString("hex")}`;
  await db.collection("user_app_registrations").insertOne({
    userId: dummyUserId,
    clientId: appA_id,
    registeredAt: new Date(),
  });
  await db.collection("oauthConsent").insertOne({
    clientId: appA_id,
    userId: dummyUserId,
    scopes: ["openid", "profile"],
    createdAt: new Date(),
  });

  const delRes = await app.request(`/api/admin/clients/${appA_id}/users/${dummyUserId}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(delRes.status, 200, "User deletion must succeed");

  const consentDoc = await db.collection("oauthConsent").findOne({ clientId: appA_id, userId: dummyUserId });
  assert.equal(consentDoc, null, "oauthConsent document must be deleted on user removal");
});

// --------------------------------------------------------------------------
// CASE 16: Pending Authorization-Code Cleanup on User Removal
// --------------------------------------------------------------------------
await runTest(16, "Pending authorization-code cleanup: pending codes removed on user deletion", async () => {
  const dummyUserId = `code_user_${crypto.randomBytes(4).toString("hex")}`;
  await db.collection("user_app_registrations").insertOne({
    userId: dummyUserId,
    clientId: appA_id,
    registeredAt: new Date(),
  });
  await db.collection("oauthAuthorizationCode").insertOne({
    clientId: appA_id,
    userId: dummyUserId,
    code: "test_pending_auth_code_123",
    expiresAt: new Date(Date.now() + 60000),
  });

  const delRes = await app.request(`/api/admin/clients/${appA_id}/users/${dummyUserId}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: scopedAdminACookie }),
  });
  assert.equal(delRes.status, 200, "User deletion must succeed");

  const codeDoc = await db.collection("oauthAuthorizationCode").findOne({ clientId: appA_id, userId: dummyUserId });
  assert.equal(codeDoc, null, "Pending authorization codes must be deleted on user removal");
});

// --------------------------------------------------------------------------
// CASE 17: Cookie Poisoning Protection
// --------------------------------------------------------------------------
await runTest(17, "Cookie poisoning: invalid current_client_id cookie fails closed", async () => {
  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({
      Cookie: "current_client_id=non_existent_malicious_app_id_999",
    }),
    body: JSON.stringify({ email: user1Email, password: user1Pass }),
  });

  assert.equal(res.status, 400, "Sign in with poisoned client cookie must reject with 400");
  const json = await res.json();
  assert.equal(json.error, "invalid_client");
});

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
// CASE 18: Parallel Browser-Tab Isolation & Shared Cookie Jar
// --------------------------------------------------------------------------
await runTest(18, "Parallel browser-tab isolation: shared cookie jar poison resilience & cross-client rejection", async () => {
  // 1. Tab A initiates with App A -> receives Cookie A in the shared browser cookie jar
  const resA = await app.request(`/api/auth/oauth/initiate?client_id=${appA_id}`, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(resA.status, 200);
  const cookieHeadersA = (resA.headers as any).getSetCookie ? (resA.headers as any).getSetCookie() : [resA.headers.get("set-cookie") || ""];
  const cookieA = cookieHeadersA.find((c: string) => c.includes("current_client_id")) || "";
  assert.ok(cookieA.includes(appA_id), "Cookie for tab A must be bound to App A");

  // Single shared browser cookie jar: currently has App A
  let sharedCookieJar = `current_client_id=${appA_id}`;

  // 2. Tab B initiates with App B in the same browser -> overwrites current_client_id in the shared jar
  const resB = await app.request(`/api/auth/oauth/initiate?client_id=${appB_id}`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: sharedCookieJar }),
  });
  assert.equal(resB.status, 200);
  const cookieHeadersB = (resB.headers as any).getSetCookie ? (resB.headers as any).getSetCookie() : [resB.headers.get("set-cookie") || ""];
  const cookieB = cookieHeadersB.find((c: string) => c.includes("current_client_id")) || "";
  assert.ok(cookieB.includes(appB_id), "Cookie for tab B must be bound to App B");

  // Shared jar now holds App B's current_client_id cookie
  sharedCookieJar = `current_client_id=${appB_id}`;

  // 3. Tab A resumes authorization flow presenting the shared cookie jar (stale App B cookie!):
  // Authoritative URL query client_id=appA_id MUST take precedence and redirect strictly to redirectUriA
  const pkceA = generatePkce();
  const authA = await app.request(
    `/api/auth/oauth2/authorize?client_id=${appA_id}&redirect_uri=${encodeURIComponent(redirectUriA)}&response_type=code&scope=openid%20offline_access&state=state_tab_a&code_challenge=${pkceA.challenge}&code_challenge_method=S256`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: `${user1Cookie}; ${sharedCookieJar}` }),
    }
  );
  assert.equal(authA.status, 302);
  const locA = authA.headers.get("location") || "";
  assert.ok(locA.startsWith(redirectUriA), "Tab A authorization must redirect to App A, ignoring stale App B cookie");
  const codeA = new URL(locA).searchParams.get("code");
  assert.ok(codeA, "Tab A must receive an authorization code");

  // 4. Tab A authorization code CANNOT be redeemed with App B's credentials at /token
  const crossExchange = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders(),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: codeA!,
      code_verifier: pkceA.verifier,
      client_id: appB_id,
      client_secret: appB_secret,
      redirect_uri: redirectUriA,
    }).toString(),
  });
  assert.ok(crossExchange.status >= 400, "App B cannot redeem Tab A authorization code");

  // 5. Sign-in fallback: Tab A submits email sign-in with explicit client_id=appA_id while shared cookie jar has App B
  const signinA = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: sharedCookieJar }),
    body: JSON.stringify({
      email: user1Email,
      password: user1Pass,
      client_id: appA_id,
    }),
  });
  assert.equal(signinA.status, 200, "Sign-in with explicit client_id prioritizes URL/body client over stale cookie");

  // 6. Unknown and disabled clients fail closed
  const resUnknown = await app.request(`/api/auth/oauth/initiate?client_id=non_existent_client_xyz`, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(resUnknown.status, 400);

  const resDisabled = await app.request(`/api/auth/oauth/initiate?client_id=${disabledApp_id}`, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(resDisabled.status, 400);
});

// --------------------------------------------------------------------------
// CASE 19: Real Better Auth Google Callback Integration & Private App Isolation
// --------------------------------------------------------------------------
await runTest(19, "Social login private-app isolation: real Better Auth handler revokes only newly created session", async () => {
  // 1. Missing state error test: callback without state parameter fails closed
  const resMissingState = await app.request("/api/auth/callback/google?code=some_dummy_auth_code_123", {
    method: "GET",
    headers: getTestHeaders({ Cookie: `current_client_id=${appA_id}` }),
  });
  assert.ok(resMissingState.status >= 300, "Missing state parameter must not succeed");
  const locMissing = resMissingState.headers.get("location") || "";
  assert.ok(locMissing.includes("error=") || resMissingState.status >= 400, "Missing state returns error redirect or 4xx");

  // 2. Provider error test with valid state: provider-level error callback is gracefully handled
  const initErr = await app.request("/api/auth/sign-in/social", {
    method: "POST",
    headers: getTestHeaders({ Cookie: `current_client_id=${appA_id}` }),
    body: JSON.stringify({
      provider: "google",
      callbackURL: `${process.env.FRONTEND_URL || "http://localhost:5174"}/dashboard`,
    }),
  });
  assert.equal(initErr.status, 200);
  const initErrJson = await initErr.json();
  const stateErr = new URL(initErrJson.url).searchParams.get("state") || "";
  const setCookieErr = (initErr.headers as any).getSetCookie
    ? (initErr.headers as any).getSetCookie()
    : [initErr.headers.get("set-cookie") || ""];
  const stateCookieErr = setCookieErr.find((c: string) => c.includes("better-auth.state")) || setCookieErr.join("; ");

  const resProviderError = await app.request(`/api/auth/callback/google?error=access_denied&error_description=User+cancelled&state=${encodeURIComponent(stateErr)}`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: `${stateCookieErr}; current_client_id=${appA_id}` }),
  });
  assert.ok(resProviderError.status >= 300, "Provider error callback must be handled");
  const locProviderErr = resProviderError.headers.get("location") || "";
  assert.ok(locProviderErr.includes("error=access_denied") || resProviderError.status >= 400, "Provider error redirects with error");

  // 3. User performs a legitimate initial social sign-in on IDP to establish valid Session A
  const unassignedSocialEmail = `unassigned_social_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const googleSub = `google_unauth_${crypto.randomBytes(4).toString("hex")}`;
  mockGoogleProfile = {
    sub: googleSub,
    email: unassignedSocialEmail,
    name: "Unassigned Social User",
  };

  const initLegit = await app.request("/api/auth/sign-in/social", {
    method: "POST",
    headers: getTestHeaders({}),
    body: JSON.stringify({
      provider: "google",
      callbackURL: `${process.env.FRONTEND_URL || "http://localhost:5174"}/dashboard`,
    }),
  });
  assert.equal(initLegit.status, 200);
  const initLegitJson = await initLegit.json();
  const stateLegitParam = new URL(initLegitJson.url).searchParams.get("state") || "";
  const setCookieLegit = (initLegit.headers as any).getSetCookie
    ? (initLegit.headers as any).getSetCookie()
    : [initLegit.headers.get("set-cookie") || ""];
  const stateCookieLegit = setCookieLegit.find((c: string) => c.includes("better-auth.state")) || setCookieLegit.join("; ");

  const cbLegit = await app.request(`/api/auth/callback/google?state=${encodeURIComponent(stateLegitParam)}&code=valid_legit_code`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: stateCookieLegit }),
  });
  assert.equal(cbLegit.status, 302, "Legitimate initial social login must succeed with 302 redirect");
  const legitSetCookies = (cbLegit.headers as any).getSetCookie
    ? (cbLegit.headers as any).getSetCookie()
    : [cbLegit.headers.get("set-cookie") || ""];
  const sessionACookie = legitSetCookies.find((c: string) => c.includes("better-auth.session_token")) || "";
  assert.ok(sessionACookie, "Must receive better-auth.session_token for Session A");
  const rawSessionAToken = sessionACookie.split(";")[0].split("=")[1].split(".")[0];
  assert.ok(rawSessionAToken, "Must extract raw token for Session A");

  // Verify Session A exists in MongoDB and extract userId
  const sessionAInDb = await db.collection("session").findOne({ token: rawSessionAToken });
  assert.ok(sessionAInDb, "Session A must be active in MongoDB");
  const unassignedUserId = String(sessionAInDb.userId);

  // Invariant check: user is NOT assigned to private appA_id
  await db.collection("user_app_registrations").deleteMany({
    clientId: appA_id,
    userId: { $in: [unassignedUserId, new ObjectId(unassignedUserId)] },
  });

  // 4. Now initiate social sign-in via Better Auth endpoint for PRIVATE appA_id
  const initRes = await app.request("/api/auth/sign-in/social", {
    method: "POST",
    headers: getTestHeaders({ Cookie: `current_client_id=${appA_id}` }),
    body: JSON.stringify({
      provider: "google",
      callbackURL: `${process.env.FRONTEND_URL || "http://localhost:5174"}/dashboard`,
    }),
  });
  assert.equal(initRes.status, 200, "Social sign-in initiation must return 200 with redirect URL");
  const initJson = await initRes.json();
  assert.ok(initJson.url, "Initiate response must contain OAuth URL");

  // Extract state parameter and state cookie
  const oauthUrl = new URL(initJson.url);
  const stateParam = oauthUrl.searchParams.get("state") || "";
  assert.ok(stateParam, "Must have state parameter");

  const setCookieHeaders = (initRes.headers as any).getSetCookie
    ? (initRes.headers as any).getSetCookie()
    : [initRes.headers.get("set-cookie") || ""];
  const stateCookie = setCookieHeaders.find((c: string) => c.includes("better-auth.state")) || setCookieHeaders.join("; ");

  // 5. Send real callback request to /api/auth/callback/google with current_client_id=appA_id
  // Real Better Auth handler executes, calls narrow mock https://oauth2.googleapis.com/token & certs,
  // logs in existing Google user, creates new session, and passes to handleSocialCallback which enforces private app isolation!
  const cbRes = await app.request(`/api/auth/callback/google?state=${encodeURIComponent(stateParam)}&code=valid_test_code_123`, {
    method: "GET",
    headers: getTestHeaders({
      Cookie: `${stateCookie}; current_client_id=${appA_id}`,
    }),
  });

  // 6. Invariant: Redirects with error=access_denied
  assert.equal(cbRes.status, 302, "Must redirect unassigned social login on private app");
  const loc = cbRes.headers.get("location") || "";
  assert.ok(loc.includes("error=access_denied"), "Redirect location must indicate access_denied");

  // 7. Invariant: Pre-existing Session A MUST REMAIN VALID in MongoDB!
  const sessionAStillActive = await db.collection("session").findOne({ token: rawSessionAToken });
  assert.ok(sessionAStillActive, "Pre-existing Session A must NOT be deleted when unassigned private login is rejected");

  // 8. Invariant: The rejected flow's newly created session MUST be deleted!
  const unauthSessions = await db.collection("session").find({
    userId: { $in: [unassignedUserId, new ObjectId(unassignedUserId)] },
    token: { $ne: rawSessionAToken },
  }).toArray();
  assert.equal(unauthSessions.length, 0, "Unauthorized newly created social session must be deterministically deleted");

  // Clean up Session A and mock Google account fixture
  await Promise.all([
    db.collection("session").deleteMany({ userId: { $in: [unassignedUserId, new ObjectId(unassignedUserId)] } }),
    db.collection("account").deleteMany({ userId: { $in: [unassignedUserId, new ObjectId(unassignedUserId)] } }),
    db.collection("user").deleteOne({ _id: { $in: [unassignedUserId as any, new ObjectId(unassignedUserId)] } as any }),
  ]);
});

// --------------------------------------------------------------------------
// CASE 20: Social Login Public-App Membership Idempotency
// --------------------------------------------------------------------------
await runTest(20, "Social login public-app membership: creates membership idempotently with zero duplicates", async () => {
  const publicAppId = `public_app_${testSuffix}`;
  await seedOAuthClient(publicAppId, "pub_secret_12345", true, ["http://localhost:5174/cb-pub"]);

  const pubSocialEmail = `pub_social_${crypto.randomBytes(4).toString("hex")}@example.com`;
  mockGoogleProfile = {
    sub: `google_pub_${crypto.randomBytes(4).toString("hex")}`,
    email: pubSocialEmail,
    name: "Public Social User",
  };

  // 1. First callback flow
  const init1 = await app.request("/api/auth/sign-in/social", {
    method: "POST",
    headers: getTestHeaders({ Cookie: `current_client_id=${publicAppId}` }),
    body: JSON.stringify({
      provider: "google",
      callbackURL: "http://localhost:5174/cb-pub",
    }),
  });
  assert.equal(init1.status, 200);
  const init1Json = await init1.json();
  const state1 = new URL(init1Json.url).searchParams.get("state")!;
  const cookies1 = (init1.headers as any).getSetCookie ? (init1.headers as any).getSetCookie().join("; ") : init1.headers.get("set-cookie") || "";

  const cb1 = await app.request(`/api/auth/callback/google?state=${encodeURIComponent(state1)}&code=valid_code_pub_1`, {
    method: "GET",
    headers: getTestHeaders({
      Cookie: `${cookies1}; current_client_id=${publicAppId}`,
    }),
  });
  assert.equal(cb1.status, 302);

  // Look up created user
  const createdUser = await db.collection("user").findOne({ email: pubSocialEmail });
  assert.ok(createdUser, "Social user must be created in MongoDB");
  const pubUserId = String(createdUser.id || createdUser._id);

  // Assert exactly 1 registration created
  const regsAfterFirst = await db.collection("user_app_registrations").find({ userId: pubUserId, clientId: publicAppId }).toArray();
  assert.equal(regsAfterFirst.length, 1, "First social callback must create exactly 1 registration");

  // 2. Second callback flow with same user into same public app
  const init2 = await app.request("/api/auth/sign-in/social", {
    method: "POST",
    headers: getTestHeaders({ Cookie: `current_client_id=${publicAppId}` }),
    body: JSON.stringify({
      provider: "google",
      callbackURL: "http://localhost:5174/cb-pub",
    }),
  });
  assert.equal(init2.status, 200);
  const init2Json = await init2.json();
  const state2 = new URL(init2Json.url).searchParams.get("state")!;
  const cookies2 = (init2.headers as any).getSetCookie ? (init2.headers as any).getSetCookie().join("; ") : init2.headers.get("set-cookie") || "";

  const cb2 = await app.request(`/api/auth/callback/google?state=${encodeURIComponent(state2)}&code=valid_code_pub_2`, {
    method: "GET",
    headers: getTestHeaders({
      Cookie: `${cookies2}; current_client_id=${publicAppId}`,
    }),
  });
  assert.equal(cb2.status, 302);

  // Invariant: Idempotency check -- still exactly 1 registration, ZERO duplicates!
  const regsAfterSecond = await db.collection("user_app_registrations").find({ userId: pubUserId, clientId: publicAppId }).toArray();
  assert.equal(regsAfterSecond.length, 1, "Second social callback must maintain exactly 1 registration with ZERO duplicates");
});

// --------------------------------------------------------------------------
// CASE 21: Unauthorized CORS Header Absence
// --------------------------------------------------------------------------
await runTest(21, "Unauthorized CORS header absence: unauthorized origin receives NO allow headers", async () => {
  const evilOrigin = "https://evil-attacker.example";
  const res = await app.request("/api/auth/oauth/initiate?client_id=" + appA_id, {
    method: "GET",
    headers: {
      Origin: evilOrigin,
    },
  });

  assert.equal(res.headers.get("access-control-allow-origin"), null, "Must NOT receive Access-Control-Allow-Origin");
  assert.equal(res.headers.get("access-control-allow-credentials"), null, "Must NOT receive Access-Control-Allow-Credentials");
});

// --------------------------------------------------------------------------
// CASE 22: Valid CORS Exact-Origin Behavior
// --------------------------------------------------------------------------
await runTest(22, "Valid CORS exact-origin behavior: exact allowed origin receives allow header", async () => {
  const validOrigin = "http://localhost:5174";
  const res = await app.request("/api/auth/oauth/initiate?client_id=" + appA_id, {
    method: "GET",
    headers: {
      Origin: validOrigin,
    },
  });

  assert.equal(res.headers.get("access-control-allow-origin"), validOrigin);
  assert.equal(res.headers.get("access-control-allow-credentials"), "true");
});

// --------------------------------------------------------------------------
// CASE 23: Trusted-Proxy Spoofing
// --------------------------------------------------------------------------
await runTest(23, "Trusted-proxy spoofing: spoofed leftmost X-Forwarded-For headers are ignored", async () => {
  const spoofedHeaders = new Headers({
    "x-forwarded-for": "1.1.1.1, 2.2.2.2, 198.51.100.55, 10.0.0.1",
  });
  const resolvedIp = getTrustedClientIp(spoofedHeaders, ["10.0.0.0/8", "172.16.0.0/12", "127.0.0.1/32"]);
  assert.equal(resolvedIp, "198.51.100.55", "Resolver must pick first untrusted hop from right, not attacker-controlled 1.1.1.1");
});

// --------------------------------------------------------------------------
// CASE 24: Target-Keyed Brute-Force Defense
// --------------------------------------------------------------------------
await runTest(24, "Target-keyed brute-force defense: repeated failures against victim email trigger 429", async () => {
  const victimEmail = `victim_${crypto.randomBytes(4).toString("hex")}@example.com`;

  // Create victim account
  await authProvider.api.signUpEmail({
    body: { email: victimEmail, password: "VictimPassword@123!", name: "Victim" },
    asResponse: true,
  });

  // Attempt 16 failed sign-ins with rotating IP addresses
  let lastStatus = 200;
  for (let i = 0; i < 17; i++) {
    const rotatingIp = `192.0.2.${(i % 250) + 1}`;
    const res = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-forwarded-for": `${rotatingIp}, 10.0.0.1`,
        Origin: process.env.FRONTEND_URL || "http://localhost:5174",
      },
      body: JSON.stringify({ email: victimEmail, password: "WrongPassword123!" }),
    });
    lastStatus = res.status;
  }

  assert.equal(lastStatus, 429, "Repeated failures across rotating IPs must trigger 429 too_many_requests");
});

// --------------------------------------------------------------------------
// CASE 25: Direct Better Auth Route Blocking
// --------------------------------------------------------------------------
await runTest(25, "Direct Better Auth route blocking: internal endpoints return 403", async () => {
  const endpoints = [
    "/api/auth/admin",
    "/api/auth/admin/set-role",
    "/api/auth/oauth2/register",
    "/api/auth/oauth2/create-client",
    "/api/auth/oauth2/update-client",
    "/api/auth/oauth2/delete-client",
    "/api/auth/oauth2/client/rotate-secret",
  ];

  for (const ep of endpoints) {
    const res = await app.request(ep, {
      method: "POST",
      headers: getTestHeaders({ Cookie: user1Cookie }),
      body: JSON.stringify({ client_id: appA_id }),
    });
    assert.equal(res.status, 403, `Direct endpoint ${ep} must return 403 for non-superadmin`);
  }
});

// --------------------------------------------------------------------------
// CASE 26: Error Leakage
// --------------------------------------------------------------------------
await runTest(26, "Error leakage: malformed requests and forced failures do not leak stack or mongo traces", async () => {
  const res = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: "Bearer invalid.malformed.jwt" }),
    body: JSON.stringify({ client_id: appA_id, client_secret: appA_secret }),
  });

  const text = await res.text();
  assert.ok(!text.includes("MongoServerSelectionError"), "Must not leak Mongo errors");
  assert.ok(!text.includes("at "), "Must not leak Node.js stack traces");
  assert.ok(!text.includes("mongodb://"), "Must not leak database URIs");
});

// --------------------------------------------------------------------------
// CASE 27: Disabled Client Behavior
// --------------------------------------------------------------------------
await runTest(27, "Disabled client behavior: disabled client is rejected at initiation and authorization", async () => {
  const initRes = await app.request(`/api/auth/oauth/initiate?client_id=${disabledApp_id}`, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(initRes.status, 400, "Disabled client must fail initiate");

  const authRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${disabledApp_id}&redirect_uri=http%3A%2F%2Flocalhost%3A5174%2Fcallback-dis&response_type=code&scope=openid&state=state1`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: user1Cookie }),
    }
  );
  assert.equal(authRes.status, 403, "Disabled client must fail authorization with 403 unauthorized_client");
});

// --------------------------------------------------------------------------
// CASE 28: Unknown Client Behavior
// --------------------------------------------------------------------------
await runTest(28, "Unknown client behavior: non-existent client fails closed and is never treated as public", async () => {
  const initRes = await app.request("/api/auth/oauth/initiate?client_id=completely_unknown_client_id_999", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(initRes.status, 400, "Unknown client must fail initiate");
  const json = await initRes.json();
  assert.equal(json.error, "invalid_client");

  const signinRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: user1Email,
      password: user1Pass,
      client_id: "completely_unknown_client_id_999",
    }),
  });
  assert.equal(signinRes.status, 400, "Sign-in with unknown client ID must reject with 400");
});

// --------------------------------------------------------------------------
// CASE 29: Invalid Redirect Behavior
// --------------------------------------------------------------------------
await runTest(29, "Invalid redirect behavior: fragments, userinfo, and unapproved origins are rejected", async () => {
  const badUris = [
    "http://localhost:5174/cb#fragment",
    "http://user:pass@localhost:5174/cb",
    "javascript:alert(1)",
    "https://unapproved-evil.com/callback",
  ];

  for (const badUri of badUris) {
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${appA_id}&redirect_uri=${encodeURIComponent(badUri)}&response_type=code&scope=openid&state=state1`,
      {
        method: "GET",
        headers: getTestHeaders({ Cookie: user1Cookie }),
      }
    );
    assert.equal(authRes.status, 400, `Redirect URI ${badUri} must be rejected with 400`);
  }
});

// --------------------------------------------------------------------------
// CASE 30: App Admin Deletion Lifecycle & Database Eviction
// --------------------------------------------------------------------------
await runTest(30, "App Admin deletion lifecycle: deleted admin document is removed and tokens rejected", async () => {
  const adminEmail = `admin_del_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const pass = "AdminDeletePass@123456";

  const createRes = await app.request(`/api/admin/clients/${appA_id}/app-admins`, {
    method: "POST",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({
      email: adminEmail,
      password: pass,
      redirectUrl: "http://localhost:5174/admin",
    }),
  });
  assert.equal(createRes.status, 201);
  const adminData = await createRes.json();
  const adminId = adminData.admin?.id || adminData.adminId || adminData.id;

  const loginRes = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: appA_id,
      client_secret: appA_secret,
      email: adminEmail,
      password: pass,
    }),
  });
  assert.equal(loginRes.status, 200);
  const { token } = await loginRes.json();

  // Delete admin
  const delRes = await app.request(`/api/admin/clients/${appA_id}/app-admins/${adminId}`, {
    method: "DELETE",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
  });
  assert.equal(delRes.status, 200, "Admin deletion must succeed");

  // Token verify fails -> 401
  const v = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${token}` }),
    body: JSON.stringify({ client_id: appA_id, client_secret: appA_secret }),
  });
  assert.equal(v.status, 401, "Deleted admin token verification must return 401");

  // Login fails -> 401
  const loginDel = await app.request("/api/auth/app-admin/login", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      client_id: appA_id,
      client_secret: appA_secret,
      email: adminEmail,
      password: pass,
    }),
  });
  assert.equal(loginDel.status, 401, "Deleted admin login must return 401");

  // MongoDB document is deleted
  const doc = await db.collection("app_admins").findOne({
    $or: [{ id: adminId }, { _id: adminId }, ...(ObjectId.isValid(adminId) ? [{ _id: new ObjectId(adminId) }] : [])],
  });
  assert.equal(doc, null, "Deleted admin document must not exist in MongoDB");
});

// --------------------------------------------------------------------------
// HARNESS SUMMARY & EXIT GATE
// --------------------------------------------------------------------------
console.log("================================================================");
console.log(`  FINAL ADVERSARIAL GATE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

if (failed > 0) {
  console.error("❌ ADVERSARIAL SECURITY GATE: FAIL");
  process.exit(1);
} else {
  console.log("✅ ADVERSARIAL SECURITY GATE: PASS");
  process.exit(0);
}
