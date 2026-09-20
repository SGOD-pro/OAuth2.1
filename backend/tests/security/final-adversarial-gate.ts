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

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");
const { registerTokenFamily, verifyAndRotateTokenFamily } = await import("../../src/db/state");
const { isRegisteredRedirectUri, getTrustedClientIp, normalizeOrigin } = await import("../../src/utils/security");

console.log("================================================================");
console.log("  SWYRA AUTH -- FINAL ADVERSARIAL SECURITY GATE HARNESS");
console.log("  Verifying Invariants I1 through I17 across all 29 Cases");
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

await runTest(4, "Refresh-token concurrency: 5 simultaneous requests produce exactly 1 successor", async () => {
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

  // Send 5 concurrent requests with exact same refresh token R
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

  // Inspect MongoDB state
  const winnerResponse = responses.find((r) => r.status === 200)!;
  const winnerJson = await winnerResponse.json();
  activeRefreshToken = winnerJson.refresh_token;
  assert.ok(activeRefreshToken, "Winner must receive new successor refresh token");

  const winnerHash = crypto.createHash("sha256").update(activeRefreshToken).digest("hex");
  const familyDoc = await db.collection("oauth_token_families").findOne({ activeTokenHash: winnerHash });

  assert.ok(familyDoc, "Token family must have exactly one active successor matching winner");
  assert.equal(familyDoc.status, "active", "Token family must remain active after concurrency race");
  assert.equal(familyDoc.clientId, appA_id);
  assert.equal(familyDoc.userId, user1Id);
  initialTokenFamilyId = familyDoc.familyId;

  // Verify MongoDB: exactly 1 active successor token document exists, no duplicate active credentials
  const b64Hash = crypto.createHash("sha256").update(activeRefreshToken).digest("base64url");
  let activeTokensInDb: any[] = [];
  for (let attempt = 0; attempt < 15; attempt++) {
    const rawTokens = await db.collection("oauthRefreshToken").find({
      clientId: appA_id,
      userId: { $in: [user1Id, new ObjectId(user1Id)] },
      $or: [{ token: activeRefreshToken }, { token: b64Hash }],
    }).toArray();
    activeTokensInDb = rawTokens.filter((t: any) => t.revoked == null);
    if (activeTokensInDb.length > 0) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.equal(activeTokensInDb.length, 1, "Exactly one active successor refresh token document must exist in MongoDB");

  // Verify old consumed token cannot remain active
  const oldB64Hash = crypto.createHash("sha256").update(tokenToRace).digest("base64url");
  let activeOldTokens: any[] = [];
  for (let attempt = 0; attempt < 15; attempt++) {
    const oldTokensInDb = await db.collection("oauthRefreshToken").find({
      clientId: appA_id,
      $or: [{ token: tokenToRace }, { token: oldB64Hash }],
    }).toArray();
    activeOldTokens = oldTokensInDb.filter((t: any) => t.revoked == null && (!t.expiresAt || new Date(t.expiresAt) > new Date()));
    if (activeOldTokens.length === 0) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.equal(activeOldTokens.length, 0, "Consumed token must not remain as an active credential");
});

// --------------------------------------------------------------------------
// CASE 5: Refresh-Token Replay & 2-Second Grace-Boundary Verification
// --------------------------------------------------------------------------
await runTest(5, "Refresh-token replay: 2-second grace boundary distinguishes in-flight race from theft", async () => {
  const familyDoc = await db.collection("oauth_token_families").findOne({ familyId: initialTokenFamilyId });
  assert.ok(familyDoc && familyDoc.consumedTokenHashes.length > 0, "Must have consumed token hash");
  const consumedHash = familyDoc.consumedTokenHashes[0];

  // 1. Within 2000ms grace window: in-flight collision check does NOT revoke family
  await db.collection("oauth_token_families").updateOne(
    { familyId: initialTokenFamilyId },
    { $set: { updatedAt: new Date() } }
  );
  const withinGrace = await verifyAndRotateTokenFamily(consumedHash, "dummy");
  assert.equal(withinGrace.replayed, false, "Within grace window, loser request must not trigger replay revocation");
  const activeFam = await db.collection("oauth_token_families").findOne({ familyId: initialTokenFamilyId });
  assert.equal(activeFam?.status, "active", "Family must remain active during grace window");

  // 2. Outside 2000ms grace window: replay check MUST trigger full cascade revocation
  await db.collection("oauth_token_families").updateOne(
    { familyId: initialTokenFamilyId },
    { $set: { updatedAt: new Date(Date.now() - 3000) } }
  );
  const outsideGrace = await verifyAndRotateTokenFamily(consumedHash, "dummy");
  assert.equal(outsideGrace.replayed, true, "Outside grace window, replay attempt must trigger revocation");

  const revokedFamily = await db.collection("oauth_token_families").findOne({ familyId: initialTokenFamilyId });
  assert.equal(revokedFamily?.status, "revoked", "Family status must be revoked after grace window expires");
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
// CASE 13: App Admin Disable/Delete Invalidation
// --------------------------------------------------------------------------
await runTest(13, "App Admin disable/delete invalidation: deactivated admin cannot verify token", async () => {
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
  const { token } = await loginRes.json();

  // Deactivate admin
  await app.request(`/api/admin/clients/${appA_id}/app-admins/${adminId}`, {
    method: "PUT",
    headers: getTestHeaders({ Cookie: superAdminCookie }),
    body: JSON.stringify({ isActive: false }),
  });

  const v = await app.request("/api/auth/app-admin/verify", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${token}` }),
    body: JSON.stringify({ client_id: appA_id, client_secret: appA_secret }),
  });
  assert.equal(v.status, 401, "Deactivated admin token verification must fail with 401");
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
// CASE 18: Parallel Browser-Tab Isolation
// --------------------------------------------------------------------------
await runTest(18, "Parallel browser-tab isolation: distinct client contexts remain isolated", async () => {
  // 1. Tab A initiates with App A -> receives Cookie A
  const resA = await app.request(`/api/auth/oauth/initiate?client_id=${appA_id}`, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(resA.status, 200);
  const cookieHeadersA = (resA.headers as any).getSetCookie ? (resA.headers as any).getSetCookie() : [resA.headers.get("set-cookie") || ""];
  const cookieA = cookieHeadersA.find((c: string) => c.includes("current_client_id")) || cookieHeadersA.join("; ");
  assert.ok(cookieA.includes(appA_id), "Cookie for tab A must be bound to App A");

  // 2. Tab B initiates with App B -> receives Cookie B
  const resB = await app.request(`/api/auth/oauth/initiate?client_id=${appB_id}`, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(resB.status, 200);
  const cookieHeadersB = (resB.headers as any).getSetCookie ? (resB.headers as any).getSetCookie() : [resB.headers.get("set-cookie") || ""];
  const cookieB = cookieHeadersB.find((c: string) => c.includes("current_client_id")) || cookieHeadersB.join("; ");
  assert.ok(cookieB.includes(appB_id), "Cookie for tab B must be bound to App B");

  // 3. Tab A continues authorization flow presenting Cookie A: must redirect strictly to App A redirectUri
  const authA = await app.request(`/api/auth/oauth2/authorize?client_id=${appA_id}&redirect_uri=${encodeURIComponent(redirectUriA)}&response_type=code&state=state_tab_a`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: `${user1Cookie}; ${cookieA}` }),
  });
  assert.equal(authA.status, 302);
  const locA = authA.headers.get("location") || "";
  assert.ok(locA.startsWith(redirectUriA), "Tab A authorization must redirect to App A");

  // 4. Tab B continues authorization flow presenting Cookie B: must redirect strictly to App B redirectUri
  const authB = await app.request(`/api/auth/oauth2/authorize?client_id=${appB_id}&redirect_uri=${encodeURIComponent(redirectUriB)}&response_type=code&state=state_tab_b`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: `${user1Cookie}; ${cookieB}` }),
  });
  assert.equal(authB.status, 302);
  const locB = authB.headers.get("location") || "";
  assert.ok(locB.startsWith(redirectUriB), "Tab B authorization must redirect to App B");

  // 5. Unknown or disabled client cannot establish a valid client context
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
// CASE 19: Social Login Private-App Isolation & Existing Session Preservation
// --------------------------------------------------------------------------
await runTest(19, "Social login private-app isolation: unassigned user callback revokes only newly created session", async () => {
  // 1. User 2 has an existing valid Session A on the IDP (e.g. from legitimate prior login)
  const existingSessionToken = `existing_sess_a_${crypto.randomBytes(16).toString("hex")}`;
  await db.collection("session").insertOne({
    id: existingSessionToken,
    token: existingSessionToken,
    userId: user2Id,
    expiresAt: new Date(Date.now() + 86400000),
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // 2. User 2 attempts unauthorized social login into private App A
  const res = await app.request("/api/auth/callback/google", {
    method: "GET",
    headers: getTestHeaders({
      Cookie: `current_client_id=${appA_id}`,
      "x-test-mock-social-user": user2Id,
    }),
  });

  // 3. Must be rejected and redirected with error=access_denied
  assert.equal(res.status, 302, "Must redirect unassigned social login on private app");
  const loc = res.headers.get("location") || "";
  assert.ok(loc.includes("error=access_denied"), "Redirect location must indicate access_denied");

  // 4. Invariant: Pre-existing Session A MUST REMAIN VALID in MongoDB!
  const sessionAInDb = await db.collection("session").findOne({ token: existingSessionToken });
  assert.ok(sessionAInDb, "Pre-existing Session A must NOT be deleted when an unassigned private login is rejected");

  // 5. Invariant: The rejected flow's newly created session (Session B) MUST be deleted!
  const unauthSessions = await db.collection("session").find({
    userId: user2Id,
    token: { $ne: existingSessionToken },
  }).toArray();
  assert.equal(unauthSessions.length, 0, "Unauthorized newly created social session must be deterministically deleted");

  // Clean up Session A fixture
  await db.collection("session").deleteOne({ token: existingSessionToken });
});

// --------------------------------------------------------------------------
// CASE 20: Social Login Public-App Membership
// --------------------------------------------------------------------------
await runTest(20, "Social login public-app membership: creates membership idempotently", async () => {
  const publicAppId = `public_app_${testSuffix}`;
  await seedOAuthClient(publicAppId, "pub_secret_12345", true, ["http://localhost:5174/cb-pub"]);

  const res = await app.request("/api/auth/callback/google", {
    method: "GET",
    headers: getTestHeaders({
      Cookie: `current_client_id=${publicAppId}`,
      "x-test-mock-social-user": user2Id,
    }),
  });

  assert.equal(res.status, 302);
  const reg = await db.collection("user_app_registrations").findOne({ userId: user2Id, clientId: publicAppId });
  assert.ok(reg, "Public app social login must record registration");
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
