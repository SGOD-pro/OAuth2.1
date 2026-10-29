import assert from "node:assert/strict";
import crypto from "crypto";
import process from "node:process";
import { Buffer } from "node:buffer";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId } from "mongodb";
import * as jose from "jose";

// 1. Start disposable in-memory MongoDB before importing application modules
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.INTERNAL_GATEWAY_SECRET = "g".repeat(32);
process.env.TRUSTED_PROXY_CIDRS = "127.0.0.1/32,10.0.0.0/8";

// 2. Import real production modules
const { getDb, closeDb } = await import("../../src/db/mongo");
const { default: app } = await import("../../src/app");
const { authProvider } = await import("../../src/utils/auth");
const { getIdpPublicKey, clearPublicKeyCacheForTesting } = await import("../../src/middleware/admin-auth");
const {
  getIdpSigningKey,
  mintJwtAccessToken,
  clearSigningKeyCacheForTesting,
} = await import("../../src/routes/auth");
const { ensureTtlIndexes, registerTokenFamily, verifyAndRotateTokenFamily } = await import("../../src/db/state");
const { validateRedirectUri } = await import("../../src/utils/security");

// Consumer refresh coordination mutex (in-flight Promise deduplication)
const inFlightRefreshes = new Map<string, Promise<any>>();
async function coordinateTokenRefresh<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const existing = inFlightRefreshes.get(key);
  if (existing) return existing;
  const promise = fn().finally(() => inFlightRefreshes.delete(key));
  inFlightRefreshes.set(key, promise);
  return promise;
}

console.log("================================================================");
console.log("  SWYRA AUTH (IN-PROCESS PROTOCOL TEST SUITE) -- LOCAL CONSUMER E2E (11 FLOWS)");
console.log("  In-process Hono test harness running against disposable MongoDB instance: " + mongoUri);
console.log("================================================================\n");

let passed = 0;
let failed = 0;
let ipCounter = 200;

function getTestHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
  const headers: Record<string, string> = {
    host: "localhost:3000",
    origin: process.env.FRONTEND_URL || "http://localhost:5174",
    referer: (process.env.FRONTEND_URL || "http://localhost:5174") + "/",
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    "x-gateway-secret": process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32),
    "x-csrf-token": "any",
  };
  for (const [k, v] of Object.entries(extra)) {
    for (const key of Object.keys(headers)) {
      if (key.toLowerCase() === k.toLowerCase()) {
        delete headers[key];
      }
    }
    headers[k] = v;
  }
  return headers;
}

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

const db = await getDb();
await ensureTtlIndexes();

// --------------------------------------------------------------------------
// SETUP: Register RSA Signing Key in JWKS Collection for IdP
// --------------------------------------------------------------------------
// Use real production getIdpSigningKey to initialize, symmetrically encrypt, and store the RS256 keypair
const idpSigningKey = await getIdpSigningKey();
assert.ok(idpSigningKey, "IdP signing key must be initialized");

// --------------------------------------------------------------------------
// SETUP: Clients (App A: Public Dev Client, App B: Private Enterprise Client)
// --------------------------------------------------------------------------
const clientA_id = "consumer-app-a-" + crypto.randomBytes(4).toString("hex");
const clientA_secret = "secret-a-" + crypto.randomBytes(8).toString("hex");
const clientA_secretHash = crypto.createHash("sha256").update(clientA_secret).digest("base64url");
const clientA_redirectUri = "http://localhost:4000/auth/callback";

const clientB_id = "consumer-app-b-" + crypto.randomBytes(4).toString("hex");
const clientB_secret = "secret-b-" + crypto.randomBytes(8).toString("hex");
const clientB_secretHash = crypto.createHash("sha256").update(clientB_secret).digest("base64url");
const clientB_redirectUri = "http://localhost:3001/api/auth/callback";

await db.collection("oauthClient").insertMany([
  {
    clientId: clientA_id,
    clientSecret: clientA_secretHash,
    name: "Express Consumer Application A",
    redirectUris: [clientA_redirectUri],
    allowedOrigins: ["http://localhost:5175", "http://localhost:4000"],
    disabled: false,
    isDev: true,
    isPublic: true,
    skipConsent: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    clientId: clientB_id,
    clientSecret: clientB_secretHash,
    name: "Next.js Private Application B",
    redirectUris: [clientB_redirectUri],
    allowedOrigins: ["http://localhost:3001"],
    disabled: false,
    isDev: true,
    isPublic: false,
    skipConsent: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  },
]);

// --------------------------------------------------------------------------
// SETUP: Users
// --------------------------------------------------------------------------
const commonPass = "TestPassword@1234!";

// 1. Platform Admin
const platformAdminEmail = `platform_admin_${crypto.randomBytes(4).toString("hex")}@example.com`;
const createdPlatformAdmin = await authProvider.api.signUpEmail({
  body: { email: platformAdminEmail, password: commonPass, name: "Platform Admin" },
});
await db.collection("user").updateOne(
  { email: platformAdminEmail },
  { $set: { role: "admin", scopedClientId: null } }
);

// 2. App A Admin (Scoped to clientA_id)
const appAdminEmail = `app_a_admin_${crypto.randomBytes(4).toString("hex")}@example.com`;
const createdAppAdmin = await authProvider.api.signUpEmail({
  body: { email: appAdminEmail, password: commonPass, name: "App A Admin" },
});
await db.collection("user").updateOne(
  { email: appAdminEmail },
  { $set: { role: "admin", scopedClientId: clientA_id } }
);

// 3. Dual App Admin (Admin on App A, registered & scoped on App B)
const dualAdminEmail = `dual_admin_${crypto.randomBytes(4).toString("hex")}@example.com`;
const createdDualAdmin = await authProvider.api.signUpEmail({
  body: { email: dualAdminEmail, password: commonPass, name: "Dual Admin" },
});
await db.collection("user").updateOne(
  { email: dualAdminEmail },
  { $set: { role: "admin", scopedClientId: clientA_id } }
);
await db.collection("user_app_registrations").insertOne({
  userId: String(createdDualAdmin.user.id),
  clientId: clientB_id,
  appRole: "admin",
  registeredAt: new Date(),
});
await db.collection("app_admins").insertOne({
  userId: String(createdDualAdmin.user.id),
  clientId: clientB_id,
  email: dualAdminEmail,
  isActive: true,
  createdAt: new Date(),
});

// 4. Ordinary User
const ordinaryUserEmail = `ordinary_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
const createdOrdinaryUser = await authProvider.api.signUpEmail({
  body: { email: ordinaryUserEmail, password: commonPass, name: "Ordinary User" },
});

// 5. Private App User 1
const privateUser1Email = `private_user1_${crypto.randomBytes(4).toString("hex")}@example.com`;
const createdPrivateUser1 = await authProvider.api.signUpEmail({
  body: { email: privateUser1Email, password: commonPass, name: "Private User 1" },
});

// 6. Private App User 2
const privateUser2Email = `private_user2_${crypto.randomBytes(4).toString("hex")}@example.com`;
const createdPrivateUser2 = await authProvider.api.signUpEmail({
  body: { email: privateUser2Email, password: commonPass, name: "Private User 2" },
});

// Helper: login via IdP email endpoint and return cookie
async function loginAndGetCookie(email: string): Promise<string> {
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ email, password: commonPass }),
  });
  assert.equal(loginRes.status, 200, `Sign-in failed for ${email}`);
  const setCookies = (loginRes.headers as any).getSetCookie
    ? (loginRes.headers as any).getSetCookie()
    : [loginRes.headers.get("set-cookie") || ""];
  return setCookies.map((c: string) => c.split(";")[0]).filter(Boolean).join("; ");
}

const platformAdminCookie = await loginAndGetCookie(platformAdminEmail);
const appAdminCookie = await loginAndGetCookie(appAdminEmail);
const dualAdminCookie = await loginAndGetCookie(dualAdminEmail);
const ordinaryUserCookie = await loginAndGetCookie(ordinaryUserEmail);
const privateUser1Cookie = await loginAndGetCookie(privateUser1Email);
const privateUser2Cookie = await loginAndGetCookie(privateUser2Email);

// ==========================================================================
// FLOW 1: Platform Admin Login & Platform Metrics Access
// ==========================================================================
await runTest("Flow 1: Platform admin accesses platform metrics and clients list", async () => {
  const statsRes = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders({ Cookie: platformAdminCookie }),
  });
  assert.equal(statsRes.status, 200, "Platform admin must access /api/admin/stats");
  const statsData = await statsRes.json();
  assert.ok(statsData.totalUsers !== undefined, "Stats data must include totalUsers");
  assert.ok(statsData.totalClients !== undefined, "Stats data must include totalClients");

  const clientsRes = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: platformAdminCookie }),
  });
  assert.equal(clientsRes.status, 200, "Platform admin must access /api/admin/clients");
  const clientsData = await clientsRes.json();
  assert.ok(Array.isArray(clientsData), "Clients response must be an array");
});

// ==========================================================================
// FLOW 2: App A Admin Denied Platform & App B, Allowed App A
// ==========================================================================
await runTest("Flow 2: App A admin denied platform & App B management, allowed App A management", async () => {
  // 1. Denied platform stats
  const statsRes = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders({ Cookie: appAdminCookie }),
  });
  assert.equal(statsRes.status, 403, "App A admin must be denied platform stats (403)");

  // 2. Denied platform clients list
  const clientsRes = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: appAdminCookie }),
  });
  assert.equal(clientsRes.status, 403, "App A admin must be denied full clients list (403)");

  // 3. Denied App B management
  const appBUsersRes = await app.request(`/api/admin/clients/${clientB_id}/users`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: appAdminCookie }),
  });
  assert.equal(appBUsersRes.status, 403, "App A admin must be denied App B user management (403)");

  // 4. Allowed App A management
  const appAUsersRes = await app.request(`/api/admin/clients/${clientA_id}/users`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: appAdminCookie }),
  });
  assert.equal(appAUsersRes.status, 200, "App A admin must be allowed App A user management (200)");
});

// ==========================================================================
// FLOW 3: Dual-App Admin Without Corruption
// ==========================================================================
await runTest("Flow 3: Dual-app admin managing A & B without token or scope cross-corruption", async () => {
  // Mint token for App A
  const tokenA = await mintJwtAccessToken({
    userId: String(createdDualAdmin.user.id),
    clientId: clientA_id,
    scope: "openid profile email",
    expiresInSeconds: 3600,
  });
  assert.ok(tokenA, "Token A must be minted");

  // Mint token for App B
  const tokenB = await mintJwtAccessToken({
    userId: String(createdDualAdmin.user.id),
    clientId: clientB_id,
    scope: "openid profile email",
    expiresInSeconds: 3600,
  });
  assert.ok(tokenB, "Token B must be minted");

  // Verify App A token structure
  const decodedA: any = jose.decodeJwt(tokenA!);
  assert.equal(decodedA.client_id, clientA_id, "Token A client_id must match clientA_id");

  // Verify App B token structure
  const decodedB: any = jose.decodeJwt(tokenB!);
  assert.equal(decodedB.client_id, clientB_id, "Token B client_id must match clientB_id");

  // Consumer Isolation check: App A must reject Token B
  const appA_isolationCheck = (token: string, expectedClientId: string) => {
    const payload: any = jose.decodeJwt(token);
    const tokenClientId = payload.client_id || payload.azp || payload.aud;
    if (tokenClientId !== expectedClientId) {
      return { status: 403, error: "forbidden", message: "Client ID mismatch" };
    }
    return { status: 200, user: payload };
  };

  assert.equal(appA_isolationCheck(tokenA!, clientA_id).status, 200, "App A accepts Token A");
  assert.equal(appA_isolationCheck(tokenB!, clientA_id).status, 403, "App A rejects Token B");
  assert.equal(appA_isolationCheck(tokenB!, clientB_id).status, 200, "App B accepts Token B");
  assert.equal(appA_isolationCheck(tokenA!, clientB_id).status, 403, "App B rejects Token A");

  // Verify password remained intact
  const verifyRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ email: dualAdminEmail, password: commonPass }),
  });
  assert.equal(verifyRes.status, 200, "Dual admin credentials must remain intact");
});

// ==========================================================================
// FLOW 4: Ordinary User Denied Admin Operations
// ==========================================================================
await runTest("Flow 4: Ordinary user is denied all administrative operations", async () => {
  const routes = [
    "/api/admin/stats",
    "/api/admin/clients",
    `/api/admin/clients/${clientA_id}/users`,
    `/api/admin/clients/${clientB_id}/users`,
  ];

  for (const route of routes) {
    const res = await app.request(route, {
      method: "GET",
      headers: getTestHeaders({ Cookie: ordinaryUserCookie }),
    });
    assert.equal(res.status, 403, `Ordinary user must receive 403 on ${route}`);
  }
});

// ==========================================================================
// FLOW 5: Private App Membership Enforcement (Zero Password Relay)
// ==========================================================================
await runTest("Flow 5: Private app membership enforcement with zero password relay", async () => {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_flow5_" + crypto.randomBytes(4).toString("hex");

  // Step 1: Unassigned user attempts authorization on private client -> denied with 302 access_denied
  const unassignedRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientB_id}&redirect_uri=${encodeURIComponent(clientB_redirectUri)}&response_type=code&scope=openid+profile+email+offline_access&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: privateUser1Cookie }),
      redirect: "manual",
    }
  );

  assert.equal(unassignedRes.status, 302, "Unassigned user must receive 302 redirect");
  const unassignedLoc = unassignedRes.headers.get("location") || "";
  const parsedUnassigned = new URL(unassignedLoc);
  assert.equal(parsedUnassigned.searchParams.get("error"), "access_denied");
  assert.equal(parsedUnassigned.searchParams.get("state"), state);

  // Step 2: Register Private User 1 in user_app_registrations for Client B
  await db.collection("user_app_registrations").insertOne({
    userId: String(createdPrivateUser1.user.id),
    clientId: clientB_id,
    registeredAt: new Date(),
  });

  // Step 3: Retry authorization -> succeeds with 302 containing authorization code
  const assignedRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientB_id}&redirect_uri=${encodeURIComponent(clientB_redirectUri)}&response_type=code&scope=openid+profile+email+offline_access&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: privateUser1Cookie }),
      redirect: "manual",
    }
  );

  assert.equal(assignedRes.status, 302, "Assigned user must receive 302 redirect with code");
  const assignedLoc = assignedRes.headers.get("location") || "";
  const parsedAssigned = new URL(assignedLoc);
  const code = parsedAssigned.searchParams.get("code");
  assert.ok(code, "Redirect must contain authorization code");

  // Step 4: Token exchange (zero password relay)
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientB_id}:${clientB_secret}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(clientB_redirectUri)}&code_verifier=${codeVerifier}`,
  });

  assert.equal(tokenRes.status, 200, "Token exchange must return 200");
  const tokenData = await tokenRes.json();
  assert.ok(tokenData.access_token, "Must receive RS256 access token");
  assert.ok(tokenData.refresh_token, "Must receive refresh token");
  assert.equal(tokenData.access_token.split(".").length, 3, "Access token must be RS256 JWT");
});

// ==========================================================================
// FLOW 6: Same-Browser Account Switching
// ==========================================================================
await runTest("Flow 6: Same-browser account switching with prompt=login", async () => {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_flow6_" + crypto.randomBytes(4).toString("hex");

  // Browser currently has User 1 session.
  // Client initiates authorization with prompt=login to switch accounts.
  const switchReqRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientA_id}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}&prompt=login`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: privateUser1Cookie }),
      redirect: "manual",
    }
  );

  assert.equal(switchReqRes.status, 302, "prompt=login must redirect to login rather than auto-approving");
  const switchLoc = switchReqRes.headers.get("location") || "";
  assert.ok(switchLoc.includes("/auth"), "Must redirect toward login path");

  // User 2 logs in to establish fresh session
  const user2Cookie = await loginAndGetCookie(privateUser2Email);

  // Re-run authorize with User 2 session
  const authUser2Res = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientA_id}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: user2Cookie }),
      redirect: "manual",
    }
  );

  assert.equal(authUser2Res.status, 302, "Authorize must succeed for User 2");
  const user2Loc = authUser2Res.headers.get("location") || "";
  const codeUser2 = new URL(user2Loc).searchParams.get("code")!;
  assert.ok(codeUser2, "Must receive code for User 2");

  // Exchange code
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${codeUser2}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&code_verifier=${codeVerifier}`,
  });

  const tokens = await tokenRes.json();
  const decoded: any = jose.decodeJwt(tokens.access_token);
  assert.equal(decoded.sub, createdPrivateUser2.user.id, "Access token subject must be User 2");
  assert.notEqual(decoded.sub, createdPrivateUser1.user.id, "Access token subject must not be User 1");
});

// ==========================================================================
// FLOW 7: Access Token Expiry + Auto-Refresh
// ==========================================================================
await runTest("Flow 7: Access token expiry followed by automatic refresh", async () => {
  // 1. Issue initial token family
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_flow7_" + crypto.randomBytes(4).toString("hex");

  const authRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientA_id}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&response_type=code&scope=openid+profile+email+offline_access&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: privateUser1Cookie }),
      redirect: "manual",
    }
  );

  const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&code_verifier=${codeVerifier}`,
  });

  const initialTokens = await tokenRes.json();
  const initialRefreshToken = initialTokens.refresh_token;
  assert.ok(initialRefreshToken, "Must have refresh token");

  // 2. Perform refresh using refresh token
  const refreshRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=refresh_token&refresh_token=${initialRefreshToken}&client_id=${clientA_id}`,
  });

  assert.equal(refreshRes.status, 200, "Token refresh must succeed");
  const refreshedTokens = await refreshRes.json();
  assert.ok(refreshedTokens.access_token, "Must receive new access token");
  assert.ok(refreshedTokens.refresh_token, "Must receive new refresh token");
  assert.notEqual(refreshedTokens.access_token, initialTokens.access_token, "New access token must differ");

  // 3. Userinfo endpoint validates the new access token
  const userinfoRes = await app.request("/api/auth/oauth2/userinfo", {
    headers: getTestHeaders({ Authorization: `Bearer ${refreshedTokens.access_token}` }),
  });
  assert.equal(userinfoRes.status, 200, "Userinfo must succeed with new access token");
  const userinfo = await userinfoRes.json();
  assert.equal(userinfo.sub, createdPrivateUser1.user.id);
});

// ==========================================================================
// FLOW 8: Concurrent Refresh Without Revocation (Consumer Deduplication & Grace Window)
// ==========================================================================
await runTest("Flow 8: Concurrent refresh without family revocation via deduplication & grace window", async () => {
  // 1. Issue fresh tokens
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_flow8_" + crypto.randomBytes(4).toString("hex");

  const authRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientA_id}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&response_type=code&scope=openid+profile+email+offline_access&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: privateUser1Cookie }),
      redirect: "manual",
    }
  );

  const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&code_verifier=${codeVerifier}`,
  });

  const tokens = await tokenRes.json();
  const testRefreshToken = tokens.refresh_token;

  // 2. Test in-flight Promise deduplication (Consumer Refresh Coordination)
  let networkCallCount = 0;
  const simulatedRefreshNetworkCall = async () => {
    networkCallCount++;
    const res = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: getTestHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
      }),
      body: `grant_type=refresh_token&refresh_token=${testRefreshToken}&client_id=${clientA_id}`,
    });
    return res.json();
  };

  // Launch 5 concurrent calls through coordinateTokenRefresh
  const concurrentResults = await Promise.all([
    coordinateTokenRefresh(testRefreshToken, simulatedRefreshNetworkCall),
    coordinateTokenRefresh(testRefreshToken, simulatedRefreshNetworkCall),
    coordinateTokenRefresh(testRefreshToken, simulatedRefreshNetworkCall),
    coordinateTokenRefresh(testRefreshToken, simulatedRefreshNetworkCall),
    coordinateTokenRefresh(testRefreshToken, simulatedRefreshNetworkCall),
  ]);

  assert.equal(networkCallCount, 1, "Consumer coordination mutex must consolidate into exactly 1 network call");
  for (const res of concurrentResults) {
    assert.equal(res.access_token, concurrentResults[0].access_token, "All concurrent callers must receive identical token");
  }

  // 3. Test IdP Grace Window: Send another refresh request with the consumed token within grace window
  const graceRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=refresh_token&refresh_token=${testRefreshToken}&client_id=${clientA_id}`,
  });

  // Spec 0002 AC-5: Returning 400 invalid_grant on consumed tokens without revoking the active token family
  assert.equal(graceRes.status, 400, "Consumed token within grace window must return 400 invalid_grant");
  const graceData = await graceRes.json();
  assert.equal(graceData.error, "invalid_grant");

  // Verify family was NOT revoked
  const initialHash = crypto.createHash("sha256").update(testRefreshToken).digest("hex");
  const family = await db.collection("oauth_token_families").findOne({
    $or: [{ activeTokenHash: initialHash }, { consumedTokenHashes: initialHash }],
  });
  assert.ok(family, "Family must exist");
  assert.equal(family.status, "active", "Family must remain active");
});

// ==========================================================================
// FLOW 9: Genuine Refresh Replay Rejection
// ==========================================================================
await runTest("Flow 9: Genuine refresh replay outside grace window is rejected and family revoked", async () => {
  // 1. Issue fresh tokens
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_flow9_" + crypto.randomBytes(4).toString("hex");

  const authRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientA_id}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&response_type=code&scope=openid+profile+email+offline_access&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: privateUser1Cookie }),
      redirect: "manual",
    }
  );

  const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&code_verifier=${codeVerifier}`,
  });

  const tokens1 = await tokenRes.json();
  const tokenGen0 = tokens1.refresh_token;

  // 2. Rotate Gen 0 -> Gen 1
  const rotate1Res = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=refresh_token&refresh_token=${tokenGen0}&client_id=${clientA_id}`,
  });
  assert.equal(rotate1Res.status, 200);
  const tokens2 = await rotate1Res.json();
  const tokenGen1 = tokens2.refresh_token;

  // Simulate expiry of grace window by aging updatedAt and rotatedAt in DB to 30 seconds ago
  const gen0Hash = crypto.createHash("sha256").update(tokenGen0).digest("hex");
  await db.collection("oauth_token_families").updateOne(
    { consumedTokenHashes: gen0Hash },
    { $set: { updatedAt: new Date(Date.now() - 30_000), rotatedAt: new Date(Date.now() - 30_000) } }
  );

  // 3. Replay Gen 0 outside grace window -> Replay Attack Detected
  const replayRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=refresh_token&refresh_token=${tokenGen0}&client_id=${clientA_id}`,
  });

  // Spec 0002 AC-6: Presentation outside grace window triggers cascade revocation
  assert.ok(replayRes.status === 400 || replayRes.status === 401, "Replayed token must be rejected with 400 or 401");
  const replayData = await replayRes.json();
  assert.equal(replayData.error, "invalid_grant");

  // 4. Verify family was revoked
  const family = await db.collection("oauth_token_families").findOne({ consumedTokenHashes: gen0Hash });
  assert.ok(family, "Family must exist");
  assert.equal(family.status, "revoked", "Entire family must be revoked");

  // 5. Subsequent attempt using Gen 1 must also be rejected
  const subsequentRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=refresh_token&refresh_token=${tokenGen1}&client_id=${clientA_id}`,
  });
  assert.ok(subsequentRes.status === 400 || subsequentRes.status === 401, "Subsequent use of child token must also be rejected (400 or 401)");
});

// ==========================================================================
// FLOW 10: IdP Restart Session Preservation
// ==========================================================================
await runTest("Flow 10: IdP restart preserves existing sessions, public keys, and refresh tokens", async () => {
  // 1. Issue authentic tokens before simulated restart
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_flow10_" + crypto.randomBytes(4).toString("hex");

  const authRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientA_id}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&response_type=code&scope=openid+profile+email+offline_access&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: privateUser1Cookie }),
      redirect: "manual",
    }
  );

  assert.equal(authRes.status, 302, "Authorize must return 302 with code");
  const loc = authRes.headers.get("location") || "";
  const code = new URL(loc).searchParams.get("code")!;
  assert.ok(code, "Must have authorization code");

  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(clientA_redirectUri)}&code_verifier=${codeVerifier}`,
  });

  assert.equal(tokenRes.status, 200, "Token exchange must succeed before restart");
  const preRestartTokens = await tokenRes.json();
  const preRestartAccessToken = preRestartTokens.access_token;
  const preRestartRefreshToken = preRestartTokens.refresh_token;
  assert.ok(preRestartAccessToken, "Pre-restart access token must exist");
  assert.ok(preRestartRefreshToken, "Pre-restart refresh token must exist");

  // 2. SIMULATE RESTART: Clear in-memory signing and public key caches
  clearSigningKeyCacheForTesting();
  clearPublicKeyCacheForTesting();

  // 3. Verify that previously minted JWT verifies offline against JWKS / getIdpPublicKey
  const keyAfterRestart = await getIdpPublicKey();
  assert.ok(keyAfterRestart, "PublicKey must be re-loaded from database after restart");
  const verifyResult = await jose.jwtVerify(preRestartAccessToken, keyAfterRestart);
  assert.equal(verifyResult.payload.sub, createdPrivateUser1.user.id, "Pre-restart token must verify successfully");

  // 4. Verify that pre-restart refresh token rotates cleanly on restarted IdP
  const refreshRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientA_id}:${clientA_secret}`).toString("base64"),
    }),
    body: `grant_type=refresh_token&refresh_token=${preRestartRefreshToken}&client_id=${clientA_id}`,
  });

  assert.equal(refreshRes.status, 200, "Pre-restart refresh token must rotate successfully after restart");
  const postRestartTokens = await refreshRes.json();
  assert.ok(postRestartTokens.access_token, "Must receive new access token after restart");
  assert.ok(postRestartTokens.refresh_token, "Must receive new refresh token after restart");
});

// ==========================================================================
// FLOW 11: Production-Mode Guard Enforcement
// ==========================================================================
await runTest("Flow 11: Production-mode guard enforcement (loopback rejection & gateway secret)", async () => {
  // Guard A: Production client cannot register or use loopback redirect URI
  const loopbackUri = "http://localhost:8080/callback";
  const isValidOnDev = validateRedirectUri(loopbackUri, { isDev: true });
  const isValidOnProd = validateRedirectUri(loopbackUri, { isDev: false });

  assert.equal(isValidOnDev, true, "Loopback is permitted for development clients");
  assert.equal(isValidOnProd, false, "Loopback is strictly forbidden for production clients");

  // Guard B: Missing gateway secret enforcement on administrative endpoints
  const noSecretHeaders = getTestHeaders();
  delete noSecretHeaders["x-gateway-secret"];

  // Request to admin route without gateway secret in production or test
  const adminRes = await app.request("/api/admin/metrics", {
    method: "GET",
    headers: noSecretHeaders,
  });

  assert.equal(adminRes.status, 403, "Request without gateway secret must be rejected with 403 Forbidden");
  const adminErr = await adminRes.json();
  assert.equal(adminErr.error, "forbidden", "Must return forbidden error");
});

console.log("\n================================================================");
console.log(`  LOCAL CONSUMER E2E TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================\n");

await closeDb();
await mongod.stop();

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
