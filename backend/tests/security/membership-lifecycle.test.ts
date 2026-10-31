// Guaranteed clean environment: never inherit external Redis credentials
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId } from "mongodb";

// 1. Guaranteed disposable in-memory database
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;

// Prove MONGO_URI matches the in-process disposable server, not any other loopback listener.
const { assertIsMemoryServerUri } = await import("../fixtures/test-env-isolation");
assertIsMemoryServerUri(mongoUri);
process.env.BETTER_AUTH_SECRET = "b".repeat(32);
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
const { checkUserAppRegistration, checkUserHasAppAccess, hashToken } = await import("../../src/utils/security");
const { checkUserIsClientAdmin } = await import("../../src/middleware/admin-auth");
const { isOriginAllowed } = await import("../../src/middleware/cors");
const { config } = await import("../../src/config");
const { registerTokenFamily } = await import("../../src/db/state");
const { migrateLegacyAppAdmins, selfHealAppAdmins } = await import("../../src/utils/admin-sync");
const {
  isolateTestEnvironment,
  validateDisposableMongoUri,
  assertNoExternalInfrastructure,
  MONGO_ALIAS_ENV_VARS,
  REDIS_ALIAS_ENV_VARS,
} = await import("../fixtures/test-env-isolation");

console.log("================================================================");
console.log("  SWYRA AUTH -- MEMBERSHIP LIFECYCLE & ORIGIN RESTRICTION SUITE");
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

const db = await getDb();

let ipCounter = 300;
function getTestHeaders(extra: Record<string, string> = {}): Headers {
  const h = new Headers();
  const ip = `198.51.100.${++ipCounter % 240 + 1}`;
  h.set("content-type", "application/json");
  h.set("host", "localhost:3000");
  h.set("origin", process.env.FRONTEND_URL || "http://localhost:5174");
  h.set("referer", (process.env.FRONTEND_URL || "http://localhost:5174") + "/");
  h.set("x-forwarded-for", `${ip}, 10.0.0.1`);
  h.set("x-gateway-secret", GATEWAY_SECRET);
  for (const [k, v] of Object.entries(extra)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

// Seed Super Admin for test harness operations
const superAdminEmail = "super_membership@swyra.com";
const superAdminPass = "SuperMemberPass123!Aa";
const superSignUp = await authProvider.api.signUpEmail({
  body: { email: superAdminEmail, password: superAdminPass, name: "Super Admin Member" },
});
await db.collection("user").updateOne(
  { email: superAdminEmail },
  { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
);
const superLoginRes = await app.request("/api/auth/sign-in/email", {
  method: "POST",
  headers: getTestHeaders(),
  body: JSON.stringify({ email: superAdminEmail, password: superAdminPass }),
});
const superCookie = (superLoginRes.headers.get("set-cookie") || "").split(";")[0];

// -----------------------------------------------------------------------------
// SETUP BASE FIXTURES
// -----------------------------------------------------------------------------
const privateClientId = "test_private_client_" + crypto.randomBytes(4).toString("hex");
await db.collection("oauthClient").insertOne({
  _id: privateClientId as any,
  id: privateClientId,
  clientId: privateClientId,
  client_id: privateClientId,
  clientSecret: "secret_" + crypto.randomBytes(16).toString("hex"),
  name: "Private Test App",
  isPublic: false,
  isDev: false,
  disabled: false,
  redirectUris: ["https://private-app.example.com/callback"],
  allowedOrigins: ["https://private-app.example.com"],
  createdAt: new Date(),
  updatedAt: new Date(),
});

// Create test user
const userEmail = `member_test_${crypto.randomBytes(4).toString("hex")}@example.com`;
const userPass = "MemberTestPass123!Aa";
const userSignUp = await authProvider.api.signUpEmail({
  body: { email: userEmail, password: userPass, name: "Membership Test User" },
});
const testUserId = String(userSignUp.user.id);

// =============================================================================
// TEST 1: Active membership grants access
// =============================================================================
await runTest("MEM-1: Active user registration grants access to private application", async () => {
  await db.collection("user_app_registrations").insertOne({
    userId: testUserId,
    clientId: privateClientId,
    status: "active",
    createdAt: new Date(),
  });

  const isRegistered = await checkUserAppRegistration(db, testUserId, privateClientId);
  assert.equal(isRegistered, true, "Active registration must grant access");
});

// =============================================================================
// TEST 2: Inactive, suspended, and revoked statuses deny access
// =============================================================================
await runTest("MEM-2: Inactive, revoked, suspended, and disabled status deny access", async () => {
  const deniedStatuses = ["inactive", "revoked", "suspended", "disabled"];

  for (const status of deniedStatuses) {
    await db.collection("user_app_registrations").updateOne(
      { userId: testUserId, clientId: privateClientId },
      { $set: { status } }
    );
    const isRegistered = await checkUserAppRegistration(db, testUserId, privateClientId);
    assert.equal(isRegistered, false, `Status '${status}' must strictly deny access`);
  }
});

// =============================================================================
// TEST 3: Boolean flags (revoked: true, disabled: true, isActive: false) deny access
// =============================================================================
await runTest("MEM-3: Explicit boolean revocation flags deny access even if status is active", async () => {
  // Reset to status: active, but revoked: true
  await db.collection("user_app_registrations").updateOne(
    { userId: testUserId, clientId: privateClientId },
    { $set: { status: "active", revoked: true, disabled: false, isActive: true } }
  );
  assert.equal(await checkUserAppRegistration(db, testUserId, privateClientId), false, "revoked: true must deny access");

  // disabled: true
  await db.collection("user_app_registrations").updateOne(
    { userId: testUserId, clientId: privateClientId },
    { $set: { status: "active", revoked: false, disabled: true, isActive: true } }
  );
  assert.equal(await checkUserAppRegistration(db, testUserId, privateClientId), false, "disabled: true must deny access");

  // isActive: false
  await db.collection("user_app_registrations").updateOne(
    { userId: testUserId, clientId: privateClientId },
    { $set: { status: "active", revoked: false, disabled: false, isActive: false } }
  );
  assert.equal(await checkUserAppRegistration(db, testUserId, privateClientId), false, "isActive: false must deny access");

  // active: false
  await db.collection("user_app_registrations").updateOne(
    { userId: testUserId, clientId: privateClientId },
    { $set: { status: "active", revoked: false, disabled: false, isActive: true, active: false } }
  );
  assert.equal(await checkUserAppRegistration(db, testUserId, privateClientId), false, "active: false must deny access");
});

// =============================================================================
// TEST 4: App Admin inactive, revoked, or disabled status denies administration
// =============================================================================
await runTest("MEM-4: App Admin inactive, revoked, or disabled record denies admin privileges", async () => {
  const adminEmail = `admin_lifecycle_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const adminPass = "AdminLifePass123!Aa";
  const adminSignUp = await authProvider.api.signUpEmail({
    body: { email: adminEmail, password: adminPass, name: "Admin Life User" },
  });
  const adminUserId = String(adminSignUp.user.id);

  const userDoc = {
    _id: new ObjectId(adminUserId),
    id: adminUserId,
    email: adminEmail,
    role: "admin",
    scopedClientId: privateClientId,
    emailVerified: true,
  };

  // Set user role in DB
  await db.collection("user").updateOne(
    { email: adminEmail },
    { $set: { role: "admin", scopedClientId: privateClientId, emailVerified: true } }
  );

  // Insert active app_admins record
  await db.collection("app_admins").insertOne({
    userId: adminUserId,
    clientId: privateClientId,
    role: "admin",
    status: "active",
    createdAt: new Date(),
  });

  const activeAllowed = await checkUserIsClientAdmin(db, userDoc, adminUserId, privateClientId);
  assert.equal(activeAllowed, true, "Active app admin must have administration privileges");

  // Inactive app admin
  await db.collection("app_admins").updateOne(
    { userId: adminUserId, clientId: privateClientId },
    { $set: { status: "revoked" } }
  );
  const revokedAllowed = await checkUserIsClientAdmin(db, userDoc, adminUserId, privateClientId);
  assert.equal(revokedAllowed, false, "Revoked app admin must NOT have administration privileges");

  // Disabled flag
  await db.collection("app_admins").updateOne(
    { userId: adminUserId, clientId: privateClientId },
    { $set: { status: "active", disabled: true } }
  );
  const disabledFlagAllowed = await checkUserIsClientAdmin(db, userDoc, adminUserId, privateClientId);
  assert.equal(disabledFlagAllowed, false, "disabled: true on app admin must deny administration privileges");
});

// =============================================================================
// TEST 5: Production origin restriction rules
// =============================================================================
await runTest("MEM-5: Production environment strictly restricts localhost and loopback origins", async () => {
  const savedEnv = process.env.NODE_ENV;
  const savedAllowDev = process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION;

  try {
    process.env.NODE_ENV = "production";
    process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION = "false";

    // A. Localhost origin without client config is rejected in production
    const unconfigLocalhost = await isOriginAllowed("http://localhost:3000");
    assert.equal(unconfigLocalhost, false, "Unconfigured localhost origin must be rejected in production");

    // B. Client configured with localhost, but isDev: false -> rejected in production
    const prodClientWithLocalhost = "client_prod_lh_" + crypto.randomBytes(4).toString("hex");
    await db.collection("oauthClient").insertOne({
      clientId: prodClientWithLocalhost,
      isDev: false,
      isPublic: false,
      disabled: false,
      allowedOrigins: ["http://localhost:8080"],
      createdAt: new Date(),
    });
    const disallowedLh = await isOriginAllowed("http://localhost:8080");
    assert.equal(disallowedLh, false, "Production client cannot use localhost origin when isDev is false");

    // C. Client configured with isDev: true, but allowDevClientsInProduction is false -> rejected
    const devClientInProd = "client_dev_prod_" + crypto.randomBytes(4).toString("hex");
    await db.collection("oauthClient").insertOne({
      clientId: devClientInProd,
      isDev: true,
      isPublic: false,
      disabled: false,
      allowedOrigins: ["http://localhost:8081"],
      createdAt: new Date(),
    });
    const devRejected = await isOriginAllowed("http://localhost:8081");
    assert.equal(devRejected, false, "isDev client must be rejected in production when allowDevClientsInProduction is false");

    // D. When allowDevClientsInProduction is true, isDev client with localhost is allowed
    process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION = "true";
    const devAllowed = await isOriginAllowed("http://localhost:8081");
    assert.equal(devAllowed, true, "isDev client is allowed when allowDevClientsInProduction is explicitly enabled");

    // E. Production client with valid HTTPS origin is allowed in production
    const validProdClient = "client_prod_valid_" + crypto.randomBytes(4).toString("hex");
    await db.collection("oauthClient").insertOne({
      clientId: validProdClient,
      isDev: false,
      isPublic: false,
      disabled: false,
      allowedOrigins: ["https://customer-portal.swyra.com"],
      createdAt: new Date(),
    });
    const validProdAllowed = await isOriginAllowed("https://customer-portal.swyra.com");
    assert.equal(validProdAllowed, true, "Valid HTTPS production origin must be allowed");
  } finally {
    process.env.NODE_ENV = savedEnv;
    if (savedAllowDev === undefined) {
      delete process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION;
    } else {
      process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION = savedAllowDev;
    }
  }
});

// =============================================================================
// TEST 6: Complete user membership removal cascade
// =============================================================================
await runTest("MEM-6: Removing user membership deletes record and revokes tokens", async () => {
  // Re-activate registration
  await db.collection("user_app_registrations").updateOne(
    { userId: testUserId, clientId: privateClientId },
    { $set: { status: "active", revoked: false, disabled: false, isActive: true, active: true } }
  );
  assert.equal(await checkUserAppRegistration(db, testUserId, privateClientId), true);

  // Insert mock tokens for this user on this client
  await db.collection("oauthAccessToken").insertOne({
    clientId: privateClientId,
    userId: testUserId,
    token: "at_" + crypto.randomBytes(16).toString("hex"),
    createdAt: new Date(),
  });
  await db.collection("oauthRefreshToken").insertOne({
    clientId: privateClientId,
    userId: testUserId,
    token: "rt_" + crypto.randomBytes(16).toString("hex"),
    createdAt: new Date(),
  });

  // Perform deletion
  await Promise.all([
    db.collection("user_app_registrations").deleteMany({
      clientId: privateClientId,
      $or: [{ userId: testUserId }, { userId: String(testUserId) }],
    }),
    db.collection("oauthAccessToken").deleteMany({
      clientId: privateClientId,
      userId: testUserId,
    }),
    db.collection("oauthRefreshToken").deleteMany({
      clientId: privateClientId,
      userId: testUserId,
    }),
  ]);

  // Verify membership and tokens are purged
  const isRegisteredAfter = await checkUserAppRegistration(db, testUserId, privateClientId);
  assert.equal(isRegisteredAfter, false, "User must have no registration after removal");

  const remainingTokens = await db.collection("oauthAccessToken").countDocuments({
    clientId: privateClientId,
    userId: testUserId,
  });
  assert.equal(remainingTokens, 0, "All access tokens must be deleted");
});

// =============================================================================
// TEST 7: Real Route: POST /api/auth/sign-in/email denies private app access
// =============================================================================
await runTest("MEM-7: Real sign-in route rejects revoked or removed user even with scopedClientId", async () => {
  const email = `route_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const pass = "RouteUserPass123!Aa";
  const signUp = await authProvider.api.signUpEmail({
    body: { email, password: pass, name: "Route Test User" },
  });
  const uid = String(signUp.user.id);

  // Set user doc with scopedClientId pointing to private client
  await db.collection("user").updateOne(
    { _id: new ObjectId(uid) },
    { $set: { role: "user", scopedClientId: privateClientId } }
  );

  // Case A: Explicitly revoked registration in user_app_registrations
  await db.collection("user_app_registrations").insertOne({
    userId: uid,
    clientId: privateClientId,
    status: "revoked",
    revoked: true,
    createdAt: new Date(),
  });

  const revokedRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email, password: pass, clientId: privateClientId }),
  });
  assert.equal(revokedRes.status, 403, "Revoked registration must be rejected with 403");
  const revokedJson = await revokedRes.json();
  assert.equal(revokedJson.error, "access_denied");

  // Case B: Removed assignment (delete record from user_app_registrations)
  // User still possesses scopedClientId on user document
  await db.collection("user_app_registrations").deleteMany({ userId: uid, clientId: privateClientId });

  const removedRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email, password: pass, clientId: privateClientId }),
  });
  assert.equal(removedRes.status, 403, "Removed assignment cannot regain access through scopedClientId");

  // Case C: Active registration allows sign-in
  await db.collection("user_app_registrations").insertOne({
    userId: uid,
    clientId: privateClientId,
    status: "active",
    createdAt: new Date(),
  });
  const allowedRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email, password: pass, clientId: privateClientId }),
  });
  assert.equal(allowedRes.status, 200, "Active user registration must succeed on sign-in");
});

// =============================================================================
// TEST 8: Real Route: GET /api/auth/oauth2/authorize rejects revoked or removed user
// =============================================================================
await runTest("MEM-8: Real authorize route redirects with error=access_denied for revoked or removed user", async () => {
  const email = `oauth_auth_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const pass = "OAuthUserPass123!Aa";
  const signUp = await authProvider.api.signUpEmail({
    body: { email, password: pass, name: "OAuth Auth User" },
  });
  const uid = String(signUp.user.id);

  // Authenticate to get session cookie
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email, password: pass }),
  });
  assert.equal(loginRes.status, 200);
  const sessionCookie = (loginRes.headers.get("set-cookie") || "").split(";")[0];

  // Configure redirectUri on client
  const redirectUri = "https://private-app.example.com/callback";
  await db.collection("oauthClient").updateOne(
    { clientId: privateClientId },
    { $set: { redirectUris: [redirectUri], allowedOrigins: ["https://private-app.example.com"] } }
  );

  // Case A: User has revoked registration
  await db.collection("user_app_registrations").insertOne({
    userId: uid,
    clientId: privateClientId,
    status: "revoked",
    revoked: true,
    createdAt: new Date(),
  });

  const authRevokedRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${privateClientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&state=state_xyz`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: sessionCookie }),
    }
  );
  assert.equal(authRevokedRes.status, 302);
  const revokedLocation = authRevokedRes.headers.get("location") || "";
  assert.ok(revokedLocation.includes("error=access_denied"), "Authorize must redirect with error=access_denied");

  // Case B: User has removed assignment (delete record) but scopedClientId is set
  await db.collection("user_app_registrations").deleteMany({ userId: uid, clientId: privateClientId });
  await db.collection("user").updateOne({ _id: new ObjectId(uid) }, { $set: { scopedClientId: privateClientId } });

  const authRemovedRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${privateClientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&state=state_xyz`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: sessionCookie }),
    }
  );
  assert.equal(authRemovedRes.status, 302);
  const removedLocation = authRemovedRes.headers.get("location") || "";
  assert.ok(removedLocation.includes("error=access_denied"), "Removed user must redirect with error=access_denied");

  // Case C: Super-Admin has NO bypass for consumer applications
  const superAdminEmail = `super_no_bypass_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const superAdminSignUp = await authProvider.api.signUpEmail({
    body: { email: superAdminEmail, password: pass, name: "Super Admin No Bypass" },
  });
  await db.collection("user").updateOne(
    { email: superAdminEmail },
    { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
  );
  const superLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: superAdminEmail, password: pass }),
  });
  const superCookie = (superLoginRes.headers.get("set-cookie") || "").split(";")[0];

  const superAuthRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${privateClientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&state=state_super`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: superCookie }),
    }
  );
  assert.equal(superAuthRes.status, 302);
  const superLoc = superAuthRes.headers.get("location") || "";
  assert.ok(superLoc.includes("error=access_denied"), "Super-Admin must be denied authorization for consumer app");
});

// =============================================================================
// TEST 9: Real Route: POST /api/auth/oauth2/token rejects token refresh for revoked/removed user
// =============================================================================
await runTest("MEM-9: Real token route rejects token refresh when user is revoked or removed", async () => {
  const email = `token_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const pass = "TokenUserPass123!Aa";
  const signUp = await authProvider.api.signUpEmail({
    body: { email, password: pass, name: "Token User" },
  });
  const uid = String(signUp.user.id);

  const clientDoc = await db.collection("oauthClient").findOne({ clientId: privateClientId });
  const clientSecret = clientDoc.clientSecret;

  const rawRefreshToken = "rt_test_" + crypto.randomBytes(16).toString("hex");
  const rawHash = hashToken(rawRefreshToken, "hex");

  // Register active token family for this user on the private client
  await registerTokenFamily("fam_" + crypto.randomBytes(8).toString("hex"), privateClientId, uid, rawHash);
  await db.collection("oauthRefreshToken").insertOne({
    token: rawRefreshToken,
    clientId: privateClientId,
    userId: uid,
    createdAt: new Date(),
  });

  // User registration is explicitly revoked
  await db.collection("user_app_registrations").insertOne({
    userId: uid,
    clientId: privateClientId,
    status: "revoked",
    revoked: true,
    createdAt: new Date(),
  });

  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "content-type": "application/x-www-form-urlencoded",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: rawRefreshToken,
      client_id: privateClientId,
      client_secret: clientSecret,
    }).toString(),
  });
  assert.equal(tokenRes.status, 401, "Token refresh must be rejected with 401 for revoked user");
  const tokenJson = await tokenRes.json();
  assert.equal(tokenJson.error, "invalid_grant");
  assert.ok(tokenJson.error_description.includes("no longer authorized"));
});

// =============================================================================
// TEST 10: Admin Routes: Revoked or removed app admin cannot manage application
// =============================================================================
await runTest("MEM-10: Revoked or removed app admin is strictly forbidden on admin management routes", async () => {
  const adminEmail = `admin_mgmt_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const adminPass = "AdminMgmtPass123!Aa";
  const signUp = await authProvider.api.signUpEmail({
    body: { email: adminEmail, password: adminPass, name: "Admin Mgmt User" },
  });
  const adminUid = String(signUp.user.id);

  // Set user role to app-admin scoped to privateClientId
  await db.collection("user").updateOne(
    { _id: new ObjectId(adminUid) },
    { $set: { role: "app-admin", scopedClientId: privateClientId, emailVerified: true } }
  );

  // Insert active app_admins record
  const adminDocId = new ObjectId();
  await db.collection("app_admins").insertOne({
    _id: adminDocId,
    userId: adminUid,
    clientId: privateClientId,
    email: adminEmail,
    role: "admin",
    isActive: true,
    status: "active",
    createdAt: new Date(),
  });

  // Login as app admin
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: adminEmail, password: adminPass }),
  });
  assert.equal(loginRes.status, 200);
  const adminCookie = (loginRes.headers.get("set-cookie") || "").split(";")[0];

  // While active: can access scoped app endpoint
  const activeRes = await app.request(`/api/admin/app/${privateClientId}/config`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: adminCookie }),
  });
  assert.equal(activeRes.status, 200, "Active app admin must have access");

  // Now revoke in app_admins: isActive: false, status: "revoked"
  await db.collection("app_admins").updateOne(
    { _id: adminDocId },
    { $set: { isActive: false, status: "revoked" } }
  );

  const revokedRes = await app.request(`/api/admin/app/${privateClientId}/config`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: adminCookie }),
  });
  assert.equal(revokedRes.status, 403, "Revoked app admin must receive 403 Forbidden");

  // Now delete app_admins record completely (removed assignment)
  await db.collection("app_admins").deleteOne({ _id: adminDocId });
  await db.collection("user_app_registrations").deleteMany({ clientId: privateClientId, userId: adminUid });
  // User still holds scopedClientId: privateClientId on their user record
  const removedRes = await app.request(`/api/admin/app/${privateClientId}/config`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: adminCookie }),
  });
  assert.equal(removedRes.status, 403, "Removed app admin must receive 403 Forbidden even if scopedClientId matches");
});

// =============================================================================
// TEST 11: Production-mode integration test: trustedOrigins, CORS, and CSRF
// =============================================================================
await runTest("MEM-11: Production-mode integration validates trustedOrigins, CORS, and CSRF boundaries", async () => {
  const savedEnv = process.env.NODE_ENV;
  const savedAllowDev = process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION;

  try {
    process.env.NODE_ENV = "production";
    process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION = "false";

    // 1. Better Auth trustedOrigins does NOT contain localhost in production
    const reqWithLocalhost = new Request("http://localhost:3000/api/auth/sign-in/email", {
      headers: { origin: "http://localhost:3000" },
    });
    const prodOrigins = await (authProvider as any).options.trustedOrigins(reqWithLocalhost);
    assert.equal(
      prodOrigins.includes("http://localhost:3000"),
      false,
      "Localhost origin must NOT be present in trustedOrigins in production"
    );
    assert.equal(
      prodOrigins.includes("http://127.0.0.1:5174"),
      false,
      "127.0.0.1 origin must NOT be present in trustedOrigins in production"
    );

    // 2. Real HTTP request with localhost Origin in production fails CORS with 403
    const corsRes = await app.request("/api/auth/sign-in/email", {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
      },
    });
    assert.equal(corsRes.status, 403, "CORS preflight for unallowed localhost origin must be rejected with 403");

    // 3. Registered production HTTPS origin is trusted
    const prodOrigin = "https://customer-portal.swyra.com";
    const reqWithProdOrigin = new Request("http://localhost:3000/api/auth/sign-in/email", {
      headers: { origin: prodOrigin },
    });
    const prodOriginsAfter = await (authProvider as any).options.trustedOrigins(reqWithProdOrigin);
    assert.equal(
      prodOriginsAfter.includes(prodOrigin),
      true,
      "Registered production HTTPS origin must be present in trustedOrigins"
    );

    const corsProdRes = await app.request("/api/auth/sign-in/email", {
      method: "OPTIONS",
      headers: {
        Origin: prodOrigin,
        "Access-Control-Request-Method": "POST",
      },
    });
    assert.equal(corsProdRes.status, 204, "CORS preflight for registered production HTTPS origin must succeed with 204");
  } finally {
    process.env.NODE_ENV = savedEnv;
    if (savedAllowDev === undefined) {
      delete process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION;
    } else {
      process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION = savedAllowDev;
    }
  }
});

// =============================================================================
// TEST 12: Bind app-admin authorization strictly to stable user IDs
// An app_admins record with matching email must NEVER grant privileges if userId differs
// =============================================================================
await runTest("MEM-12: App admin authorization strictly requires matching immutable userId, never email alone", async () => {
  const stableClientId = "test_stable_id_client_" + crypto.randomBytes(4).toString("hex");
  await db.collection("oauthClient").insertOne({
    _id: stableClientId as any,
    id: stableClientId,
    clientId: stableClientId,
    client_id: stableClientId,
    clientSecret: "secret_" + crypto.randomBytes(16).toString("hex"),
    name: "Stable ID App",
    isPublic: false,
    isDev: false,
    allowedOrigins: ["https://stable-app.example.com"],
    redirectUris: ["https://stable-app.example.com/callback"],
    status: "active",
    disabled: false,
    createdAt: new Date(),
  });

  const legitimateEmail = `legit_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const attackerEmail = `attacker_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password123!Aa";

  // Create Legitimate User A
  const signUpA = await authProvider.api.signUpEmail({
    body: { email: legitimateEmail, password, name: "Legitimate Admin" },
  });
  const userAId = String(signUpA.user.id);
  await db.collection("user").updateOne(
    { _id: new ObjectId(userAId) },
    { $set: { role: "admin", scopedClientId: stableClientId, emailVerified: true } }
  );

  // Create Attacker User B
  const signUpB = await authProvider.api.signUpEmail({
    body: { email: attackerEmail, password, name: "Attacker User" },
  });
  const userBId = String(signUpB.user.id);
  await db.collection("user").updateOne(
    { _id: new ObjectId(userBId) },
    { $set: { role: "admin", scopedClientId: stableClientId, emailVerified: true } }
  );

  // Provision app_admins assignment strictly for User A's userId, but with attacker's email to test email spoofing
  await db.collection("app_admins").insertOne({
    userId: userAId,
    clientId: stableClientId,
    email: attackerEmail,
    role: "admin",
    status: "active",
    isActive: true,
    createdAt: new Date(),
  });
  await db.collection("user_app_registrations").insertOne({
    userId: userAId,
    clientId: stableClientId,
    appRole: "admin",
    status: "active",
    isActive: true,
    registeredAt: new Date(),
  });

  // Check checkUserIsClientAdmin directly for User B: must be FALSE because userId does not match even though email matches
  const userBDoc = await db.collection("user").findOne({ _id: new ObjectId(userBId) });
  const isBAdmin = await checkUserIsClientAdmin(db, userBDoc, userBId, stableClientId);
  assert.equal(isBAdmin, false, "User B with matching email but differing userId must NOT receive admin rights");

  // Login as User B and attempt real admin route: must be rejected with 403
  const loginBRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: attackerEmail, password }),
  });
  assert.equal(loginBRes.status, 200);
  const cookieB = (loginBRes.headers.get("set-cookie") || "").split(";")[0];
  const bRouteRes = await app.request(`/api/admin/app/${stableClientId}/config`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookieB }),
  });
  assert.equal(bRouteRes.status, 403, "User B must receive 403 Forbidden on client admin route despite matching email");

  // Verify User A with matching userId gets 200 OK
  const userADoc = await db.collection("user").findOne({ _id: new ObjectId(userAId) });
  const isAAdmin = await checkUserIsClientAdmin(db, userADoc, userAId, stableClientId);
  assert.equal(isAAdmin, true, "User A with matching userId must receive admin rights");

  const loginARes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: legitimateEmail, password }),
  });
  assert.equal(loginARes.status, 200);
  const cookieA = (loginARes.headers.get("set-cookie") || "").split(";")[0];
  const aRouteRes = await app.request(`/api/admin/app/${stableClientId}/config`, {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookieA }),
  });
  assert.equal(aRouteRes.status, 200, "User A must receive 200 OK on client admin route");
});

// =============================================================================
// TEST 13: Email change preserves access; deleted and recreated user denied
// =============================================================================
await runTest("MEM-13: Email change preserves access; deleted and recreated user denied", async () => {
  const lifecycleClientId = "test_lifecycle_id_client_" + crypto.randomBytes(4).toString("hex");
  await db.collection("oauthClient").insertOne({
    _id: lifecycleClientId as any,
    id: lifecycleClientId,
    clientId: lifecycleClientId,
    client_id: lifecycleClientId,
    clientSecret: "secret_" + crypto.randomBytes(16).toString("hex"),
    name: "Lifecycle Client",
    isPublic: false,
    isDev: false,
    allowedOrigins: ["https://lifecycle-app.example.com"],
    redirectUris: ["https://lifecycle-app.example.com/callback"],
    status: "active",
    disabled: false,
    createdAt: new Date(),
  });

  const originalEmail = `original_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const updatedEmail = `updated_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password123!Aa";

  // Create User
  const signUp = await authProvider.api.signUpEmail({
    body: { email: originalEmail, password, name: "Original Admin" },
  });
  const originalUserId = String(signUp.user.id);
  await db.collection("user").updateOne({ _id: new ObjectId(originalUserId) }, { $set: { emailVerified: true } });

  await db.collection("app_admins").insertOne({
    userId: originalUserId,
    clientId: lifecycleClientId,
    email: originalEmail,
    role: "admin",
    status: "active",
    isActive: true,
    createdAt: new Date(),
  });
  await db.collection("user_app_registrations").insertOne({
    userId: originalUserId,
    clientId: lifecycleClientId,
    appRole: "admin",
    status: "active",
    isActive: true,
    registeredAt: new Date(),
  });

  // 1. Email change: user doc updates email to updatedEmail
  await db.collection("user").updateOne({ _id: new ObjectId(originalUserId) }, { $set: { email: updatedEmail } });
  const updatedUserDoc = await db.collection("user").findOne({ _id: new ObjectId(originalUserId) });

  const isStillAdmin = await checkUserIsClientAdmin(db, updatedUserDoc, originalUserId, lifecycleClientId);
  assert.equal(isStillAdmin, true, "User must preserve admin access after email change because userId matches");

  // 2. User is deleted and a new user signs up with the original email
  await db.collection("user").deleteOne({ _id: new ObjectId(originalUserId) });

  const recreatedSignUp = await authProvider.api.signUpEmail({
    body: { email: originalEmail, password, name: "Recreated User" },
  });
  const recreatedUserId = String(recreatedSignUp.user.id);
  assert.notEqual(recreatedUserId, originalUserId, "Recreated user must have a new distinct userId");

  const recreatedUserDoc = await db.collection("user").findOne({ _id: new ObjectId(recreatedUserId) });
  const isRecreatedAdmin = await checkUserIsClientAdmin(db, recreatedUserDoc, recreatedUserId, lifecycleClientId);
  assert.equal(isRecreatedAdmin, false, "Recreated user with same email must NOT inherit previous user's admin access");
});

// =============================================================================
// TEST 14: Duplicate app_admins records: revoked status takes precedence
// =============================================================================
await runTest("MEM-14: Duplicate app_admins records: revoked or inactive status strictly denies admin rights", async () => {
  const dupClientId = "test_dup_id_client_" + crypto.randomBytes(4).toString("hex");
  const testUserId = new ObjectId().toString();
  const testUserDoc = { _id: new ObjectId(testUserId), id: testUserId, email: "dup@example.com", role: "user" };

  // Insert two records for same user and client: one active, one revoked
  await db.collection("app_admins").insertMany([
    {
      userId: testUserId,
      clientId: dupClientId,
      status: "active",
      isActive: true,
      createdAt: new Date(Date.now() - 5000),
    },
    {
      userId: testUserId,
      clientId: dupClientId,
      status: "revoked",
      isActive: false,
      createdAt: new Date(),
    },
  ]);

  // checkUserIsClientAdmin must evaluate both and fail closed on any inactive/revoked record
  const isAdmin = await checkUserIsClientAdmin(db, testUserDoc, testUserId, dupClientId);
  assert.equal(isAdmin, false, "Revoked duplicate record must cause admin authorization to fail closed");
});

// =============================================================================
// TEST 15: Unsafe legacy fallback removed: role 'admin' and scopedClientId without assignment record is strictly denied
// =============================================================================
await runTest("MEM-15: Removal of unsafe legacy fallback: role 'admin' with scopedClientId without assignment record is denied", async () => {
  const unassignedClientId = "test_unassigned_client_" + crypto.randomBytes(4).toString("hex");
  const legacyUserId = new ObjectId().toString();
  const legacyUserDoc = {
    _id: new ObjectId(legacyUserId),
    id: legacyUserId,
    email: "legacy_unassigned@example.com",
    role: "admin",
    scopedClientId: unassignedClientId,
  };

  // Ensure NO record exists in app_admins or user_app_registrations
  const hasAppAdmin = await db.collection("app_admins").findOne({ userId: legacyUserId, clientId: unassignedClientId });
  assert.equal(hasAppAdmin, null);

  const isAdmin = await checkUserIsClientAdmin(db, legacyUserDoc, legacyUserId, unassignedClientId);
  assert.equal(isAdmin, false, "Unassigned user must NOT be granted admin rights merely by scopedClientId without assignment record");
});

// =============================================================================
// TEST 16: Safe test and benchmark infrastructure isolation guard
// =============================================================================
await runTest("MEM-16: Test infrastructure isolation guard blocks non-disposable Mongo and remote Redis", async () => {
  // 1. validateDisposableMongoUri rejects remote / production Mongo URIs
  assert.throws(
    () => validateDisposableMongoUri("mongodb+srv://admin:pass@cluster0.abc.mongodb.net/prod"),
    /SECURITY_VIOLATION/,
    "Remote Atlas mongodb+srv URI must be rejected"
  );
  assert.throws(
    () => validateDisposableMongoUri("mongodb://prod-db.internal.swyra.com:27017/prod"),
    /SECURITY_VIOLATION/,
    "Non-loopback remote Mongo URI must be rejected"
  );

  // 2. validateDisposableMongoUri permits loopback / local disposable URIs
  assert.doesNotThrow(() => validateDisposableMongoUri("mongodb://127.0.0.1:27017/disposable_test"));
  assert.doesNotThrow(() => validateDisposableMongoUri("mongodb://localhost:27017/disposable_test"));

  // 3. Redis alias stripping
  process.env.UPSTASH_REDIS_REST_URL = "https://stray-external-redis.upstash.io";
  process.env.REDIS_URL = "redis://stray-redis:6379";
  isolateTestEnvironment();

  assert.equal(process.env.UPSTASH_REDIS_REST_URL, undefined, "UPSTASH_REDIS_REST_URL must be stripped");
  assert.equal(process.env.REDIS_URL, undefined, "REDIS_URL must be stripped");
  assert.doesNotThrow(() => assertNoExternalInfrastructure());
});

// =============================================================================
// TEST 17: Cross-source conflicts: revocation in either source strictly denies access
// =============================================================================
await runTest("MEM-17: Cross-source conflict: explicit revocation in either app_admins or user_app_registrations denies access", async () => {
  const conflictClientId = "test_conflict_client_" + crypto.randomBytes(4).toString("hex");
  const conflictOrigin = "https://conflict-client.example.com";
  await db.collection("oauthClient").insertOne({
    _id: conflictClientId as any,
    id: conflictClientId,
    clientId: conflictClientId,
    client_id: conflictClientId,
    name: "Conflict Test Client",
    isPublic: false,
    isDev: false,
    disabled: false,
    redirectUris: [`${conflictOrigin}/callback`],
    allowedOrigins: [conflictOrigin],
  });

  // User 1: Active in app_admins, but REVOKED in user_app_registrations
  const user1Pass = "PassConflict1!Aa";
  const user1SignUp = await authProvider.api.signUpEmail({
    body: { email: `conflict1_${Date.now()}@example.com`, password: user1Pass, name: "Conflict User 1" },
  });
  const user1Id = String(user1SignUp.user.id);
  const user1Doc = await db.collection("user").findOne({ _id: new ObjectId(user1Id) });

  await db.collection("app_admins").insertOne({
    userId: user1Id,
    clientId: conflictClientId,
    status: "active",
    isActive: true,
  });
  await db.collection("user_app_registrations").insertOne({
    userId: user1Id,
    clientId: conflictClientId,
    status: "revoked",
    isActive: false,
    revoked: true,
    registeredAt: new Date(),
  });

  assert.equal(await checkUserIsClientAdmin(db, user1Doc, user1Id, conflictClientId), false, "User 1 must be denied admin privileges");
  assert.equal(await checkUserHasAppAccess(db, user1Doc, conflictClientId), false, "User 1 must be denied private app access");

  // User 2: Active in user_app_registrations, but REVOKED in app_admins
  const user2Pass = "PassConflict2!Aa";
  const user2SignUp = await authProvider.api.signUpEmail({
    body: { email: `conflict2_${Date.now()}@example.com`, password: user2Pass, name: "Conflict User 2" },
  });
  const user2Id = String(user2SignUp.user.id);
  const user2Doc = await db.collection("user").findOne({ _id: new ObjectId(user2Id) });

  await db.collection("user_app_registrations").insertOne({
    userId: user2Id,
    clientId: conflictClientId,
    status: "active",
    isActive: true,
    registeredAt: new Date(),
  });
  await db.collection("app_admins").insertOne({
    userId: user2Id,
    clientId: conflictClientId,
    status: "suspended",
    isActive: false,
    revoked: true,
  });

  assert.equal(await checkUserIsClientAdmin(db, user2Doc, user2Id, conflictClientId), false, "User 2 must be denied admin privileges");
  assert.equal(await checkUserHasAppAccess(db, user2Doc, conflictClientId), false, "User 2 must be denied private app access");

  // Test real route behavior: login User 2 and request authorize
  const user2LoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: user2Doc.email, password: user2Pass }),
  });
  assert.equal(user2LoginRes.status, 200);
  const user2Cookie = (user2LoginRes.headers.get("set-cookie") || "").split(";")[0];

  const authRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${conflictClientId}&redirect_uri=${encodeURIComponent(`${conflictOrigin}/callback`)}&response_type=code&scope=openid&state=state_c1&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256`,
    {
      method: "GET",
      headers: getTestHeaders({ cookie: user2Cookie }),
    }
  );
  assert.equal(authRes.status, 302, "Must redirect unassigned/revoked user");
  const redirectLocation = authRes.headers.get("location") || "";
  assert.ok(redirectLocation.includes("error=access_denied"), "Redirect must contain error=access_denied");
});

// =============================================================================
// TEST 18: Safe legacy migration with dry-run, audit, and email reuse detection
// =============================================================================
await runTest("MEM-18: Safe legacy migration handles dry-run, email reuse, and explicit revocation preservation", async () => {
  const migClientId = "test_mig_client_" + crypto.randomBytes(4).toString("hex");

  // 1. Dry run: audits but does NOT mutate database
  const migEmail1 = `legacy1_${Date.now()}@example.com`;
  const user1SignUp = await authProvider.api.signUpEmail({
    body: { email: migEmail1, password: "Password123!Aa", name: "Legacy User 1" },
  });
  const user1Id = String(user1SignUp.user.id);
  const legacyDoc1 = {
    _id: new ObjectId(),
    clientId: migClientId,
    email: migEmail1,
    status: "active",
    createdAt: new Date(),
  };
  await db.collection("app_admins").insertOne(legacyDoc1);

  const dryRunRes = await migrateLegacyAppAdmins(db, { dryRun: true });
  assert.equal(dryRunRes.migratedCount, 1, "Dry run must report 1 record eligible for migration");

  // Verify doc was NOT mutated in DB
  const unmutated = await db.collection("app_admins").findOne({ _id: legacyDoc1._id });
  assert.equal(unmutated.userId, undefined, "Dry run must NOT set userId in DB");

  // 2. Apply mode: persists migration
  const applyRes = await migrateLegacyAppAdmins(db, { dryRun: false });
  assert.equal(applyRes.migratedCount, 1, "Apply mode must report 1 migrated record");
  const mutated = await db.collection("app_admins").findOne({ _id: legacyDoc1._id });
  assert.equal(mutated.userId, user1Id, "Apply mode must persist resolved userId");

  // 3. Repeated migration run: idempotent, reports 0 newly migrated
  const repeatRes = await migrateLegacyAppAdmins(db, { dryRun: false });
  assert.equal(repeatRes.migratedCount, 0, "Repeated migration run must find 0 unmigrated records");

  // 4. Email reuse detection: user created significantly after admin assignment
  const reuseEmail = `reuse_${Date.now()}@example.com`;
  const oldAssignmentDate = new Date(Date.now() - 365 * 24 * 3600 * 1000); // 1 year ago
  const legacyReuseDoc = {
    _id: new ObjectId(),
    clientId: migClientId,
    email: reuseEmail,
    status: "active",
    createdAt: oldAssignmentDate,
  };
  await db.collection("app_admins").insertOne(legacyReuseDoc);

  // New user signs up today
  await authProvider.api.signUpEmail({
    body: { email: reuseEmail, password: "Password123!Aa", name: "New User Reused Email" },
  });

  const reuseRes = await migrateLegacyAppAdmins(db, { dryRun: false });
  assert.equal(reuseRes.conflictCount, 1, "Email reuse must be flagged as a migration conflict");
  assert.ok(reuseRes.conflicts[0].reason.includes("Potential email reuse"), "Conflict reason must cite potential email reuse");

  // Verify reuse doc was NOT migrated
  const reuseDocAfter = await db.collection("app_admins").findOne({ _id: legacyReuseDoc._id });
  assert.equal(reuseDocAfter.userId, undefined, "Email reuse record must NOT be assigned to new user");

  // 5. Explicit revocation preservation: revoked legacy record remains revoked
  const revokedEmail = `revoked_legacy_${Date.now()}@example.com`;
  const revSignUp = await authProvider.api.signUpEmail({
    body: { email: revokedEmail, password: "Password123!Aa", name: "Revoked Legacy Admin" },
  });
  const revUserId = String(revSignUp.user.id);
  const revUserDoc = await db.collection("user").findOne({ _id: new ObjectId(revUserId) });

  const legacyRevDoc = {
    _id: new ObjectId(),
    clientId: migClientId,
    email: revokedEmail,
    status: "revoked",
    isActive: false,
    createdAt: new Date(),
  };
  await db.collection("app_admins").insertOne(legacyRevDoc);

  const revMigRes = await migrateLegacyAppAdmins(db, { dryRun: false });
  assert.equal(revMigRes.migratedCount, 1);
  const revMigDoc = await db.collection("app_admins").findOne({ _id: legacyRevDoc._id });
  assert.equal(revMigDoc.userId, revUserId);
  assert.equal(revMigDoc.isActive, false, "Revocation state must be preserved");
  assert.equal(revMigDoc.status, "revoked", "Revocation status must be preserved");

  assert.equal(await checkUserIsClientAdmin(db, revUserDoc, revUserId, migClientId), false, "Migrated revoked admin must remain denied");
  assert.equal(await checkUserHasAppAccess(db, revUserDoc, migClientId), false, "Migrated revoked admin must not have app access");
});

// =============================================================================
// TEST 19: dry-run produces zero database writes including audit records
// =============================================================================
await runTest("MEM-19: migrateLegacyAppAdmins dry-run produces zero database writes", async () => {
  const dryClientId = "test_dry_run_" + crypto.randomBytes(4).toString("hex");
  const dryEmail = `dry_run_${Date.now()}@example.com`;

  // Create a real user
  const drySignUp = await authProvider.api.signUpEmail({
    body: { email: dryEmail, password: "Password123!Aa", name: "Dry Run User" },
  });
  const dryUserId = String(drySignUp.user.id);

  // Insert a legacy admin record without userId
  const dryLegacyDoc = {
    _id: new ObjectId(),
    clientId: dryClientId,
    email: dryEmail,
    status: "active",
    createdAt: new Date(),
  };
  await db.collection("app_admins").insertOne(dryLegacyDoc);

  // Count audit records before dry run
  const auditCountBefore = await db.collection("admin_audit").countDocuments({});

  // Run dry-run migration
  const dryRes = await migrateLegacyAppAdmins(db, { dryRun: true });
  assert.ok(dryRes.migratedCount >= 1, "Dry run must report the eligible record");

  // Verify: no mutation to app_admins
  const docAfterDry = await db.collection("app_admins").findOne({ _id: dryLegacyDoc._id });
  assert.equal(docAfterDry?.userId, undefined, "Dry run must NOT write userId to app_admins");

  // Verify: zero new audit records written
  const auditCountAfter = await db.collection("admin_audit").countDocuments({});
  assert.equal(auditCountAfter, auditCountBefore, "Dry run must NOT write any audit records");

  // Verify: no user_app_registrations created
  const regAfterDry = await db.collection("user_app_registrations").findOne({
    clientId: dryClientId,
    $or: [{ userId: dryUserId }, { userId: drySignUp.user.id }],
  });
  assert.equal(regAfterDry, null, "Dry run must NOT create user_app_registrations");

  // Cleanup
  await db.collection("app_admins").deleteOne({ _id: dryLegacyDoc._id });
});

// =============================================================================
// TEST 20: selfHealAppAdmins does NOT invoke migrateLegacyAppAdmins
// =============================================================================
await runTest("MEM-20: selfHealAppAdmins does not auto-migrate legacy records", async () => {
  const healClientId = "test_heal_nomig_" + crypto.randomBytes(4).toString("hex");
  const healEmail = `heal_legacy_${Date.now()}@example.com`;

  // Create a user
  await authProvider.api.signUpEmail({
    body: { email: healEmail, password: "Password123!Aa", name: "Heal No Migrate" },
  });

  // Insert a legacy admin record WITHOUT userId (the kind migrateLegacyAppAdmins would process)
  const healLegacyDoc = {
    _id: new ObjectId(),
    clientId: healClientId,
    email: healEmail,
    status: "active",
    createdAt: new Date(),
    // userId intentionally absent — this is a legacy record
  };
  await db.collection("app_admins").insertOne(healLegacyDoc);

  // Invoke selfHeal
  await selfHealAppAdmins(db);

  // Verify: legacy record was NOT migrated (userId still absent)
  const docAfterHeal = await db.collection("app_admins").findOne({ _id: healLegacyDoc._id });
  assert.equal(
    docAfterHeal?.userId,
    undefined,
    "selfHealAppAdmins must NOT set userId on legacy records — migration requires explicit --apply"
  );

  // Cleanup
  await db.collection("app_admins").deleteOne({ _id: healLegacyDoc._id });
});

// =============================================================================
// TEST 21: assertIsMemoryServerUri rejects non-matching loopback URIs
// =============================================================================
await runTest("MEM-21: assertIsMemoryServerUri blocks non-matching loopback URIs", async () => {
  // Must pass: mongoUri is the actual memory server URI (already set in process.env.MONGO_URI)
  assert.doesNotThrow(() => assertIsMemoryServerUri(mongoUri), "Must not throw for matching URI");

  // Must throw: a different loopback URI is not this disposable server
  let threw = false;
  try {
    // Temporarily set MONGO_URI to a different loopback port so the assertion can fire
    const saved = process.env.MONGO_URI;
    process.env.MONGO_URI = "mongodb://127.0.0.1:27017/some_other_db";
    try {
      assertIsMemoryServerUri(mongoUri);
    } finally {
      process.env.MONGO_URI = saved;
    }
  } catch (err: any) {
    threw = true;
    assert.ok(err.message.includes("SECURITY_VIOLATION"), "Must include SECURITY_VIOLATION");
  }
  assert.ok(threw, "assertIsMemoryServerUri must throw when active URI differs from disposable server URI");
});

// =============================================================================
// TEST 22: Comprehensive isolation guard alias validation without credential leakage
// =============================================================================
await runTest("MEM-22: Isolation guard verifies all Mongo and Redis aliases and redacts sensitive data", async () => {
  // 1. Verify all Mongo aliases are caught
  for (const alias of MONGO_ALIAS_ENV_VARS) {
    process.env[alias] = "mongodb+srv://secret_user:super_secret_password@prod.cluster.mongodb.net/db";
    let thrownError: any = null;
    try {
      validateDisposableMongoUri(process.env[alias]!, alias);
    } catch (err: any) {
      thrownError = err;
    }
    delete process.env[alias];

    assert.ok(thrownError, `Must throw for non-disposable Mongo alias ${alias}`);
    assert.ok(thrownError.message.includes("SECURITY_VIOLATION"), "Must include SECURITY_VIOLATION");
    assert.ok(!thrownError.message.includes("secret_user"), "Must NEVER leak username in error");
    assert.ok(!thrownError.message.includes("super_secret_password"), "Must NEVER leak password in error");
    assert.ok(!thrownError.message.includes("prod.cluster.mongodb.net"), "Must NEVER leak remote host in error");
  }

  // 2. Verify all Redis aliases are stripped and rejected
  for (const alias of REDIS_ALIAS_ENV_VARS) {
    process.env[alias] = "sensitive-secret-token-xyz-123";
    let thrownError: any = null;
    try {
      assertNoExternalInfrastructure();
    } catch (err: any) {
      thrownError = err;
    }
    delete process.env[alias];

    assert.ok(thrownError, `Must throw for active Redis alias ${alias}`);
    assert.ok(thrownError.message.includes("SECURITY_VIOLATION"), "Must include SECURITY_VIOLATION");
    assert.ok(!thrownError.message.includes("sensitive-secret-token"), "Must NEVER leak token in error");
  }
});

await closeDb();
await mongod.stop();

console.log("\n================================================================");
console.log(`  MEMBERSHIP LIFECYCLE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================\n");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
