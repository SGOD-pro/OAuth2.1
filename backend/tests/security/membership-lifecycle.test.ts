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
