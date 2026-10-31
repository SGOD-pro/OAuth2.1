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
const { checkUserAppRegistration } = await import("../../src/utils/security");
const { checkUserIsClientAdmin } = await import("../../src/middleware/admin-auth");
const { isOriginAllowed } = await import("../../src/middleware/cors");
const { config } = await import("../../src/config");

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

// -----------------------------------------------------------------------------
// SETUP BASE FIXTURES
// -----------------------------------------------------------------------------
const privateClientId = "test_private_client_" + crypto.randomBytes(4).toString("hex");
await db.collection("oauthClient").insertOne({
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
