import assert from "node:assert/strict";
import crypto from "crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId, type Db } from "mongodb";
import { SignJWT, generateKeyPair, exportJWK } from "jose";

// 1. Start disposable in-memory MongoDB before loading modules
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
const GATEWAY_SECRET = "g".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = GATEWAY_SECRET;

// 2. Import modules
const { getDb, closeDb } = await import("../../src/db/mongo");
const { default: app } = await import("../../src/app");
const {
  isSuperAdmin,
  isAppAdmin,
  isAnyAdmin,
  checkUserIsClientAdmin,
  requireConsumerAppAdmin,
} = await import("../../src/middleware/admin-auth");
const { resolveUserRoleForClient } = await import("../../src/routes/auth");
const { syncAppAdminIdentity, removeAppAdminIdentity, selfHealAppAdmins } = await import("../../src/utils/admin-sync");
const { runIdentityMigration } = await import("../../scripts/migrate-identity-roles");

async function run() {
  console.log("================================================================================");
  console.log("  ADMINISTRATOR IDENTITY & PORTAL ISOLATION VERIFICATION SUITE");
  console.log("================================================================================\n");

  const db = await getDb();

  // Helper to generate a signed JWT for testing bearer auth
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwkPublic = await exportJWK(publicKey);
  jwkPublic.kid = "test-key-id";
  jwkPublic.alg = "RS256";
  jwkPublic.use = "sig";

  // Store key in jwks collection so middleware can resolve public key
  await db.collection("jwks").insertOne({
    kid: "test-key-id",
    publicKey: JSON.stringify(jwkPublic),
    createdAt: new Date(),
  });

  async function createTestJwt(claims: Record<string, any>) {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "test-key-id" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);
  }

  // Seed test OAuth clients: app-alpha and app-beta
  await db.collection("oauthClient").insertMany([
    {
      clientId: "app-alpha",
      name: "App Alpha",
      redirectUris: ["https://alpha.example.com/callback"],
      allowedOrigins: ["https://alpha.example.com"],
      isPublic: true,
      isDev: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      clientId: "app-beta",
      name: "App Beta",
      redirectUris: ["https://beta.example.com/callback"],
      allowedOrigins: ["https://beta.example.com"],
      isPublic: false,
      isDev: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ]);

  // --------------------------------------------------------------------------
  // TEST 1: Canonical Domain Roles Type Checking
  // --------------------------------------------------------------------------
  console.log("[TEST 1] Canonical typed domain roles: super-admin, app-admin, user");
  {
    assert.equal(isSuperAdmin({ role: "super-admin" }), true);
    assert.equal(isSuperAdmin({ role: "admin", scopedClientId: null }), true); // legacy support
    assert.equal(isSuperAdmin({ role: "app-admin" }), false);
    assert.equal(isSuperAdmin({ role: "user" }), false);
    assert.equal(isSuperAdmin({ role: "admin", scopedClientId: "app-alpha" }), false);
    assert.equal(isSuperAdmin({ role: "admin", scopedClientId: "" }), false); // fail-closed on empty string
    assert.equal(isSuperAdmin({ role: "admin", scopedClientId: undefined }), false); // fail-closed on undefined

    assert.equal(isAppAdmin({ role: "app-admin" }), true);
    assert.equal(isAppAdmin({ role: "admin", scopedClientId: "app-alpha" }), true);
    assert.equal(isAppAdmin({ role: "super-admin" }), false);
    assert.equal(isAppAdmin({ role: "user" }), false);

    assert.equal(isAnyAdmin({ role: "super-admin" }), true);
    assert.equal(isAnyAdmin({ role: "app-admin" }), true);
    assert.equal(isAnyAdmin({ role: "user" }), false);
    assert.equal(isAnyAdmin({ role: "unknown" }), false);
    assert.equal(isAnyAdmin(null), false);

    console.log("  [PASS] Canonical typed domain roles correctly isolate roles and fail closed");
  }

  // --------------------------------------------------------------------------
  // TEST 2: Super Admin Platform Access vs Consumer Portal Denied
  // --------------------------------------------------------------------------
  console.log("\n[TEST 2] Super Admin: Platform management allowed, Consumer admin portal denied");
  {
    const superAdminUserId = new ObjectId();
    await db.collection("user").insertOne({
      _id: superAdminUserId,
      email: "superadmin@swyra.com",
      role: "super-admin",
      scopedClientId: null,
      emailVerified: true,
      banned: false,
    });

    const superAdminToken = await createTestJwt({
      sub: superAdminUserId.toString(),
      email: "superadmin@swyra.com",
      role: "super-admin",
      scoped_client_id: null,
      iss: process.env.BETTER_AUTH_URL,
      aud: process.env.BETTER_AUTH_URL,
    });

    // Super Admin accessing platform management endpoint
    const resPlatform = await app.request("/api/admin/clients", {
      method: "GET",
      headers: {
        "x-gateway-secret": GATEWAY_SECRET,
        authorization: `Bearer ${superAdminToken}`,
      },
    });
    assert.equal(resPlatform.status, 200, "Super Admin must access /api/admin/clients");

    // Super Admin accessing consumer client via resolveUserRoleForClient returns role: "user"
    const superAdminUserDoc = await db.collection("user").findOne({ _id: superAdminUserId });
    const resolvedRole = await resolveUserRoleForClient(db, superAdminUserDoc, "app-alpha");
    assert.equal(resolvedRole.role, "user", "Super Admin must receive role: 'user' for consumer apps");
    assert.equal(resolvedRole.scopedClientId, null, "Super Admin must receive scopedClientId: null for consumer apps");

    // checkUserIsClientAdmin returns false for Super Admin
    const isClientAdmin = await checkUserIsClientAdmin(db, superAdminUserDoc, superAdminUserId.toString(), "app-alpha");
    assert.equal(isClientAdmin, false, "Super Admin must never be reported as consumer client admin");

    console.log("  [PASS] Super Admin platform management allowed, consumer admin privileges strictly denied");
  }

  // --------------------------------------------------------------------------
  // TEST 3: App Admin MAuth Dashboard Denied & Cross-Tenant Denied
  // --------------------------------------------------------------------------
  console.log("\n[TEST 3] App Admin: MAuth console denied, cross-tenant denied, own app allowed");
  {
    const appAdminUserId = new ObjectId();
    await db.collection("user").insertOne({
      _id: appAdminUserId,
      email: "alpha-admin@example.com",
      role: "app-admin",
      scopedClientId: "app-alpha",
      emailVerified: true,
      banned: false,
    });

    await db.collection("app_admins").insertOne({
      _id: new ObjectId(),
      userId: appAdminUserId.toString(),
      email: "alpha-admin@example.com",
      clientId: "app-alpha",
      isActive: true,
    });

    const appAdminToken = await createTestJwt({
      sub: appAdminUserId.toString(),
      email: "alpha-admin@example.com",
      role: "admin",
      scoped_client_id: "app-alpha",
      iss: process.env.BETTER_AUTH_URL,
      aud: "app-alpha",
    });

    // 1a. App Admin attempting to access central MAuth platform dashboard APIs with client audience
    const resMAuthAud = await app.request("/api/admin/clients", {
      method: "GET",
      headers: {
        "x-gateway-secret": GATEWAY_SECRET,
        authorization: `Bearer ${appAdminToken}`,
      },
    });
    assert.equal(resMAuthAud.status, 403, "App Admin must be denied central MAuth platform APIs");
    const mauthAudBody = await resMAuthAud.json();
    assert.equal(mauthAudBody.code, "ERR_AUDIENCE_FORBIDDEN");
    assert.ok(mauthAudBody.requestId, "Response must include requestId");

    // 1b. App Admin attempting to access central MAuth platform APIs with platform audience
    const appAdminPlatformAudToken = await createTestJwt({
      sub: appAdminUserId.toString(),
      email: "alpha-admin@example.com",
      role: "admin",
      scoped_client_id: "app-alpha",
      iss: process.env.BETTER_AUTH_URL,
      aud: process.env.BETTER_AUTH_URL,
    });
    const resMAuthRole = await app.request("/api/admin/clients", {
      method: "GET",
      headers: {
        "x-gateway-secret": GATEWAY_SECRET,
        authorization: `Bearer ${appAdminPlatformAudToken}`,
      },
    });
    assert.equal(resMAuthRole.status, 403, "App Admin must be denied central MAuth platform APIs even with platform audience");
    const mauthRoleBody = await resMAuthRole.json();
    assert.equal(mauthRoleBody.code, "ERR_SUPER_ADMIN_REQUIRED");
    assert.ok(mauthRoleBody.requestId, "Response must include requestId");

    // 2. App Admin attempting cross-tenant access to App Beta
    const resCrossTenant = await app.request("/api/admin/clients/app-beta", {
      method: "GET",
      headers: {
        "x-gateway-secret": GATEWAY_SECRET,
        authorization: `Bearer ${appAdminToken}`,
      },
    });
    assert.equal(resCrossTenant.status, 403, "App Admin must be denied other tenant");
    const crossBody = await resCrossTenant.json();
    assert.equal(crossBody.code, "ERR_CROSS_TENANT_FORBIDDEN");

    // 3. App Admin accessing own App Alpha
    const resOwnApp = await app.request("/api/admin/clients/app-alpha", {
      method: "GET",
      headers: {
        "x-gateway-secret": GATEWAY_SECRET,
        authorization: `Bearer ${appAdminToken}`,
      },
    });
    assert.equal(resOwnApp.status, 200, "App Admin must be allowed on own app");

    console.log("  [PASS] App Admin strictly denied central MAuth and other tenants; allowed on own app");
  }

  // --------------------------------------------------------------------------
  // TEST 4: Multi-App Admin Access
  // --------------------------------------------------------------------------
  console.log("\n[TEST 4] Multi-App Admin: Allowed on assigned apps, denied on unassigned apps");
  {
    const multiAdminUserId = new ObjectId();
    await db.collection("user").insertOne({
      _id: multiAdminUserId,
      email: "multi-admin@example.com",
      role: "app-admin",
      scopedClientId: "app-alpha",
      emailVerified: true,
      banned: false,
    });

    await db.collection("app_admins").insertMany([
      { userId: multiAdminUserId.toString(), email: "multi-admin@example.com", clientId: "app-alpha", isActive: true },
      { userId: multiAdminUserId.toString(), email: "multi-admin@example.com", clientId: "app-beta", isActive: true },
    ]);

    const userDoc = await db.collection("user").findOne({ _id: multiAdminUserId });

    assert.equal(await checkUserIsClientAdmin(db, userDoc, multiAdminUserId.toString(), "app-alpha"), true);
    assert.equal(await checkUserIsClientAdmin(db, userDoc, multiAdminUserId.toString(), "app-beta"), true);
    assert.equal(await checkUserIsClientAdmin(db, userDoc, multiAdminUserId.toString(), "app-gamma"), false);

    console.log("  [PASS] Multi-App Admin privileges verified for multiple assigned apps");
  }

  // --------------------------------------------------------------------------
  // TEST 5: Standard User Denied All Admin Surfaces
  // --------------------------------------------------------------------------
  console.log("\n[TEST 5] Standard User: Denied all admin surfaces");
  {
    const standardUserId = new ObjectId();
    await db.collection("user").insertOne({
      _id: standardUserId,
      email: "user@example.com",
      role: "user",
      scopedClientId: null,
      emailVerified: true,
      banned: false,
    });

    const userToken = await createTestJwt({
      sub: standardUserId.toString(),
      email: "user@example.com",
      role: "user",
      iss: process.env.BETTER_AUTH_URL,
      aud: "app-alpha",
    });

    const userPlatformAudToken = await createTestJwt({
      sub: standardUserId.toString(),
      email: "user@example.com",
      role: "user",
      iss: process.env.BETTER_AUTH_URL,
      aud: process.env.BETTER_AUTH_URL,
    });

    // 1. Standard user attempting platform API with platform audience
    const res1 = await app.request("/api/admin/clients", {
      method: "GET",
      headers: {
        "x-gateway-secret": GATEWAY_SECRET,
        authorization: `Bearer ${userPlatformAudToken}`,
      },
    });
    assert.equal(res1.status, 403, "Standard user must be denied platform API");
    const body1 = await res1.json();
    assert.equal(body1.code, "ERR_ROLE_FORBIDDEN");

    // 2. Standard user attempting client admin API with client audience
    const res2 = await app.request("/api/admin/clients/app-alpha", {
      method: "GET",
      headers: {
        "x-gateway-secret": GATEWAY_SECRET,
        authorization: `Bearer ${userToken}`,
      },
    });
    assert.equal(res2.status, 403, "Standard user must be denied client admin API");
    const body2 = await res2.json();
    assert.equal(body2.code, "ERR_ROLE_FORBIDDEN");

    console.log("  [PASS] Standard user denied all admin surfaces with ERR_ROLE_FORBIDDEN");
  }

  // --------------------------------------------------------------------------
  // TEST 6: Gateway Rejection Distinguishable from Role Rejection
  // --------------------------------------------------------------------------
  console.log("\n[TEST 6] Gateway rejection vs Role/Scope rejection distinction");
  {
    // 1. Missing gateway secret
    const resGateway = await app.request("/api/admin/clients", {
      method: "GET",
    });
    assert.equal(resGateway.status, 403);
    const gwBody = await resGateway.json();
    assert.equal(gwBody.code, "ERR_GATEWAY_FORBIDDEN");
    assert.ok(gwBody.requestId, "Must provide requestId");
    assert.ok(resGateway.headers.get("x-request-id"), "Header x-request-id must be present");

    // 2. Gateway secret present, but unauthenticated
    const resUnauth = await app.request("/api/admin/clients", {
      method: "GET",
      headers: { "x-gateway-secret": GATEWAY_SECRET },
    });
    assert.equal(resUnauth.status, 401);
    const unauthBody = await resUnauth.json();
    assert.equal(unauthBody.code, "ERR_UNAUTHENTICATED");
    assert.ok(unauthBody.requestId);

    console.log("  [PASS] ERR_GATEWAY_FORBIDDEN is clearly distinguishable from ERR_UNAUTHENTICATED and role errors");
  }

  // --------------------------------------------------------------------------
  // TEST 7: Mutual Exclusivity - Cannot Assign Super Admin as App Admin
  // --------------------------------------------------------------------------
  console.log("\n[TEST 7] Mutual Exclusivity: Reject assigning Super Admin as App Admin");
  {
    const superAdmin = await db.collection("user").findOne({ email: "superadmin@swyra.com" });
    assert.ok(superAdmin);

    // Call syncAppAdminIdentity with Super Admin email
    await syncAppAdminIdentity(db, {
      email: "superadmin@swyra.com",
      clientId: "app-alpha",
      hashedPassword: "new-password-hash",
    });

    // Check user was NOT converted
    const userAfter = await db.collection("user").findOne({ email: "superadmin@swyra.com" });
    assert.equal(userAfter.role, "super-admin", "Super Admin role must remain super-admin");
    assert.equal(userAfter.scopedClientId, null, "Super Admin scopedClientId must remain null");

    // Registration was NOT created
    const reg = await db.collection("user_app_registrations").findOne({
      userId: superAdmin._id.toString(),
      clientId: "app-alpha",
    });
    assert.equal(reg, null, "No user_app_registrations must be created for Super Admin");

    console.log("  [PASS] Super Admin cannot be assigned as App Admin; mutual exclusivity enforced");
  }

  // --------------------------------------------------------------------------
  // TEST 8: Identity Role Migration Script (Audit, Apply, Idempotency)
  // --------------------------------------------------------------------------
  console.log("\n[TEST 8] Identity Role Migration: Audit dry-run, Apply mode, Idempotency");
  {
    // Seed legacy users:
    // Legacy super admin: role "admin", scopedClientId: null
    const legSuperId = new ObjectId();
    await db.collection("user").insertOne({
      _id: legSuperId,
      email: "legacy-super@swyra.com",
      role: "admin",
      scopedClientId: null,
    });

    // Legacy app admin: role "admin", scopedClientId: "app-alpha"
    const legAppId = new ObjectId();
    await db.collection("user").insertOne({
      _id: legAppId,
      email: "legacy-app@example.com",
      role: "admin",
      scopedClientId: "app-alpha",
    });

    // Ambiguous legacy admin: role "admin", scopedClientId: undefined (missing)
    const legAmbiguousId = new ObjectId();
    await db.collection("user").insertOne({
      _id: legAmbiguousId,
      email: "ambiguous@example.com",
      role: "admin",
      // scopedClientId omitted!
    });

    // 1. Dry run
    const dryRunRes = await runIdentityMigration({ apply: false, dbUri: mongoUri });
    assert.equal(dryRunRes.applied, false, "Dry run must not apply changes");

    // Check docs still have old roles
    const user1 = await db.collection("user").findOne({ _id: legSuperId });
    assert.equal(user1.role, "admin", "Dry run must not modify documents");

    // 2. Apply migration
    const applyRes = await runIdentityMigration({ apply: true, dbUri: mongoUri });
    assert.equal(applyRes.applied, true);

    const migratedSuper = await db.collection("user").findOne({ _id: legSuperId });
    assert.equal(migratedSuper.role, "super-admin", "Legacy super admin must be migrated to 'super-admin'");

    const migratedApp = await db.collection("user").findOne({ _id: legAppId });
    assert.equal(migratedApp.role, "app-admin", "Legacy app admin must be migrated to 'app-admin'");

    const ambiguousUser = await db.collection("user").findOne({ _id: legAmbiguousId });
    assert.equal(ambiguousUser.role, "admin", "Ambiguous user must remain untouched for operator resolution");

    // 3. Idempotent rerun
    const rerunRes = await runIdentityMigration({ apply: true, dbUri: mongoUri });
    assert.equal(rerunRes.applied, true);
    assert.equal(rerunRes.appliedCount, 0, "Rerun must make 0 updates on already migrated documents");

    console.log("  [PASS] Migration dry-run, apply, and idempotency successfully verified");
  }

  console.log("\n================================================================================");
  console.log("  ALL 8 ISOLATION & IDENTITY POLICY TESTS PASSED CLEANLY!");
  console.log("================================================================================\n");

  await closeDb();
  await mongod.stop();
  process.exit(0);
}

run().catch(async (err) => {
  console.error("Test execution failed:", err);
  await closeDb();
  await mongod.stop();
  process.exit(1);
});
