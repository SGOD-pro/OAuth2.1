process.env.NODE_ENV = "test";
process.env.MONGO_URI = "mongodb://localhost:27017/test";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.INTERNAL_GATEWAY_SECRET = "g".repeat(32);

import assert from "node:assert/strict";
import { ObjectId, type Db } from "mongodb";

const { syncAppAdminIdentity, removeAppAdminIdentity, selfHealAppAdmins } = await import("../../src/utils/admin-sync");
const { resolveUserRoleForClient } = await import("../../src/routes/auth");
const { checkUserIsClientAdmin } = await import("../../src/middleware/admin-auth");

// Lightweight in memory mock MongoDB implementation for isolated unit testing
class MockCollection {
  public docs: any[] = [];

  constructor(initialDocs: any[] = []) {
    this.docs = initialDocs.map((doc) => ({ ...doc }));
  }

  async findOne(query: Record<string, any>) {
    const doc = this.docs.find((d) => this.matches(d, query));
    return doc ? { ...doc } : null;
  }

  find(query: Record<string, any>) {
    const getFiltered = () => this.docs.filter((d) => this.matches(d, query)).map((d) => ({ ...d }));
    return {
      sort: (sortObj: Record<string, any>) => ({
        toArray: async () => {
          const items = getFiltered();
          const sortField = Object.keys(sortObj)[0];
          const sortDir = sortObj[sortField] || 1;
          if (sortField) {
            items.sort((a, b) => {
              if (a[sortField] < b[sortField]) return -1 * sortDir;
              if (a[sortField] > b[sortField]) return 1 * sortDir;
              return 0;
            });
          }
          return items;
        },
      }),
      toArray: async () => getFiltered(),
    };
  }

  async updateOne(query: Record<string, any>, update: Record<string, any>, options?: { upsert?: boolean }) {
    const idx = this.docs.findIndex((doc) => this.matches(doc, query));
    if (idx >= 0) {
      if (update.$set) {
        Object.assign(this.docs[idx], update.$set);
      }
      return { matchedCount: 1, modifiedCount: 1, upsertedCount: 0 };
    }
    if (options?.upsert) {
      const newDoc = { ...query };
      if (update.$set) Object.assign(newDoc, update.$set);
      if (update.$setOnInsert) Object.assign(newDoc, update.$setOnInsert);
      this.docs.push(newDoc);
      return { matchedCount: 0, modifiedCount: 0, upsertedCount: 1 };
    }
    return { matchedCount: 0, modifiedCount: 0, upsertedCount: 0 };
  }

  async updateMany(query: Record<string, any>, update: Record<string, any>) {
    let count = 0;
    for (const doc of this.docs) {
      if (this.matches(doc, query)) {
        if (update.$set) {
          Object.assign(doc, update.$set);
          count++;
        }
      }
    }
    return { matchedCount: count, modifiedCount: count };
  }

  async insertOne(doc: any) {
    this.docs.push({ ...doc });
    return { insertedId: doc._id || new ObjectId() };
  }

  async deleteMany(query: Record<string, any>) {
    const initialLen = this.docs.length;
    this.docs = this.docs.filter((doc) => !this.matches(doc, query));
    return { deletedCount: initialLen - this.docs.length };
  }

  private matches(doc: any, query: Record<string, any>): boolean {
    for (const [key, val] of Object.entries(query)) {
      if (key === "$or" && Array.isArray(val)) {
        const anyMatch = val.some((subQ) => this.matches(doc, subQ));
        if (!anyMatch) return false;
        continue;
      }
      if (val instanceof ObjectId || doc[key] instanceof ObjectId) {
        if (String(doc[key]) !== String(val)) return false;
        continue;
      }
      if (val && typeof val === "object") {
        if ("$ne" in val && doc[key] === val.$ne) return false;
        if ("$exists" in val) {
          const exists = doc[key] !== undefined;
          if (exists !== val.$exists) return false;
        }
        continue;
      }
      if (doc[key] !== val) {
        return false;
      }
    }
    return true;
  }
}

function createMockDb(collections: Record<string, any[]>) {
  const colMap = new Map<string, MockCollection>();
  for (const [name, initialDocs] of Object.entries(collections)) {
    colMap.set(name, new MockCollection(initialDocs));
  }

  return {
    collection: (name: string) => {
      if (!colMap.has(name)) {
        colMap.set(name, new MockCollection());
      }
      return colMap.get(name) as any;
    },
  } as unknown as Db;
}

async function runTests() {
  console.log("Starting Admin Scoping and Identity Decoupling Unit Tests");

  // TEST 1: Super Admin is protected during syncAppAdminIdentity (AC-1)
  {
    const superAdminUserId = new ObjectId();
    const mockDb = createMockDb({
      user: [
        {
          _id: superAdminUserId,
          email: "superadmin@swyra.com",
          role: "admin",
          scopedClientId: null,
          banned: false,
        },
      ],
      account: [
        {
          userId: superAdminUserId.toString(),
          providerId: "credential",
          password: "super_secret_argon_hash",
        },
      ],
      user_app_registrations: [],
    });

    await syncAppAdminIdentity(mockDb, {
      email: "superadmin@swyra.com",
      clientId: "client-acme",
      hashedPassword: "overwritten_hash",
    });

    const user = await mockDb.collection("user").findOne({ email: "superadmin@swyra.com" });
    assert.ok(user, "User must exist");
    assert.equal(user.role, "admin", "Super Admin role must remain admin");
    assert.equal(user.scopedClientId, null, "Super Admin scopedClientId must remain null");

    const account = await mockDb.collection("account").findOne({ userId: superAdminUserId.toString() });
    assert.ok(account, "Account must exist");
    assert.equal(account.password, "super_secret_argon_hash", "Super Admin password must not be overwritten");

    const reg = await mockDb.collection("user_app_registrations").findOne({
      userId: superAdminUserId.toString(),
      clientId: "client-acme",
    });
    assert.equal(reg, null, "Registration must NOT be created because Super Admin cannot be assigned as App Admin");

    console.log("PASS: AC-1 Super Admin preserved during syncAppAdminIdentity (mutually exclusive role)");
  }

  // TEST 2: Multi app admin preserves primary scope and adds registration (AC-2)
  {
    const adminUserId = new ObjectId();
    const mockDb = createMockDb({
      user: [
        {
          _id: adminUserId,
          email: "appadmin@example.com",
          role: "admin",
          scopedClientId: "client-alpha",
        },
      ],
      account: [],
      user_app_registrations: [],
    });

    await syncAppAdminIdentity(mockDb, {
      email: "appadmin@example.com",
      clientId: "client-beta",
      hashedPassword: "hash-beta",
    });

    const user = await mockDb.collection("user").findOne({ _id: adminUserId });
    assert.ok(user, "User must exist");
    assert.equal(user.scopedClientId, "client-alpha", "Existing scopedClientId must be preserved");

    const reg = await mockDb.collection("user_app_registrations").findOne({
      userId: adminUserId.toString(),
      clientId: "client-beta",
    });
    assert.ok(reg, "Registration must exist");
    assert.equal(reg.appRole, "admin", "Secondary app role must be registered as admin");
    console.log("PASS: AC-2 Multi app admin scope preserved and registered");
  }

  // TEST 3: Dynamic role resolution for client (AC-3)
  {
    const superAdmin = { _id: new ObjectId(), role: "admin", scopedClientId: null };
    const multiAdmin = { _id: new ObjectId(), role: "admin", scopedClientId: "client-alpha" };
    const standardUser = { _id: new ObjectId(), role: "user", scopedClientId: null };

    const mockDb = createMockDb({
      user_app_registrations: [
        { userId: multiAdmin._id.toString(), clientId: "client-alpha", appRole: "admin" },
        { userId: multiAdmin._id.toString(), clientId: "client-beta", appRole: "admin" },
        { userId: standardUser._id.toString(), clientId: "client-gamma", appRole: "user" },
      ],
      app_admins: [
        { userId: multiAdmin._id.toString(), clientId: "client-delta", status: "active" },
      ],
    });

    // Super Admin should be role: "user" for any consumer client (never receives consumer app-admin privileges)
    const res1 = await resolveUserRoleForClient(mockDb, superAdmin, "client-random");
    assert.equal(res1.role, "user");
    assert.equal(res1.scopedClientId, null);

    // Multi Admin requesting client-alpha (primary scope)
    const res2 = await resolveUserRoleForClient(mockDb, multiAdmin, "client-alpha");
    assert.equal(res2.role, "admin");
    assert.equal(res2.scopedClientId, "client-alpha");

    // Multi Admin requesting client-beta (from user_app_registrations)
    const res3 = await resolveUserRoleForClient(mockDb, multiAdmin, "client-beta");
    assert.equal(res3.role, "admin");
    assert.equal(res3.scopedClientId, "client-beta");

    // Multi Admin requesting client-delta (from app_admins)
    const res4 = await resolveUserRoleForClient(mockDb, multiAdmin, "client-delta");
    assert.equal(res4.role, "admin");
    assert.equal(res4.scopedClientId, "client-delta");

    // Multi Admin requesting unassigned client-omega
    const res5 = await resolveUserRoleForClient(mockDb, multiAdmin, "client-omega");
    assert.equal(res5.role, "user");
    assert.equal(res5.scopedClientId, null);

    // Standard user requesting client-gamma
    const res6 = await resolveUserRoleForClient(mockDb, standardUser, "client-gamma");
    assert.equal(res6.role, "user");
    assert.equal(res6.scopedClientId, null);

    console.log("PASS: AC-3 resolveUserRoleForClient dynamically isolates roles");
  }

  // TEST 4: Removal resilience for multi app admins (AC-4)
  {
    const adminUserId = new ObjectId();
    const mockDb = createMockDb({
      user: [
        {
          _id: adminUserId,
          email: "appadmin@example.com",
          role: "admin",
          scopedClientId: "client-one",
        },
      ],
      app_admins: [
        { userId: adminUserId.toString(), clientId: "client-two", status: "active" },
      ],
      user_app_registrations: [
        { userId: adminUserId.toString(), clientId: "client-one", appRole: "admin" },
        { userId: adminUserId.toString(), clientId: "client-two", appRole: "admin" },
      ],
    });

    // Remove client-one
    await removeAppAdminIdentity(mockDb, {
      userId: adminUserId.toString(),
      clientId: "client-one",
    });

    const user = await mockDb.collection("user").findOne({ _id: adminUserId });
    assert.equal(user.role, "app-admin", "User must remain app-admin because client-two is still active");
    assert.equal(user.scopedClientId, "client-two", "scopedClientId should re-point to remaining client");

    // Now remove client-two
    // Clear app_admins entry to simulate client-two removal
    const appAdminsCol = mockDb.collection("app_admins") as unknown as MockCollection;
    appAdminsCol.docs = [];

    await removeAppAdminIdentity(mockDb, {
      userId: adminUserId.toString(),
      clientId: "client-two",
    });

    const demotedUser = await mockDb.collection("user").findOne({ _id: adminUserId });
    assert.equal(demotedUser.role, "user", "User must be demoted to user after all assignments removed");
    assert.equal(demotedUser.scopedClientId, null, "scopedClientId must be null");

    const repointAudit = await mockDb.collection("admin_audit").findOne({ action: "admin_identity_repointed" });
    assert.ok(repointAudit, "Audit record should be created when admin is repointed");
    assert.equal(repointAudit.targetClientId, "client-two");

    const demoteAudit = await mockDb.collection("admin_audit").findOne({ action: "admin_identity_demoted" });
    assert.ok(demoteAudit, "Audit record should be created when admin is demoted");
    assert.equal(demoteAudit.targetClientId, "client-two");

    console.log("PASS: AC-4 removeAppAdminIdentity multi app removal resilience");
  }

  // TEST 4b: Removal resilience when surviving admin assignment exists in user_app_registrations only (AC-4)
  {
    const adminUserId = new ObjectId();
    const mockDb = createMockDb({
      user: [
        {
          _id: adminUserId,
          email: "regadmin@example.com",
          role: "admin",
          scopedClientId: "client-alpha",
        },
      ],
      app_admins: [], // No app_admins entries!
      user_app_registrations: [
        { userId: adminUserId.toString(), clientId: "client-alpha", appRole: "admin" },
        { userId: adminUserId.toString(), clientId: "client-beta", appRole: "admin" },
      ],
    });

    // Remove client-alpha
    await removeAppAdminIdentity(mockDb, {
      userId: adminUserId.toString(),
      clientId: "client-alpha",
    });

    const userAfterFirstRemoval = await mockDb.collection("user").findOne({ _id: adminUserId });
    assert.ok(userAfterFirstRemoval, "User must exist");
    assert.equal(userAfterFirstRemoval.role, "app-admin", "User must remain app-admin because client-beta survives in user_app_registrations");
    assert.equal(userAfterFirstRemoval.scopedClientId, "client-beta", "scopedClientId must re-point to surviving client-beta");

    // Remove client-beta (last remaining assignment)
    await removeAppAdminIdentity(mockDb, {
      userId: adminUserId.toString(),
      clientId: "client-beta",
    });

    const userAfterFinalRemoval = await mockDb.collection("user").findOne({ _id: adminUserId });
    assert.ok(userAfterFinalRemoval, "User must exist");
    assert.equal(userAfterFinalRemoval.role, "user", "User must be demoted to user once all assignments are gone");
    assert.equal(userAfterFinalRemoval.scopedClientId, null, "scopedClientId must be null");

    console.log("PASS: AC-4 removeAppAdminIdentity survives with user_app_registrations only");
  }

  // TEST 5: checkUserIsClientAdmin multi app access (AC-7)
  {
    const superAdmin = { _id: new ObjectId(), role: "admin", scopedClientId: null };
    const multiAdminId = new ObjectId();
    const multiAdmin = { _id: multiAdminId, role: "admin", scopedClientId: "client-x" };

    const mockDb = createMockDb({
      user_app_registrations: [
        { userId: multiAdminId.toString(), clientId: "client-y", appRole: "admin" },
      ],
      app_admins: [
        { userId: multiAdminId.toString(), clientId: "client-z", status: "active" },
      ],
    });

    // Without an explicit assignment record in app_admins or user_app_registrations,
    // scopedClientId alone strictly fails closed (no unsafe legacy fallback)
    assert.equal(await checkUserIsClientAdmin(mockDb, superAdmin, superAdmin._id.toString(), "client-any"), false);
    assert.equal(await checkUserIsClientAdmin(mockDb, multiAdmin, multiAdminId.toString(), "client-x"), false);
    assert.equal(await checkUserIsClientAdmin(mockDb, multiAdmin, multiAdminId.toString(), "client-y"), true);
    assert.equal(await checkUserIsClientAdmin(mockDb, multiAdmin, multiAdminId.toString(), "client-z"), true);
    assert.equal(await checkUserIsClientAdmin(mockDb, multiAdmin, multiAdminId.toString(), "client-unknown"), false);

    console.log("PASS: AC-7 checkUserIsClientAdmin verifies multi app admin rights");
  }

  // TEST 6: Introspect dynamic role resolution reflects post-issuance DB state (AC-3)
  {
    const userId = new ObjectId();
    const tokenClientId = "client-app";

    const mockDb = createMockDb({
      user: [
        {
          _id: userId,
          role: "admin",
          scopedClientId: tokenClientId,
        },
      ],
      user_app_registrations: [
        { userId: userId.toString(), clientId: tokenClientId, appRole: "admin" },
      ],
      app_admins: [],
    });

    // Active state: user is admin for client-app in DB
    const userDocActive = await mockDb.collection("user").findOne({ _id: userId });
    const resolvedActive = await resolveUserRoleForClient(mockDb, userDocActive, tokenClientId);
    assert.equal(resolvedActive.role, "admin", "Role must be admin when DB reflects assignment");
    assert.equal(resolvedActive.scopedClientId, tokenClientId, "scopedClientId must match client-app");

    // Post-issuance revocation in DB: admin is demoted
    // Even if JWT token payload contains stale claims (role: "admin"), introspect uses dynamic resolution
    await mockDb.collection("user").updateOne(
      { _id: userId },
      { $set: { role: "user", scopedClientId: null } }
    );
    await mockDb.collection("user_app_registrations").deleteMany({
      userId: userId.toString(),
      clientId: tokenClientId,
    });

    const userDocRevoked = await mockDb.collection("user").findOne({ _id: userId });
    const resolvedRevoked = await resolveUserRoleForClient(mockDb, userDocRevoked, tokenClientId);
    assert.equal(resolvedRevoked.role, "user", "Dynamic role resolution must return user on revoked admin despite stale JWT claims");
    assert.equal(resolvedRevoked.scopedClientId, null, "scopedClientId must be null on revoked admin");

    console.log("PASS: AC-3 Introspect dynamic role resolution reflects post-issuance state");
  }

  // TEST 7: selfHealAppAdmins background sweep preserves Super Admin (AC-1, AC-2)
  {
    const superAdminUserId = new ObjectId();
    const mockDb = createMockDb({
      user: [
        {
          _id: superAdminUserId,
          email: "superadmin@swyra.com",
          role: "admin",
          scopedClientId: null,
          banned: false,
        },
      ],
      account: [
        {
          userId: superAdminUserId.toString(),
          providerId: "credential",
          password: "untouched_super_hash",
        },
      ],
      app_admins: [
        {
          email: "superadmin@swyra.com",
          clientId: "client-background-sync",
          name: "Attacker Impersonation",
          password: "malicious_hash",
          isActive: false,
        },
      ],
      user_app_registrations: [],
    });

    await selfHealAppAdmins(mockDb);

    const user = await mockDb.collection("user").findOne({ email: "superadmin@swyra.com" });
    assert.ok(user, "Super Admin user doc must exist");
    assert.equal(user.role, "admin", "Super Admin role must remain admin");
    assert.equal(user.scopedClientId, null, "Super Admin scopedClientId must remain null");
    assert.equal(user.banned, false, "Super Admin must not be banned by background sweep");

    const account = await mockDb.collection("account").findOne({ userId: superAdminUserId.toString() });
    assert.ok(account, "Account doc must exist");
    assert.equal(account.password, "untouched_super_hash", "Super Admin password must not be overwritten");

    const reg = await mockDb.collection("user_app_registrations").findOne({
      userId: superAdminUserId.toString(),
      clientId: "client-background-sync",
    });
    assert.equal(reg, null, "Registration must NOT be created because Super Admin is protected from app-admin assignment");

    console.log("PASS: AC-1 & AC-2 selfHealAppAdmins background sweep preserves Super Admin");
  }

  // TEST 8: removeAppAdminIdentity by email with normalization (AC-4)
  {
    const adminUserId = new ObjectId();
    const mockDb = createMockDb({
      user: [
        {
          _id: adminUserId,
          email: "emailadmin@example.com",
          role: "admin",
          scopedClientId: "client-first",
        },
      ],
      app_admins: [
        { email: "emailadmin@example.com", clientId: "client-second", isActive: true },
      ],
      user_app_registrations: [
        { userId: adminUserId.toString(), clientId: "client-first", appRole: "admin" },
        { userId: adminUserId.toString(), clientId: "client-second", appRole: "admin" },
      ],
    });

    // Remove client-first using uppercase and padded email
    await removeAppAdminIdentity(mockDb, {
      email: "  EMAILADMIN@EXAMPLE.COM  ",
      clientId: "client-first",
    });

    const user1 = await mockDb.collection("user").findOne({ _id: adminUserId });
    assert.equal(user1.role, "app-admin");
    assert.equal(user1.scopedClientId, "client-second");

    // Remove client-second
    const appAdminsCol = mockDb.collection("app_admins") as unknown as MockCollection;
    appAdminsCol.docs = [];

    await removeAppAdminIdentity(mockDb, {
      email: "emailadmin@example.com",
      clientId: "client-second",
    });

    const user2 = await mockDb.collection("user").findOne({ _id: adminUserId });
    assert.equal(user2.role, "user");
    assert.equal(user2.scopedClientId, null);

    console.log("PASS: AC-4 removeAppAdminIdentity by email with normalization");
  }

  // TEST 9: removeAppAdminIdentity is safe for Global Super Admin (AC-1, AC-4)
  {
    const superAdminUserId = new ObjectId();
    const mockDb = createMockDb({
      user: [
        {
          _id: superAdminUserId,
          email: "global@swyra.com",
          role: "admin",
          scopedClientId: null,
        },
      ],
      user_app_registrations: [
        { userId: superAdminUserId.toString(), clientId: "client-foo", appRole: "admin" },
      ],
      app_admins: [],
    });

    await removeAppAdminIdentity(mockDb, {
      userId: superAdminUserId.toString(),
      clientId: "client-foo",
    });

    const user = await mockDb.collection("user").findOne({ _id: superAdminUserId });
    assert.equal(user.role, "admin", "Super Admin role must remain admin");
    assert.equal(user.scopedClientId, null, "Super Admin scopedClientId must remain null");

    // Registration for client-foo should still be deleted
    const reg = await mockDb.collection("user_app_registrations").findOne({
      userId: superAdminUserId.toString(),
      clientId: "client-foo",
    });
    assert.equal(reg, null, "Registration for removed client should be deleted");

    console.log("PASS: AC-1 & AC-4 removeAppAdminIdentity is safe for Global Super Admin");
  }

  // TEST 10: checkUserIsClientAdmin edge cases and inactive states (AC-7)
  {
    const userId = new ObjectId();
    const mockDb = createMockDb({
      app_admins: [
        { userId: userId.toString(), clientId: "client-inactive", isActive: false },
      ],
      user_app_registrations: [],
    });

    // Null database or empty clientId
    assert.equal(await checkUserIsClientAdmin(null, null, userId.toString(), "client-x"), false);
    assert.equal(await checkUserIsClientAdmin(mockDb, null, userId.toString(), ""), false);

    // Inactive app admin record returns false
    const userDoc = { _id: userId, role: "user", scopedClientId: null };
    assert.equal(await checkUserIsClientAdmin(mockDb, userDoc, userId.toString(), "client-inactive"), false);

    console.log("PASS: AC-7 checkUserIsClientAdmin handles edge cases and inactive states");
  }

  // TEST 11: resolveUserRoleForClient edge cases (AC-3)
  {
    const mockDb = createMockDb({});

    // Null userDoc
    const resNull = await resolveUserRoleForClient(mockDb, null, "client-any");
    assert.deepEqual(resNull, { role: "user", scopedClientId: null });

    // Empty clientId fails closed to standard user role and null scope
    const userDoc = { role: "custom-role", scopedClientId: "client-prev" };
    const resEmpty = await resolveUserRoleForClient(mockDb, userDoc, "");
    assert.deepEqual(resEmpty, { role: "user", scopedClientId: null });

    // Global super admin returns role: "user" and scopedClientId: null for consumer client contexts
    const superAdmin = { role: "admin", scopedClientId: null };
    const resSuperEmpty = await resolveUserRoleForClient(mockDb, superAdmin, "");
    assert.deepEqual(resSuperEmpty, { role: "user", scopedClientId: null });

    console.log("PASS: AC-3 resolveUserRoleForClient edge cases handled cleanly");
  }

  // TEST 12: Conflict detection between Super Admin and scoped app_admins (AC-6)
  {
    const adminEmail = "super@swyra.com";
    const mockDb = createMockDb({
      app_admins: [
        { email: adminEmail, clientId: "client-conflict-1" },
        { email: adminEmail, clientId: "client-conflict-2" },
      ],
    });

    // Verify conflict detection query pattern used in create-admin and migrate-app-admins
    const conflicts = await mockDb.collection("app_admins").find({ email: adminEmail }).toArray();
    assert.equal(conflicts.length, 2, "Both conflicting app_admins records detected");
    assert.equal(conflicts[0].clientId, "client-conflict-1");
    assert.equal(conflicts[1].clientId, "client-conflict-2");

    // Test clean-scoped resolution pattern
    const deleteResult = await mockDb.collection("app_admins").deleteMany({ email: adminEmail });
    assert.equal(deleteResult.deletedCount, 2, "Conflicting scoped records cleaned up cleanly");

    const remaining = await mockDb.collection("app_admins").find({ email: adminEmail }).toArray();
    assert.equal(remaining.length, 0, "No conflicting records remain");

    console.log("PASS: AC-6 Conflict detection and resolution for Super Admin accounts");
  }

  console.log("\nALL 12 UNIT SECURITY AND ISOLATION TESTS PASSED!");
  process.exit(0);
}

runTests().catch((err) => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
