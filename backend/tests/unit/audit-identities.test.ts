import assert from "node:assert/strict";
import {
  isSuperAdminDoc,
  isAppAdminDoc,
  evaluateIdentityAccount,
} from "../../scripts/audit-operator-identities";

console.log("================================================================");
console.log("  SWYRA AUTH -- AUDIT OPERATOR IDENTITIES UNIT TESTS");
console.log("================================================================\n");

// 1. Super Admin Predicate
assert.equal(isSuperAdminDoc({ role: "super-admin", scopedClientId: null }), true);
assert.equal(isSuperAdminDoc({ role: "super-admin", scopedClientId: undefined }), true);
assert.equal(isSuperAdminDoc({ role: "admin", scopedClientId: null }), true);
assert.equal(isSuperAdminDoc({ role: "super-admin", scopedClientId: "client-a" }), false);
assert.equal(isSuperAdminDoc({ role: "super-admin", scopedClientId: "" }), false);
assert.equal(isSuperAdminDoc({ role: "admin", scopedClientId: "client-a" }), false);
assert.equal(isSuperAdminDoc({ role: "admin", scopedClientId: undefined }), false);
assert.equal(isSuperAdminDoc({ role: "user" }), false);
console.log("[PASS] isSuperAdminDoc predicate accurately enforces super admin criteria");

// 2. App Admin Predicate
assert.equal(isAppAdminDoc({ role: "app-admin", scopedClientId: "client-a" }), true);
assert.equal(isAppAdminDoc({ role: "app-admin", scopedClientId: null }), true);
assert.equal(isAppAdminDoc({ role: "app-admin", scopedClientId: undefined }), true);
assert.equal(isAppAdminDoc({ role: "admin", scopedClientId: "client-a" }), true);
assert.equal(isAppAdminDoc({ role: "app-admin", scopedClientId: "" }), false);
assert.equal(isAppAdminDoc({ role: "admin", scopedClientId: "" }), false);
assert.equal(isAppAdminDoc({ role: "admin", scopedClientId: null }), false);
assert.equal(isAppAdminDoc({ role: "super-admin", scopedClientId: null }), false);
assert.equal(isAppAdminDoc({ role: "user" }), false);
console.log("[PASS] isAppAdminDoc predicate accurately enforces app admin criteria");

// 3. Identity Evaluation Classifications
const validSuper = evaluateIdentityAccount({ role: "super-admin", scopedClientId: null }, []);
assert.ok(validSuper.startsWith("VALID Super-Admin"), "Super admin without assignments must be valid");

const conflictSuperAssignments = evaluateIdentityAccount(
  { role: "super-admin", scopedClientId: null },
  ["client-a", "client-b"]
);
assert.ok(conflictSuperAssignments.startsWith("INVALID (Conflict:"), "Super admin with assignments must be flagged as conflict");

const conflictSuperScope = evaluateIdentityAccount(
  { role: "super-admin", scopedClientId: "client-a" },
  []
);
assert.ok(conflictSuperScope.startsWith("INVALID (Conflict:"), "Super admin with client scope must be flagged as conflict");

const validApp = evaluateIdentityAccount(
  { role: "app-admin", scopedClientId: "client-a" },
  ["client-a"]
);
assert.ok(validApp.startsWith("VALID App-Admin"), "App admin with scope and assignments must be valid");

const validMultiApp = evaluateIdentityAccount(
  { role: "app-admin", scopedClientId: null },
  ["client-a", "client-b"]
);
assert.ok(validMultiApp.startsWith("VALID App-Admin"), "Multi-app admin with assignments must be valid");

const ambiguousLegacyAdmin = evaluateIdentityAccount(
  { role: "admin", scopedClientId: undefined },
  []
);
assert.ok(ambiguousLegacyAdmin.startsWith("INVALID (Ambiguous legacy admin"), "Legacy admin with undefined scope must fail closed");

const flaggedStandardUser = evaluateIdentityAccount(
  { role: "user", scopedClientId: "client-a" },
  ["client-a"]
);
assert.ok(flaggedStandardUser.startsWith("FLAGGED (Standard user"), "Standard user with assignments must be flagged");

const validStandardUser = evaluateIdentityAccount({ role: "user" }, []);
assert.equal(validStandardUser, "Standard User (No admin privileges)");

console.log("[PASS] evaluateIdentityAccount accurately classifies all operator states and detects conflicts");

console.log("\n================================================================");
console.log("  ALL AUDIT IDENTITIES UNIT TESTS PASSED!");
console.log("================================================================\n");
