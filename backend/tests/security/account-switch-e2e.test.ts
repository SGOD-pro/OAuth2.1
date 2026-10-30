import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId } from "mongodb";

console.log("================================================================");
console.log("  SWYRA AUTH -- ACCOUNT SWITCH & SESSION ISOLATION E2E SUITE");
console.log("================================================================\n");

// 1. Start disposable in-memory MongoDB
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;
process.env.BETTER_AUTH_SECRET = "b".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
const GATEWAY_SECRET = "g".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = GATEWAY_SECRET;
process.env.TRUSTED_PROXY_CIDRS = "127.0.0.1/32,10.0.0.0/8";

const { getDb, closeDb } = await import("../../src/db/mongo");
const { default: app } = await import("../../src/app");
const { authProvider } = await import("../../src/utils/auth");

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

let ipCounter = 900;
function getTestHeaders(extra: Record<string, string> = {}): Headers {
  const h = new Headers();
  const ip = `198.51.100.${++ipCounter % 240 + 1}`;
  h.set("content-type", "application/json");
  h.set("host", "localhost:3000");
  h.set("origin", "http://localhost:5174");
  h.set("x-forwarded-for", `${ip}, 10.0.0.1`);
  h.set("x-gateway-secret", GATEWAY_SECRET);
  for (const [k, v] of Object.entries(extra)) {
    h.set(k, v);
  }
  return h;
}

const db = await getDb();

// Seed App Admin
const appAdminEmail = "appadmin_switch@example.com";
const appAdminPass = "AppAdminPass123!Aa";
await authProvider.api.signUpEmail({
  body: { email: appAdminEmail, password: appAdminPass, name: "App Admin Switch" },
});
await db.collection("user").updateOne(
  { email: appAdminEmail },
  { $set: { role: "app-admin", scopedClientId: "client-corp-alpha", emailVerified: true } }
);

// Seed Super Admin
const superAdminEmail = "superadmin_switch@example.com";
const superAdminPass = "SuperAdminPass123!Aa";
await authProvider.api.signUpEmail({
  body: { email: superAdminEmail, password: superAdminPass, name: "Super Admin Switch" },
});
await db.collection("user").updateOne(
  { email: superAdminEmail },
  { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
);

// ==============================================================================
// 1. Active App Admin Session Denial & Account Switch
// ==============================================================================

await runTest("SWITCH-1: App Admin session is denied access to MAuth platform APIs (403)", async () => {
  // Sign in as App Admin
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPass }),
  });
  assert.equal(loginRes.status, 200, "App Admin login must succeed");
  const cookie = (loginRes.headers.get("set-cookie") || "").split(";")[0];
  assert.ok(cookie, "Cookie must be returned");

  // Attempt to call MAuth Super-Admin endpoint
  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie }),
  });

  assert.equal(res.status, 403, "App Admin session must be strictly denied MAuth APIs (403)");
  const data = await res.json();
  assert.equal(data.code, "ERR_SUPER_ADMIN_REQUIRED");
});

await runTest("SWITCH-2: Explicit sign-out clears session on server and prevents restoration", async () => {
  // Sign in as App Admin
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPass }),
  });
  assert.equal(loginRes.status, 200);
  const cookie = (loginRes.headers.get("set-cookie") || "").split(";")[0];

  // Perform deliberate sign-out (as done when clicking "Sign in with a different account")
  const signOutRes = await app.request("/api/auth/sign-out", {
    method: "POST",
    headers: getTestHeaders({ Cookie: cookie }),
    body: JSON.stringify({}),
  });
  assert.equal(signOutRes.status, 200, "Sign out must succeed (200)");

  // Attempting to use old cookie after sign-out must fail closed
  const checkRes = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie }),
  });
  assert.equal(checkRes.status, 401, "Old session cookie must return 401 unauthenticated after sign-out");
});

await runTest("SWITCH-3: Account switch to Super-Admin grants MAuth console access", async () => {
  // Sign in as Super Admin
  const superLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: superAdminEmail, password: superAdminPass }),
  });
  assert.equal(superLoginRes.status, 200, "Super Admin login must succeed");
  const superCookie = (superLoginRes.headers.get("set-cookie") || "").split(";")[0];

  // Verify access to platform console API
  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: superCookie }),
  });
  assert.equal(res.status, 200, "Super Admin must receive 200 on MAuth platform API");
});

// ==============================================================================
// 2. Client Side Tampering Defense
// ==============================================================================

await runTest("TAMPER-1: Client-supplied JSON role in headers/body grants zero backend access", async () => {
  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({
      "x-user-role": "super-admin",
      "x-scoped-client-id": "null",
      "x-user-email": "superadmin_switch@example.com",
    }),
  });

  assert.equal(res.status, 401, "Unsigned request claiming role in headers must return 401");
});

console.log("\n================================================================");
console.log(`  ACCOUNT SWITCH RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================\n");

await closeDb();
await mongod.stop();

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}

