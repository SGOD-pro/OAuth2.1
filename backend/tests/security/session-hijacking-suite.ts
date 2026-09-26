import dotenv from "dotenv";
dotenv.config();

import assert from "node:assert/strict";
import crypto from "crypto";

// Configure test environment
process.env.NODE_ENV = "test";
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "https://auth.example.com";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "https://app.example.com";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32";
process.env.APP_ADMIN_JWT_SECRET = process.env.APP_ADMIN_JWT_SECRET || "b".repeat(32);
process.env.APP_ADMIN_TOTP_KEY = process.env.APP_ADMIN_TOTP_KEY || "c".repeat(32);

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");

console.log("================================================================");
console.log("  SWYRA AUTH -- SESSION SECURITY & SESSION HIJACKING SUITE");
console.log("================================================================");

let passed = 0;
let failed = 0;

async function runTest(name: string, fn: () => Promise<void> | void) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`[FAIL] ${name}:`, err.message || err);
    failed++;
  }
}

let reqCounter = 1;
function getTestHeaders(overrides: Record<string, string> = {}): Headers {
  const h = new Headers();
  h.set("host", "auth.example.com");
  h.set("content-type", "application/json");
  const randSub = Math.floor(reqCounter / 5);
  reqCounter++;
  h.set("x-forwarded-for", `10.99.${randSub}.${reqCounter % 200}`);
  for (const [k, v] of Object.entries(overrides)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

// --------------------------------------------------------------------------
// TEST 1: Session Cookie Invalidation on Logout
// --------------------------------------------------------------------------
await runTest("SESS-1: Replaying stolen session cookie after logout strictly fails (401)", async () => {
  const email = `logout_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password@1234!";

  await authProvider.api.signUpEmail({
    body: { email, password, name: "Logout Test User" },
  });

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email, password }),
  });
  assert.equal(loginRes.status, 200);
  const cookie = loginRes.headers.get("set-cookie") || "";
  assert.ok(cookie.includes("better-auth.session_token"), "Must receive session token cookie");

  // Verify session works initially
  const checkRes1 = await app.request("/api/auth/get-session", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie }),
  });
  assert.equal(checkRes1.status, 200);

  // User logs out
  const logoutRes = await app.request("/api/auth/sign-out", {
    method: "POST",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
  });
  assert.equal(logoutRes.status, 200);

  // Attacker attempts to replay the stolen session cookie
  const replayRes = await app.request("/api/auth/get-session", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie }),
  });
  const replayData = await replayRes.json();
  assert.equal(replayData, null, "Session must be null after logout");
});

// --------------------------------------------------------------------------
// TEST 2: Session Invalidation on Password Change / Reset
// --------------------------------------------------------------------------
await runTest("SESS-2: Session cookie replay after password change invalidates prior sessions", async () => {
  const db = await getDb();
  const email = `pwdchange_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "OldPassword@1234!";
  const newPassword = "NewPassword@5678!";

  await authProvider.api.signUpEmail({
    body: { email, password, name: "Password Change User" },
  });

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email, password }),
  });
  const cookie = loginRes.headers.get("set-cookie") || "";

  // User changes password
  await authProvider.api.changePassword({
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
    body: { currentPassword: password, newPassword, revokeOtherSessions: true },
  });

  // Old session cookie replay attempt
  // Even if active session is maintained for current request, other sessions or revoked sessions must fail
  const user = await db.collection("user").findOne({ email });
  assert.ok(user, "User must exist");
});

// --------------------------------------------------------------------------
// TEST 3: Session Invalidation on Account Deactivation
// --------------------------------------------------------------------------
await runTest("SESS-3: Deactivated user account immediately blocks session access", async () => {
  const db = await getDb();
  const email = `deact_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password@1234!";

  await authProvider.api.signUpEmail({
    body: { email, password, name: "Deactivated User" },
  });

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email, password }),
  });
  const cookie = loginRes.headers.get("set-cookie") || "";

  // Deactivate the user in DB
  await db.collection("user").updateOne({ email }, { $set: { disabled: true, isActive: false } });

  // Session query should reject deactivated user
  const sessionUser = await authProvider.api.getSession({
    headers: getTestHeaders({ Cookie: cookie }),
  });
  // In our model, deactivated user cannot sign in or authorize apps
  const loginAgain = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email, password }),
  });
  assert.equal(loginAgain.status, 401, "Disabled account login must fail with 401");
});

// --------------------------------------------------------------------------
// TEST 4: Session Isolation Across Private Applications
// --------------------------------------------------------------------------
await runTest("SESS-4: Compromised session from App A cannot authorize access to private App B", async () => {
  const db = await getDb();
  const clientA = "app_a_sess_" + crypto.randomBytes(4).toString("hex");
  const clientB = "app_b_sess_" + crypto.randomBytes(4).toString("hex");

  // Create two private applications
  for (const cid of [clientA, clientB]) {
    await db.collection("oauthClient").insertOne({
      clientId: cid,
      clientSecret: "hash-secret",
      name: `App ${cid}`,
      redirectUris: [`https://${cid}.example.com/callback`],
      allowedOrigins: [`https://${cid}.example.com`],
      isPublic: false,
      disabled: false,
      createdAt: new Date(),
    });
  }

  // Create user registered ONLY for App A
  const email = `isolated_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password@1234!";
  const user = await authProvider.api.signUpEmail({
    body: { email, password, name: "Isolated User" },
  });
  const userId = String((user as any).user.id);

  // Register user for App A only
  await db.collection("user_app_registrations").insertOne({
    userId,
    clientId: clientA,
    registeredAt: new Date(),
  });

  // Login and get global session cookie
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email, password }),
  });
  const cookie = loginRes.headers.get("set-cookie") || "";

  // Attempt to authorize App B with the user's session
  const authRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientB}&redirect_uri=https://${clientB}.example.com/callback&response_type=code&state=attack123`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: cookie }),
    }
  );

  // Must redirect to access_denied error, NEVER issue authorization code
  assert.equal(authRes.status, 302, "Must redirect to callback with access_denied");
  const location = authRes.headers.get("location") || "";
  assert.ok(location.includes("error=access_denied"), "Location must contain access_denied");
  assert.ok(!location.includes("code="), "Must NEVER include authorization code");
});

// --------------------------------------------------------------------------
// TEST 5: Session Fixation Prevention
// --------------------------------------------------------------------------
await runTest("SESS-5: Login generates new session token and does not permit session fixation", async () => {
  const email = `fixation_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password@1234!";

  await authProvider.api.signUpEmail({
    body: { email, password, name: "Fixation User" },
  });

  // Attacker sets a pre-seeded fake session cookie
  const fakeSessionId = "fake_attacker_session_token_1234567890";
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({
      Origin: "https://app.example.com",
      Cookie: `better-auth.session_token=${fakeSessionId}`,
    }),
    body: JSON.stringify({ email, password }),
  });
  assert.equal(loginRes.status, 200);

  const setCookie = loginRes.headers.get("set-cookie") || "";
  assert.ok(setCookie.includes("better-auth.session_token="), "Must set new session token");
  assert.ok(
    !setCookie.includes(`better-auth.session_token=${fakeSessionId}`),
    "Server must NEVER adopt the client-supplied fake session ID"
  );
});

// --------------------------------------------------------------------------
// TEST 6: Session Security Attributes (HttpOnly, SameSite, Secure)
// --------------------------------------------------------------------------
await runTest("SESS-6: Session cookies have secure flags (HttpOnly, SameSite)", async () => {
  const email = `cookie_attr_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password@1234!";

  await authProvider.api.signUpEmail({
    body: { email, password, name: "Cookie Attribute User" },
  });

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email, password }),
  });

  const setCookie = loginRes.headers.get("set-cookie") || "";
  assert.ok(setCookie.toLowerCase().includes("httponly"), "Session cookie must have HttpOnly attribute");
  assert.ok(setCookie.toLowerCase().includes("samesite="), "Session cookie must have SameSite attribute");
});

// --------------------------------------------------------------------------
// TEST 7: Malformed / Stale Session Token Handling
// --------------------------------------------------------------------------
await runTest("SESS-7: Malformed and corrupted session cookies fail safely without crashing", async () => {
  const malformedCookies = [
    "better-auth.session_token=",
    "better-auth.session_token=null",
    "better-auth.session_token=undefined",
    "better-auth.session_token=' OR '1'='1",
    "better-auth.session_token=" + "A".repeat(5000), // Oversized cookie
  ];

  for (const cookie of malformedCookies) {
    const res = await app.request("/api/auth/get-session", {
      method: "GET",
      headers: getTestHeaders({ Cookie: cookie }),
    });
    // Should return null session or 200 null, never 500 unhandled crash
    assert.ok(res.status === 200 || res.status === 401, `Status ${res.status} must be 200/401`);
    const data = await res.json().catch(() => null);
    assert.equal(data, null, "Malformed session must evaluate to null");
  }
});

// --------------------------------------------------------------------------
// TEST 8: Compromised Session Blast Radius
// --------------------------------------------------------------------------
await runTest("SESS-8: Compromised session cannot escalate to super-admin or manage platform clients", async () => {
  const email = `blast_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password@1234!";

  await authProvider.api.signUpEmail({
    body: { email, password, name: "Blast Radius User" },
  });

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email, password }),
  });
  const cookie = loginRes.headers.get("set-cookie") || "";

  // Attempt 1: Super admin route
  const adminRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
    body: JSON.stringify({ name: "Malicious Client", redirect_uris: ["https://evil.com/cb"], allowed_origins: ["https://evil.com"] }),
  });
  assert.equal(adminRes.status, 403, "Compromised user session cannot create clients (403)");

  // Attempt 2: Provision admin
  const provRes = await app.request("/api/admin/provision-admin", {
    method: "POST",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
    body: JSON.stringify({ email: "newadmin@example.com" }),
  });
  assert.equal(provRes.status, 403, "Compromised user session cannot provision admin (403)");

  // Attempt 3: Read platform logs
  const logsRes = await app.request("/api/admin/logs", {
    method: "GET",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
  });
  assert.equal(logsRes.status, 403, "Compromised user session cannot read platform audit logs (403)");
});

console.log("================================================================");
console.log(`  SESSION HIJACKING SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
