import dotenv from "dotenv";
dotenv.config();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "127.0.0.1/32,10.0.0.0/8";

import assert from "node:assert/strict";
import crypto from "node:crypto";

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");

console.log("================================================================");
console.log("  SWYRA AUTH -- PRIVATE APPLICATION OAUTH 2.1 BEHAVIOR SUITE");
console.log("================================================================");

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

// Seed private client
const privateClientId = "private_test_client_" + crypto.randomBytes(4).toString("hex");
const privateSecret = "secret_" + crypto.randomBytes(8).toString("hex");
const privateSecretHash = crypto.createHash("sha256").update(privateSecret).digest("base64url");
const privateRedirectUri = "https://private.example.com/callback";

await db.collection("oauthClient").insertOne({
  clientId: privateClientId,
  clientSecret: privateSecretHash,
  name: "Private Enterprise Application",
  redirectUris: [privateRedirectUri],
  allowedOrigins: ["https://private.example.com"],
  isPublic: false,
  isDev: false,
  disabled: false,
  skipConsent: true,
  createdAt: new Date(),
  updatedAt: new Date(),
});

// Seed users:
// User A: assigned to private application
// User B: unassigned (not registered for private application)
// User C: app administrator scoped to this client
const userA_email = `assigned_${crypto.randomBytes(4).toString("hex")}@example.com`;
const userB_email = `unassigned_${crypto.randomBytes(4).toString("hex")}@example.com`;
const userC_email = `appadmin_${crypto.randomBytes(4).toString("hex")}@example.com`;
const commonPass = "TestPassword@1234!";

const createdA = await authProvider.api.signUpEmail({ body: { email: userA_email, password: commonPass, name: "User Assigned" } });
const createdB = await authProvider.api.signUpEmail({ body: { email: userB_email, password: commonPass, name: "User Unassigned" } });
const createdC = await authProvider.api.signUpEmail({ body: { email: userC_email, password: commonPass, name: "Admin Scoped" } });

const idA = createdA.user.id;
const idB = createdB.user.id;
const idC = createdC.user.id;

// Register User A for the private application
await db.collection("user_app_registrations").insertOne({
  userId: String(idA),
  clientId: privateClientId,
  registeredAt: new Date(),
});

// User C is admin scoped to this client
await db.collection("user").updateOne(
  { email: userC_email },
  { $set: { role: "admin", scopedClientId: privateClientId } }
);

let ipCounter = 700;
function getTestHeaders(extra: Record<string, string> = {}): Headers {
  const h = new Headers();
  const ip = `198.51.100.${++ipCounter % 240 + 1}`;
  h.set("content-type", "application/json");
  h.set("host", "localhost:3000");
  h.set("origin", process.env.FRONTEND_URL || "https://oauth21.vercel.app");
  h.set("referer", (process.env.FRONTEND_URL || "https://oauth21.vercel.app") + "/");
  h.set("x-forwarded-for", `${ip}, 10.0.0.1`);
  h.set("x-gateway-secret", process.env.INTERNAL_GATEWAY_SECRET || "139f62efde9b06735e66e7e9329fdcd51b44108c07717f3307af44c1dcdd3a57");
  h.set("x-csrf-token", "any");
  for (const [k, v] of Object.entries(extra)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

// Sign in users to obtain their session cookies
async function getSessionCookie(email: string): Promise<string> {
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email, password: commonPass }),
  });
  assert.equal(loginRes.status, 200, `Sign-in must succeed for ${email}`);
  const setCookie = loginRes.headers.get("set-cookie") || "";
  return setCookie.split(";")[0];
}

const cookieA = await getSessionCookie(userA_email);
const cookieB = await getSessionCookie(userB_email);
const cookieC = await getSessionCookie(userC_email);

// --------------------------------------------------------------------------
// TEST 1: Unauthenticated request to /oauth2/authorize on private client
// --------------------------------------------------------------------------
await runTest("PRIV-1: Unauthenticated user on private client is redirected to IdP login with is_public=false", async () => {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_unauth_" + crypto.randomBytes(4).toString("hex");

  const res = await app.request(
    `/api/auth/oauth2/authorize?client_id=${privateClientId}&redirect_uri=${encodeURIComponent(privateRedirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders(),
      redirect: "manual",
    }
  );

  assert.equal(res.status, 302, "Must redirect unauthenticated user to IdP login");
  const location = res.headers.get("location") || "";
  assert.ok(location.includes("/auth"), `Location must point to IdP login page: ${location}`);
  assert.ok(location.includes("is_public=false"), `Location must include is_public=false: ${location}`);
  assert.ok(location.includes(`client_id=${privateClientId}`), `Location must include client_id: ${location}`);
});

// --------------------------------------------------------------------------
// TEST 2: Authenticated but Unassigned user is DENIED access
// --------------------------------------------------------------------------
await runTest("PRIV-2: Authenticated user not assigned to private client is denied with access_denied", async () => {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_unassigned_" + crypto.randomBytes(4).toString("hex");

  const res = await app.request(
    `/api/auth/oauth2/authorize?client_id=${privateClientId}&redirect_uri=${encodeURIComponent(privateRedirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: cookieB }),
      redirect: "manual",
    }
  );

  assert.equal(res.status, 302, "Must redirect unassigned user with error");
  const location = res.headers.get("location") || "";
  const parsed = new URL(location);
  assert.equal(parsed.searchParams.get("error"), "access_denied");
  assert.ok(parsed.searchParams.get("error_description")?.includes("Access restricted"));
  assert.equal(parsed.searchParams.get("state"), state);
});

// --------------------------------------------------------------------------
// TEST 3: Authenticated and Assigned user is GRANTED authorization
// --------------------------------------------------------------------------
await runTest("PRIV-3: Authenticated user explicitly assigned to private client receives authorization code", async () => {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_assigned_" + crypto.randomBytes(4).toString("hex");

  const res = await app.request(
    `/api/auth/oauth2/authorize?client_id=${privateClientId}&redirect_uri=${encodeURIComponent(privateRedirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: cookieA }),
      redirect: "manual",
    }
  );

  assert.equal(res.status, 302, "Must redirect assigned user to callback with code");
  const location = res.headers.get("location") || "";
  const parsed = new URL(location);
  assert.equal(parsed.origin, new URL(privateRedirectUri).origin);
  assert.equal(parsed.pathname, new URL(privateRedirectUri).pathname);
  assert.ok(parsed.searchParams.get("code"), "Must contain OAuth authorization code");
  assert.equal(parsed.searchParams.get("state"), state);

  // Exchange code for tokens
  const code = parsed.searchParams.get("code")!;
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${privateClientId}:${privateSecret}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(privateRedirectUri)}&code_verifier=${codeVerifier}`,
  });

  assert.equal(tokenRes.status, 200, "Token exchange must succeed");
  const tokenData = await tokenRes.json();
  assert.ok(tokenData.access_token, "Must receive access_token");

  // Call UserInfo endpoint
  const userinfoRes = await app.request("/api/auth/oauth2/userinfo", {
    headers: getTestHeaders({ Authorization: `Bearer ${tokenData.access_token}` }),
  });
  assert.equal(userinfoRes.status, 200, "UserInfo must return 200");
  const userinfo = await userinfoRes.json();
  console.log("USERINFO RESULT:", JSON.stringify(userinfo));
  assert.equal(userinfo.sub, idA);
  assert.equal(userinfo.role, "user");
  assert.equal(userinfo.scoped_client_id, null);
});

// --------------------------------------------------------------------------
// TEST 4: App Administrator OAuth flow yields admin role + scoped_client_id
// --------------------------------------------------------------------------
await runTest("PRIV-4: Scoped App Admin receives role: admin and scoped_client_id in OAuth userinfo", async () => {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_admin_" + crypto.randomBytes(4).toString("hex");

  const res = await app.request(
    `/api/auth/oauth2/authorize?client_id=${privateClientId}&redirect_uri=${encodeURIComponent(privateRedirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders({ Cookie: cookieC }),
      redirect: "manual",
    }
  );

  assert.equal(res.status, 302, "Must redirect admin user to callback with code");
  const location = res.headers.get("location") || "";
  const parsed = new URL(location);
  const code = parsed.searchParams.get("code")!;
  assert.ok(code, "Must receive authorization code");

  // Exchange code
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${privateClientId}:${privateSecret}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(privateRedirectUri)}&code_verifier=${codeVerifier}`,
  });

  assert.equal(tokenRes.status, 200);
  const tokenData = await tokenRes.json();

  // Call UserInfo endpoint
  const userinfoRes = await app.request("/api/auth/oauth2/userinfo", {
    headers: getTestHeaders({ Authorization: `Bearer ${tokenData.access_token}` }),
  });
  assert.equal(userinfoRes.status, 200);
  const userinfo = await userinfoRes.json();
  assert.equal(userinfo.sub, idC);
  assert.equal(userinfo.role, "admin");
  assert.equal(userinfo.scoped_client_id, privateClientId);
});

// --------------------------------------------------------------------------
// TEST 5: Self-registration on private application is strictly blocked
// --------------------------------------------------------------------------
await runTest("PRIV-5: Direct sign-up on private client is rejected with 403 registration_disabled", async () => {
  const newEmail = `hacker_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const res = await app.request(`/api/auth/sign-up/email?client_id=${privateClientId}`, {
    method: "POST",
    headers: getTestHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ email: newEmail, password: "SecurePassword123!", name: "Attacker" }),
  });

  assert.equal(res.status, 403, "Must reject sign-up for private application");
  const data = await res.json();
  assert.equal(data.error, "registration_disabled");
});

console.log("================================================================");
console.log(`  PRIVATE APP OAUTH SUITE: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
