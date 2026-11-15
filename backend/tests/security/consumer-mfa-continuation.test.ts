import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";

console.log("================================================================");
console.log("  SWYRA AUTH -- CONSUMER OAUTH MFA CONTINUATION SECURITY SUITE");
console.log("================================================================\n");

const mongod = await MongoMemoryServer.create();
process.env.MONGO_URI = mongod.getUri();
process.env.NODE_ENV = "test";
process.env.BETTER_AUTH_SECRET = "m".repeat(32);
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
const { createOTP } = await import("@better-auth/utils/otp");
const { base32 } = await import("@better-auth/utils/base32");

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

let ipCounter = 200;
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

function extractMfaCookie(res: Response): string {
  const setCookie = res.headers.get("set-cookie") || "";
  const parts = setCookie.split(",").map((s) => s.trim().split(";")[0]);
  return parts.filter((c) => c.includes("better-auth.two_factor")).join("; ");
}

function extractSessionCookie(res: Response): string {
  const setCookie = res.headers.get("set-cookie") || "";
  const match = setCookie.match(/better-auth\.session_token=[^;]+/);
  return match ? match[0] : "";
}

function makePKCE() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function makeAuthorizeUrl(clientId: string, redirectUri: string, state: string, codeChallenge: string): string {
  return `/api/auth/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;
}

const db = await getDb();

// -----------------------------------------------------------------------------
// Seed Test Clients
// -----------------------------------------------------------------------------
const clientA = "client-private-app-a";
const clientASecret = "secret-app-a-1234567890";
const clientAHash = crypto.createHash("sha256").update(clientASecret).digest("base64url");
const clientACallback = "https://app-a.example.com/oauth/callback";

const clientB = "client-private-app-b";
const clientBSecret = "secret-app-b-1234567890";
const clientBHash = crypto.createHash("sha256").update(clientBSecret).digest("base64url");
const clientBCallback = "https://app-b.example.com/oauth/callback";

const clientPublic = "client-public-app-mfa";
const clientPublicCallback = "https://public-app.example.com/oauth/callback";

await db.collection("oauthClient").insertMany([
  {
    id: clientA,
    clientId: clientA,
    clientSecret: clientAHash,
    name: "Private App A",
    redirectUris: [clientACallback],
    allowedOrigins: ["https://app-a.example.com"],
    isPublic: false,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  },
  {
    id: clientB,
    clientId: clientB,
    clientSecret: clientBHash,
    name: "Private App B",
    redirectUris: [clientBCallback],
    allowedOrigins: ["https://app-b.example.com"],
    isPublic: false,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  },
  {
    id: clientPublic,
    clientId: clientPublic,
    name: "Public App MFA",
    redirectUris: [clientPublicCallback],
    allowedOrigins: ["https://public-app.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  },
]);

// -----------------------------------------------------------------------------
// Seed App Admin with MFA for Client A
// -----------------------------------------------------------------------------
const appAdminEmail = "admin_mfa_a@example.com";
const appAdminPass = "AppAdminPass123!Aa";
const appAdminSignUp = await authProvider.api.signUpEmail({
  body: { email: appAdminEmail, password: appAdminPass, name: "App Admin A MFA" },
});
const appAdminId = String(appAdminSignUp.user.id);

// Bind as App Admin for Client A
await db.collection("user").updateOne(
  { email: appAdminEmail },
  { $set: { role: "app-admin", scopedClientId: clientA, emailVerified: true } }
);
await db.collection("user_app_registrations").insertOne({
  userId: appAdminId,
  clientId: clientA,
  appRole: "admin",
  status: "active",
  registeredAt: new Date(),
});

// Enable 2FA on App Admin A
const adminPreSignIn = await authProvider.api.signInEmail({
  body: { email: appAdminEmail, password: appAdminPass },
  asResponse: true,
});
const adminPreCookie = (adminPreSignIn.headers.get("set-cookie") || "").split(";")[0];

const admin2faSetup = await authProvider.api.enableTwoFactor({
  body: { password: appAdminPass, method: "totp" },
  headers: new Headers({ cookie: adminPreCookie }),
});
const adminB32Secret = new URL(admin2faSetup.totpURI).searchParams.get("secret")!;
const adminRawSecret = new TextDecoder().decode(base32.decode(adminB32Secret));
const adminBackupCodes = admin2faSetup.backupCodes;

// Complete enablement
const initCode = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
await authProvider.api.verifyTOTP({
  body: { code: initCode },
  headers: new Headers({ cookie: adminPreCookie }),
  asResponse: true,
});

// -----------------------------------------------------------------------------
// Seed Super Admin with MFA for MAuth Platform
// -----------------------------------------------------------------------------
const superAdminEmail = "super_mfa@swyra.com";
const superAdminPass = "SuperAdminPass123!Aa";
const superAdminSignUp = await authProvider.api.signUpEmail({
  body: { email: superAdminEmail, password: superAdminPass, name: "Super Admin MFA" },
});
const superAdminId = String(superAdminSignUp.user.id);

await db.collection("user").updateOne(
  { email: superAdminEmail },
  { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
);

const superPreSignIn = await authProvider.api.signInEmail({
  body: { email: superAdminEmail, password: superAdminPass },
  asResponse: true,
});
const superPreCookie = (superPreSignIn.headers.get("set-cookie") || "").split(";")[0];

const super2faSetup = await authProvider.api.enableTwoFactor({
  body: { password: superAdminPass, method: "totp" },
  headers: new Headers({ cookie: superPreCookie }),
});
const superB32Secret = new URL(super2faSetup.totpURI).searchParams.get("secret")!;
const superRawSecret = new TextDecoder().decode(base32.decode(superB32Secret));

const superInitCode = await createOTP(superRawSecret, { digits: 6, period: 30 }).totp();
await authProvider.api.verifyTOTP({
  body: { code: superInitCode },
  headers: new Headers({ cookie: superPreCookie }),
  asResponse: true,
});

// -----------------------------------------------------------------------------
// Seed Non-MFA App Admin for Client B
// -----------------------------------------------------------------------------
const nonMfaEmail = "admin_nonmfa_b@example.com";
const nonMfaPass = "NonMfaPass123!Aa";
const nonMfaSignUp = await authProvider.api.signUpEmail({
  body: { email: nonMfaEmail, password: nonMfaPass, name: "Non MFA Admin B" },
});
const nonMfaId = String(nonMfaSignUp.user.id);
await db.collection("user").updateOne(
  { email: nonMfaEmail },
  { $set: { role: "app-admin", scopedClientId: clientB, emailVerified: true } }
);
await db.collection("user_app_registrations").insertOne({
  userId: nonMfaId,
  clientId: clientB,
  appRole: "admin",
  status: "active",
  registeredAt: new Date(),
});

// -----------------------------------------------------------------------------
// Seed User with MFA for Public App
// -----------------------------------------------------------------------------
const publicMfaUserEmail = "public_mfa_user@example.com";
const publicMfaUserPass = "PublicMfaPass123!Aa";
const publicMfaSignUp = await authProvider.api.signUpEmail({
  body: { email: publicMfaUserEmail, password: publicMfaUserPass, name: "Public MFA User" },
});
const publicMfaUserId = String(publicMfaSignUp.user.id);

const publicPreSignIn = await authProvider.api.signInEmail({
  body: { email: publicMfaUserEmail, password: publicMfaUserPass },
  asResponse: true,
});
const publicPreCookie = (publicPreSignIn.headers.get("set-cookie") || "").split(";")[0];

const public2faSetup = await authProvider.api.enableTwoFactor({
  body: { password: publicMfaUserPass, method: "totp" },
  headers: new Headers({ cookie: publicPreCookie }),
});
const publicB32Secret = new URL(public2faSetup.totpURI).searchParams.get("secret")!;
const publicRawSecret = new TextDecoder().decode(base32.decode(publicB32Secret));
const publicBackupCodes = public2faSetup.backupCodes;

const publicInitCode = await createOTP(publicRawSecret, { digits: 6, period: 30 }).totp();
await authProvider.api.verifyTOTP({
  body: { code: publicInitCode },
  headers: new Headers({ cookie: publicPreCookie }),
  asResponse: true,
});

// =============================================================================
// TEST 1: Private App A admin with TOTP completes MFA and returns to App A
// =============================================================================
await runTest("MFA-1: Private App A admin with TOTP returns to App A callback with code", async () => {
  const state = "state_totp_test_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientA, clientACallback, state, pkce.challenge);

  // 1. Initiate OAuth authorization
  const authRes = await app.request(authUrl, { method: "GET", headers: getTestHeaders() });
  assert.equal(authRes.status, 302, "Initial authorization must redirect unauthenticated caller to login");

  // 2. Submit credentials on sign-in
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: appAdminEmail,
      password: appAdminPass,
      callbackURL: authUrl,
    }),
  });
  assert.equal(loginRes.status, 200, "Sign-in must return 200 with 2FA redirect requirement");
  const loginData = await loginRes.json();
  assert.equal(loginData.twoFactorRedirect, true, "Response must indicate twoFactorRedirect: true");

  const mfaCookie = extractMfaCookie(loginRes);
  assert.ok(mfaCookie, "Two factor pending cookie must be returned");

  // 3. Generate valid TOTP code and verify
  const totpCode = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
  const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookie }),
    body: JSON.stringify({ code: totpCode }),
  });
  assert.equal(verifyRes.status, 200, "TOTP verification must succeed");
  const sessionCookie = extractSessionCookie(verifyRes);
  assert.ok(sessionCookie, "Session cookie must be issued on successful TOTP verification");

  // 4. Resume OAuth authorization with session cookie
  const resumeRes = await app.request(authUrl, { method: "GET", headers: getTestHeaders({ Cookie: sessionCookie }) });
  assert.equal(resumeRes.status, 302, "Resumed OAuth must redirect to consumer callback");
  const location = resumeRes.headers.get("location");
  assert.ok(location, "Redirect location header must exist");
  assert.ok(location.startsWith(clientACallback), "Must redirect to registered Client A callback URL");
  const callbackUrl = new URL(location);
  assert.ok(callbackUrl.searchParams.get("code"), "Must contain authorization code");
  assert.equal(callbackUrl.searchParams.get("state"), state, "Must preserve exact state parameter");
});

// =============================================================================
// TEST 2: Backup recovery code flow returns to the same validated app
// =============================================================================
await runTest("MFA-2: Backup recovery code flow returns to the same validated application", async () => {
  const state = "state_backup_test_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientA, clientACallback, state, pkce.challenge);

  // Sign in to receive 2FA prompt
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: appAdminEmail,
      password: appAdminPass,
      callbackURL: authUrl,
    }),
  });
  assert.equal(loginRes.status, 200);
  const mfaCookie = extractMfaCookie(loginRes);
  assert.ok(mfaCookie);

  // Verify using first backup recovery code
  const recoveryCode = adminBackupCodes[0];
  const verifyRes = await app.request("/api/auth/two-factor/verify-backup-code", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookie }),
    body: JSON.stringify({ code: recoveryCode }),
  });
  assert.equal(verifyRes.status, 200, "Backup code verification must succeed");
  const sessionCookie = extractSessionCookie(verifyRes);
  assert.ok(sessionCookie);

  // Resume OAuth continuation
  const resumeRes = await app.request(authUrl, { method: "GET", headers: getTestHeaders({ Cookie: sessionCookie }) });
  assert.equal(resumeRes.status, 302);
  const location = resumeRes.headers.get("location")!;
  assert.ok(location.startsWith(clientACallback));
  const callbackUrl = new URL(location);
  assert.ok(callbackUrl.searchParams.get("code"));
  assert.equal(callbackUrl.searchParams.get("state"), state);
});

// =============================================================================
// TEST 3: Super-admin MFA verifies and returns to MAuth platform
// =============================================================================
await runTest("MFA-3: Super admin MFA authorizes MAuth platform administration", async () => {
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: superAdminEmail,
      password: superAdminPass,
      callbackURL: "/admin",
    }),
  });
  assert.equal(loginRes.status, 200);
  const mfaCookie = extractMfaCookie(loginRes);

  const superCode = await createOTP(superRawSecret, { digits: 6, period: 30 }).totp();
  const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookie }),
    body: JSON.stringify({ code: superCode }),
  });
  assert.equal(verifyRes.status, 200);
  const sessionCookie = extractSessionCookie(verifyRes);
  assert.ok(sessionCookie);

  // Invoke MAuth platform API
  const adminRes = await app.request("/api/admin/clients", {
    method: "GET",
    headers: getTestHeaders({ Cookie: sessionCookie }),
  });
  assert.equal(adminRes.status, 200, "Super admin with MFA must have full MAuth platform access");
});

// =============================================================================
// TEST 4: App-admin direct MAuth access remains strictly denied
// =============================================================================
await runTest("MFA-4: App admin session from consumer MFA is denied access to MAuth platform APIs", async () => {
  // Sign in App Admin and verify TOTP
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPass }),
  });
  const mfaCookie = extractMfaCookie(loginRes);
  const totpCode = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
  const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookie }),
    body: JSON.stringify({ code: totpCode }),
  });
  const sessionCookie = extractSessionCookie(verifyRes);
  assert.ok(sessionCookie);

  // Attempt to access MAuth platform endpoints
  const platformEndpoints = [
    { method: "GET", path: "/api/admin/clients" },
    { method: "GET", path: "/api/admin/users" },
    { method: "GET", path: "/api/admin/stats" },
    { method: "POST", path: "/api/admin/clients" },
  ];

  for (const ep of platformEndpoints) {
    const res = await app.request(ep.path, {
      method: ep.method,
      headers: getTestHeaders({ Cookie: sessionCookie }),
    });
    assert.equal(res.status, 403, `App Admin must receive 403 on platform endpoint ${ep.path}`);
    const data = await res.json();
    assert.equal(data.code, "ERR_SUPER_ADMIN_REQUIRED", "Must return ERR_SUPER_ADMIN_REQUIRED");
  }
});

// =============================================================================
// TEST 5: Non-MFA consumer login returns correctly to validated application
// =============================================================================
await runTest("MFA-5: Non-MFA consumer login issues immediate session and returns to app", async () => {
  const state = "state_nonmfa_test_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientB, clientBCallback, state, pkce.challenge);

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: nonMfaEmail,
      password: nonMfaPass,
      callbackURL: authUrl,
    }),
  });
  assert.equal(loginRes.status, 200);
  const sessionCookie = extractSessionCookie(loginRes);
  assert.ok(sessionCookie, "Non-MFA user must receive session cookie immediately");

  const resumeRes = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders({ Cookie: sessionCookie }),
  });
  assert.equal(resumeRes.status, 302);
  const location = resumeRes.headers.get("location")!;
  assert.ok(location.startsWith(clientBCallback));
  const callbackUrl = new URL(location);
  assert.ok(callbackUrl.searchParams.get("code"));
  assert.equal(callbackUrl.searchParams.get("state"), state);
});

// =============================================================================
// TEST 6: Two tabs for different clients cannot exchange continuations
// =============================================================================
await runTest("MFA-6: Two tabs for different clients maintain isolated state-bound continuations", async () => {
  const stateA = "state_tab_a_" + crypto.randomBytes(6).toString("hex");
  const stateB = "state_tab_b_" + crypto.randomBytes(6).toString("hex");
  const pkceA = makePKCE();
  const pkceB = makePKCE();
  const authUrlA = makeAuthorizeUrl(clientA, clientACallback, stateA, pkceA.challenge);
  const authUrlB = makeAuthorizeUrl(clientB, clientBCallback, stateB, pkceB.challenge);

  // Tab A initiates OAuth for Client A
  const tabARes = await app.request(authUrlA, { method: "GET", headers: getTestHeaders() });
  assert.equal(tabARes.status, 302);

  // Tab B initiates OAuth for Client B (overwriting current_client_id cookie in shared browser jar)
  const tabBRes = await app.request(authUrlB, { method: "GET", headers: getTestHeaders() });
  assert.equal(tabBRes.status, 302);

  // Tab A authenticates with MFA and resumes using stateA
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPass }),
  });
  const mfaCookie = extractMfaCookie(loginRes);
  const totpCode = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
  const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookie }),
    body: JSON.stringify({ code: totpCode }),
  });
  const sessionCookie = extractSessionCookie(verifyRes);

  // Tab A resumes with its own query parameters
  const resumeTabA = await app.request(authUrlA, {
    method: "GET",
    headers: getTestHeaders({ Cookie: sessionCookie }),
  });
  assert.equal(resumeTabA.status, 302);
  const locationA = resumeTabA.headers.get("location")!;
  assert.ok(locationA.startsWith(clientACallback), "Tab A must redirect strictly to Client A callback");
  const urlA = new URL(locationA);
  assert.equal(urlA.searchParams.get("state"), stateA, "Tab A must match stateA");

  // Tab B resuming with Tab A session must evaluate private authorization for Client B
  // App Admin A is NOT authorized for Client B: must fail closed with access_denied
  const resumeTabB = await app.request(authUrlB, {
    method: "GET",
    headers: getTestHeaders({ Cookie: sessionCookie }),
  });
  assert.equal(resumeTabB.status, 302);
  const locationB = resumeTabB.headers.get("location")!;
  assert.ok(locationB.startsWith(clientBCallback));
  const urlB = new URL(locationB);
  assert.equal(urlB.searchParams.get("error"), "access_denied", "Tab B must fail with access_denied for unauthorized client");
  assert.equal(urlB.searchParams.get("state"), stateB, "Tab B must preserve stateB in error redirect");
});

// =============================================================================
// TEST 7: Forged callback/context, expired challenge and replay fail safely
// =============================================================================
await runTest("MFA-7: Forged callbacks, replayed codes and expired challenges fail safely", async () => {
  // A. Forged redirect_uri not registered for Client A
  const forgedUriRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientA}&redirect_uri=https://evil.com/callback&response_type=code&state=s123`,
    { method: "GET", headers: getTestHeaders() }
  );
  assert.equal(forgedUriRes.status, 400, "Unregistered redirect URI must be rejected with 400");

  // B. Missing state parameter
  const missingStateRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientA}&redirect_uri=${encodeURIComponent(clientACallback)}&response_type=code`,
    { method: "GET", headers: getTestHeaders() }
  );
  assert.equal(missingStateRes.status, 302, "Missing state must redirect to auth with error");
  const loc = missingStateRes.headers.get("location")!;
  assert.ok(loc.includes("error=state_required"), "Must return state_required error");

  // C. Replayed backup code
  // The first backup code was consumed in TEST 2
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPass }),
  });
  const mfaCookie = extractMfaCookie(loginRes);
  const alreadyUsedCode = adminBackupCodes[0];
  const replayRes = await app.request("/api/auth/two-factor/verify-backup-code", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookie }),
    body: JSON.stringify({ code: alreadyUsedCode }),
  });
  assert.equal(replayRes.status, 401, "Replayed backup code must be rejected with 401");

  // D. Invalid TOTP code
  const invalidTotpRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookie }),
    body: JSON.stringify({ code: "000000" }),
  });
  assert.equal(invalidTotpRes.status, 401, "Invalid TOTP code must be rejected with 401");
});

// =============================================================================
// TEST 8: Account switching does not lose or mix OAuth transaction state
// =============================================================================
await runTest("MFA-8: Account switching does not lose or mix OAuth transaction state", async () => {
  const state = "state_switch_test_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientA, clientACallback, state, pkce.challenge);

  // 1. Initial OAuth flow initiated for Client A
  await app.request(authUrl, { method: "GET", headers: getTestHeaders() });

  // 2. Sign in as App Admin A (authorized)
  const loginA = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPass }),
  });
  const mfaCookieA = extractMfaCookie(loginA);
  const totpCodeA = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
  const verifyA = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookieA }),
    body: JSON.stringify({ code: totpCodeA }),
  });
  const sessionCookieA = extractSessionCookie(verifyA);

  // Verify Admin A completes authorization for Client A
  const authA = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders({ Cookie: sessionCookieA }),
  });
  assert.equal(authA.status, 302);
  const locA = authA.headers.get("location")!;
  assert.ok(locA.startsWith(clientACallback));
  assert.ok(locA.includes("code="));

  // 3. User logs out (account switch)
  await app.request("/api/auth/sign-out", {
    method: "POST",
    headers: getTestHeaders({ Cookie: sessionCookieA }),
  });

  // 4. User logs in as Admin B (unauthorized for Client A)
  const loginB = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: nonMfaEmail, password: nonMfaPass }),
  });
  const sessionCookieB = extractSessionCookie(loginB);

  // Continuing with state for Client A must fail with access_denied
  const authB = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders({ Cookie: sessionCookieB }),
  });
  assert.equal(authB.status, 302);
  const locB = authB.headers.get("location")!;
  assert.ok(locB.startsWith(clientACallback));
  assert.ok(locB.includes("error=access_denied"), "Switched unauthorized account must be denied for Client A");
  assert.ok(locB.includes(`state=${state}`), "State must be preserved in access_denied redirect");
});

// =============================================================================
// TEST 9: MFA retry resilience and error code discrimination
// =============================================================================
await runTest("MFA-9: MFA retry resilience allows retry on incorrect code and rejects invalid cookie", async () => {
  // 1. Initial sign in to acquire MFA challenge cookie
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPass }),
  });
  assert.equal(loginRes.status, 200);
  const mfaCookie = extractMfaCookie(loginRes);

  // 2. Attempt 1 with invalid TOTP code returns 401 with INVALID_CODE
  const attempt1 = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookie }),
    body: JSON.stringify({ code: "111111" }),
  });
  assert.equal(attempt1.status, 401, "First invalid TOTP attempt must return 401");
  const err1 = await attempt1.json();
  assert.ok(
    err1.code === "INVALID_CODE" || (err1.message && err1.message.toLowerCase().includes("invalid")),
    "Error code or message must indicate invalid code, not expired session"
  );

  // 3. Attempt 2 with correct TOTP code succeeds on the same challenge (not expired)
  const freshTotp = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
  const attempt2 = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookie }),
    body: JSON.stringify({ code: freshTotp }),
  });
  assert.equal(attempt2.status, 200, "Second valid TOTP attempt must succeed after retry");
  const data2 = await attempt2.json();
  assert.ok(data2.token, "Successful retry must return session token");

  // 4. Verification with a missing/tampered cookie returns INVALID_TWO_FACTOR_COOKIE
  const invalidCookieRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: "better-auth.two_factor=invalid_token_xyz" }),
    body: JSON.stringify({ code: freshTotp }),
  });
  assert.equal(invalidCookieRes.status, 401, "Tampered cookie must return 401");
  const errCookie = await invalidCookieRes.json();
  assert.ok(
    errCookie.code === "INVALID_TWO_FACTOR_COOKIE" || (errCookie.message && errCookie.message.toLowerCase().includes("cookie")),
    "Missing/tampered challenge cookie must return INVALID_TWO_FACTOR_COOKIE"
  );
});

// =============================================================================
// TEST 10: Public application registration upon successful two-factor verification
// =============================================================================
await runTest("MFA-10: Public application registration is recorded upon successful 2FA verification", async () => {
  // 1. Confirm user is NOT registered for clientPublic initially
  const initialReg = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: clientPublic,
  });
  assert.equal(initialReg, null, "User must not have a registration record for public client initially");

  // 2. Initiate authorization flow for clientPublic
  const state = "state_public_mfa_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientPublic, clientPublicCallback, state, pkce.challenge);

  const authRes = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(authRes.status, 302);

  // Extract transaction cookie from authorize response
  const setCookie = authRes.headers.get("set-cookie") || "";
  const txMatch = setCookie.match(/oauth_transaction_id=[^;]+/);
  const clientMatch = setCookie.match(/current_client_id=[^;]+/);
  const authCookies = [txMatch?.[0], clientMatch?.[0]].filter(Boolean).join("; ");

  // 3. User submits password; 2FA is required
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookies }),
    body: JSON.stringify({
      email: publicMfaUserEmail,
      password: publicMfaUserPass,
      callbackURL: authUrl,
    }),
  });
  assert.equal(loginRes.status, 200);
  const loginData = await loginRes.json();
  assert.equal(loginData.twoFactorRedirect, true);

  // Still not registered because second factor has not succeeded yet
  const midReg = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: clientPublic,
  });
  assert.equal(midReg, null, "User must not be registered before 2FA verification");

  const mfaCookie = extractMfaCookie(loginRes);
  assert.ok(mfaCookie);

  // 4. Complete second factor verification with TOTP code
  const combinedCookies = [mfaCookie, authCookies].filter(Boolean).join("; ");
  const totpCode = await createOTP(publicRawSecret, { digits: 6, period: 30 }).totp();

  const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: combinedCookies }),
    body: JSON.stringify({ code: totpCode }),
  });
  assert.equal(verifyRes.status, 200, "TOTP verification must succeed");
  const sessionCookie = extractSessionCookie(verifyRes);
  assert.ok(sessionCookie);

  // 5. Assert user_app_registrations record was created upon 2FA success
  const postReg = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: clientPublic,
  });
  assert.ok(postReg, "user_app_registrations record must be created upon successful 2FA verification for public client");
  assert.equal(postReg.clientId, clientPublic);
  assert.equal(postReg.userId, publicMfaUserId);

  // 6. Complete OAuth authorization with session cookie
  const resumeRes = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders({ Cookie: sessionCookie }),
  });
  assert.equal(resumeRes.status, 302);
  const loc = resumeRes.headers.get("location")!;
  assert.ok(loc.startsWith(clientPublicCallback));
  assert.ok(loc.includes("code="));
});

// =============================================================================
// TEST 11: CORS exposed headers include pagination and rate-limit metadata
// =============================================================================
await runTest("MFA-11: CORS exposed headers include pagination and rate limit metadata", async () => {
  const optionsRes = await app.request("/api/admin/logs", {
    method: "OPTIONS",
    headers: getTestHeaders({ origin: "http://localhost:5174" }),
  });
  assert.equal(optionsRes.status, 204);
  const exposed = optionsRes.headers.get("access-control-expose-headers") || "";
  assert.ok(exposed.includes("X-Total-Count"), "Exposed headers must include X-Total-Count");
  assert.ok(exposed.includes("X-Page"), "Exposed headers must include X-Page");
  assert.ok(exposed.includes("X-Limit"), "Exposed headers must include X-Limit");
  assert.ok(exposed.includes("X-Total-Pages"), "Exposed headers must include X-Total-Pages");
});

// =============================================================================
// TEST 12: Public application registration via recovery backup code path
// =============================================================================
await runTest("MFA-12: Public application registration via recovery backup code path", async () => {
  const clientPublicBackup = "client-public-app-backup";
  const clientPublicBackupCb = "https://public-backup.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientPublicBackup,
    clientId: clientPublicBackup,
    name: "Public App Backup MFA",
    redirectUris: [clientPublicBackupCb],
    allowedOrigins: ["https://public-backup.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const state = "state_backup_public_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientPublicBackup, clientPublicBackupCb, state, pkce.challenge);

  const authRes = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(authRes.status, 302);

  const setCookie = authRes.headers.get("set-cookie") || "";
  const txMatch = setCookie.match(/oauth_transaction_id=[^;]+/);
  const clientMatch = setCookie.match(/current_client_id=[^;]+/);
  const authCookies = [txMatch?.[0], clientMatch?.[0]].filter(Boolean).join("; ");

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookies }),
    body: JSON.stringify({
      email: publicMfaUserEmail,
      password: publicMfaUserPass,
      callbackURL: authUrl,
    }),
  });
  assert.equal(loginRes.status, 200);

  // Before second factor: must not be registered
  const preReg = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: clientPublicBackup,
  });
  assert.equal(preReg, null);

  const mfaCookie = extractMfaCookie(loginRes);
  const combinedCookies = [mfaCookie, authCookies].filter(Boolean).join("; ");
  const backupCode = publicBackupCodes[0];

  const verifyRes = await app.request("/api/auth/two-factor/verify-backup-code", {
    method: "POST",
    headers: getTestHeaders({ Cookie: combinedCookies }),
    body: JSON.stringify({ code: backupCode }),
  });
  assert.equal(verifyRes.status, 200);

  // After second factor: must be registered exactly once
  const postReg = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: clientPublicBackup,
  });
  assert.ok(postReg);
  assert.equal(postReg.clientId, clientPublicBackup);
  assert.equal(postReg.userId, publicMfaUserId);
});

// =============================================================================
// TEST 13: Failed MFA creates no application membership
// =============================================================================
await runTest("MFA-13: Failed MFA creates no application membership", async () => {
  const clientFail = "client-public-fail-test";
  const clientFailCb = "https://public-fail.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientFail,
    clientId: clientFail,
    name: "Public App Fail Test",
    redirectUris: [clientFailCb],
    allowedOrigins: ["https://public-fail.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const state = "state_fail_test_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientFail, clientFailCb, state, pkce.challenge);

  const authRes = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders(),
  });
  const setCookie = authRes.headers.get("set-cookie") || "";
  const txMatch = setCookie.match(/oauth_transaction_id=[^;]+/);
  const clientMatch = setCookie.match(/current_client_id=[^;]+/);
  const authCookies = [txMatch?.[0], clientMatch?.[0]].filter(Boolean).join("; ");

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookies }),
    body: JSON.stringify({
      email: publicMfaUserEmail,
      password: publicMfaUserPass,
      callbackURL: authUrl,
    }),
  });
  assert.equal(loginRes.status, 200);

  const mfaCookie = extractMfaCookie(loginRes);
  const combinedCookies = [mfaCookie, authCookies].filter(Boolean).join("; ");

  // Provide incorrect TOTP code
  const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: combinedCookies }),
    body: JSON.stringify({ code: "000000" }),
  });
  assert.equal(verifyRes.status, 401);

  // Must not be registered
  const failReg = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: clientFail,
  });
  assert.equal(failReg, null);
});

// =============================================================================
// TEST 14: Forged query client_id or forged cookie without transaction creates no membership and no audit attribution
// =============================================================================
await runTest("MFA-14: Forged query or cookie without transaction creates no membership or false attribution", async () => {
  const forgedClientId = "client-public-app-mfa";

  // Standalone sign-in (no OAuth authorize)
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: publicMfaUserEmail,
      password: publicMfaUserPass,
    }),
  });
  assert.equal(loginRes.status, 200);

  const mfaCookie = extractMfaCookie(loginRes);
  const totpCode = await createOTP(publicRawSecret, { digits: 6, period: 30 }).totp();

  // Clean out any existing registration for this test
  await db.collection("user_app_registrations").deleteMany({
    userId: publicMfaUserId,
    clientId: forgedClientId,
  });

  // Attempt to pass forged query client_id and forged current_client_id cookie
  const verifyRes = await app.request(`/api/auth/two-factor/verify-totp?client_id=${forgedClientId}`, {
    method: "POST",
    headers: getTestHeaders({
      Cookie: `${mfaCookie}; current_client_id=${forgedClientId}`,
    }),
    body: JSON.stringify({ code: totpCode }),
  });
  assert.equal(verifyRes.status, 200);

  // Assert no registration was created
  const reg = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: forgedClientId,
  });
  assert.equal(reg, null, "Forged query or cookie must never create application membership");

  // Assert audit event recorded null for clientId to prevent false attribution
  const auditEvent = await db.collection("auth_events").findOne(
    { eventType: "two_factor_verify", userId: publicMfaUserId },
    { sort: { timestamp: -1 } }
  );
  assert.ok(auditEvent);
  assert.equal(auditEvent.clientId, null, "Audit event must not attribute to forged client_id");
});

// =============================================================================
// TEST 15: Conflicting query client_id against transaction creates no membership
// =============================================================================
await runTest("MFA-15: Conflicting query client_id against transaction creates no membership", async () => {
  const clientPublicConflict = "client-public-app-conflict";
  const clientPublicConflictCb = "https://public-conflict.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientPublicConflict,
    clientId: clientPublicConflict,
    name: "Public App Conflict",
    redirectUris: [clientPublicConflictCb],
    allowedOrigins: ["https://public-conflict.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const state = "state_conflict_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientPublicConflict, clientPublicConflictCb, state, pkce.challenge);

  const authRes = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders(),
  });
  const setCookie = authRes.headers.get("set-cookie") || "";
  const txMatch = setCookie.match(/oauth_transaction_id=[^;]+/);
  const clientMatch = setCookie.match(/current_client_id=[^;]+/);
  const authCookies = [txMatch?.[0], clientMatch?.[0]].filter(Boolean).join("; ");

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookies }),
    body: JSON.stringify({
      email: publicMfaUserEmail,
      password: publicMfaUserPass,
      callbackURL: authUrl,
    }),
  });
  assert.equal(loginRes.status, 200);

  const mfaCookie = extractMfaCookie(loginRes);
  const combinedCookies = [mfaCookie, authCookies].filter(Boolean).join("; ");
  const totpCode = await createOTP(publicRawSecret, { digits: 6, period: 30 }).totp();

  // Attacker injects conflicting client_id query param
  const verifyRes = await app.request("/api/auth/two-factor/verify-totp?client_id=client-different-app", {
    method: "POST",
    headers: getTestHeaders({ Cookie: combinedCookies }),
    body: JSON.stringify({ code: totpCode }),
  });
  assert.equal(verifyRes.status, 200);

  // Verify no registration was created for either client
  const reg1 = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: clientPublicConflict,
  });
  assert.equal(reg1, null, "Conflicting context must abort membership registration");
  const reg2 = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: "client-different-app",
  });
  assert.equal(reg2, null);
});

// =============================================================================
// TEST 16: Expired OAuth transaction cannot create membership
// =============================================================================
await runTest("MFA-16: Expired OAuth transaction cannot create membership", async () => {
  const clientPublicExp = "client-public-app-expired";
  const clientPublicExpCb = "https://public-exp.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientPublicExp,
    clientId: clientPublicExp,
    name: "Public App Expired",
    redirectUris: [clientPublicExpCb],
    allowedOrigins: ["https://public-exp.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const state = "state_exp_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientPublicExp, clientPublicExpCb, state, pkce.challenge);

  const authRes = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders(),
  });
  const setCookie = authRes.headers.get("set-cookie") || "";
  const txMatch = setCookie.match(/oauth_transaction_id=([^;]+)/);
  const rawTxId = txMatch ? txMatch[1] : "";
  const clientMatch = setCookie.match(/current_client_id=[^;]+/);
  const authCookies = [txMatch?.[0], clientMatch?.[0]].filter(Boolean).join("; ");

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookies }),
    body: JSON.stringify({
      email: publicMfaUserEmail,
      password: publicMfaUserPass,
      callbackURL: authUrl,
    }),
  });
  assert.equal(loginRes.status, 200);

  // Expire transaction in the database
  await db.collection("oauth_transactions").updateOne(
    { transactionId: rawTxId },
    { $set: { expiresAt: new Date(Date.now() - 10000) } }
  );

  const mfaCookie = extractMfaCookie(loginRes);
  const combinedCookies = [mfaCookie, authCookies].filter(Boolean).join("; ");
  const totpCode = await createOTP(publicRawSecret, { digits: 6, period: 30 }).totp();

  const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: combinedCookies }),
    body: JSON.stringify({ code: totpCode }),
  });
  assert.equal(verifyRes.status, 200);

  // Verify no registration was created
  const reg = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: clientPublicExp,
  });
  assert.equal(reg, null, "Expired transaction must not create membership");
});

// =============================================================================
// TEST 17: Disabled client receives no new membership
// =============================================================================
await runTest("MFA-17: Disabled client receives no new membership", async () => {
  const clientPublicDisabled = "client-public-disabled";
  const clientPublicDisabledCb = "https://public-disabled.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientPublicDisabled,
    clientId: clientPublicDisabled,
    name: "Public App Disabled",
    redirectUris: [clientPublicDisabledCb],
    allowedOrigins: ["https://public-disabled.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const state = "state_dis_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientPublicDisabled, clientPublicDisabledCb, state, pkce.challenge);

  const authRes = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders(),
  });
  const setCookie = authRes.headers.get("set-cookie") || "";
  const txMatch = setCookie.match(/oauth_transaction_id=[^;]+/);
  const clientMatch = setCookie.match(/current_client_id=[^;]+/);
  const authCookies = [txMatch?.[0], clientMatch?.[0]].filter(Boolean).join("; ");

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookies }),
    body: JSON.stringify({
      email: publicMfaUserEmail,
      password: publicMfaUserPass,
      callbackURL: authUrl,
    }),
  });
  assert.equal(loginRes.status, 200);

  // Disable client in database before MFA verification
  await db.collection("oauthClient").updateOne(
    { clientId: clientPublicDisabled },
    { $set: { disabled: true } }
  );

  const mfaCookie = extractMfaCookie(loginRes);
  const combinedCookies = [mfaCookie, authCookies].filter(Boolean).join("; ");
  const totpCode = await createOTP(publicRawSecret, { digits: 6, period: 30 }).totp();

  const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: combinedCookies }),
    body: JSON.stringify({ code: totpCode }),
  });
  assert.equal(verifyRes.status, 200);

  // Verify no registration was created
  const reg = await db.collection("user_app_registrations").findOne({
    userId: publicMfaUserId,
    clientId: clientPublicDisabled,
  });
  assert.equal(reg, null, "Disabled client must not receive new membership");
});

// =============================================================================
// TEST 18: Super admin with MFA does not receive application membership
// =============================================================================
await runTest("MFA-18: Super admin with MFA does not receive application membership", async () => {
  const clientSuperTest = "client-public-super-test";
  const clientSuperTestCb = "https://public-super.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientSuperTest,
    clientId: clientSuperTest,
    name: "Public App Super Test",
    redirectUris: [clientSuperTestCb],
    allowedOrigins: ["https://public-super.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const state = "state_super_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientSuperTest, clientSuperTestCb, state, pkce.challenge);

  const authRes = await app.request(authUrl, {
    method: "GET",
    headers: getTestHeaders(),
  });
  const setCookie = authRes.headers.get("set-cookie") || "";
  const txMatch = setCookie.match(/oauth_transaction_id=[^;]+/);
  const clientMatch = setCookie.match(/current_client_id=[^;]+/);
  const authCookies = [txMatch?.[0], clientMatch?.[0]].filter(Boolean).join("; ");

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookies }),
    body: JSON.stringify({
      email: superAdminEmail,
      password: superAdminPass,
      callbackURL: authUrl,
    }),
  });
  assert.equal(loginRes.status, 200);

  const mfaCookie = extractMfaCookie(loginRes);
  const combinedCookies = [mfaCookie, authCookies].filter(Boolean).join("; ");
  const superB32Secret = new URL(super2faSetup.totpURI).searchParams.get("secret")!;
  const superRawSecret = new TextDecoder().decode(base32.decode(superB32Secret));
  const totpCode = await createOTP(superRawSecret, { digits: 6, period: 30 }).totp();

  const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: combinedCookies }),
    body: JSON.stringify({ code: totpCode }),
  });
  assert.equal(verifyRes.status, 200);

  // Super admin must never be recorded in user_app_registrations
  const reg = await db.collection("user_app_registrations").findOne({
    userId: superAdminId,
    clientId: clientSuperTest,
  });
  assert.equal(reg, null, "Super admin must never receive consumer app membership");
});

// Helper for focused tests
async function createTestMfaUser(email: string, pass: string, name: string) {
  const signUp = await authProvider.api.signUpEmail({
    body: { email, password: pass, name },
  });
  const userId = String(signUp.user.id);
  const preSignIn = await authProvider.api.signInEmail({
    body: { email, password: pass },
    asResponse: true,
  });
  const preCookie = (preSignIn.headers.get("set-cookie") || "").split(";")[0];
  const setup = await authProvider.api.enableTwoFactor({
    body: { password: pass, method: "totp" },
    headers: new Headers({ cookie: preCookie }),
  });
  const b32Secret = new URL(setup.totpURI).searchParams.get("secret")!;
  const rawSecret = new TextDecoder().decode(base32.decode(b32Secret));
  const backupCodes = setup.backupCodes;
  const initCode = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
  await authProvider.api.verifyTOTP({
    body: { code: initCode },
    headers: new Headers({ cookie: preCookie }),
    asResponse: true,
  });
  return { userId, email, pass, rawSecret, backupCodes };
}

// =============================================================================
// TEST 19: Valid TOTP and recovery-code flows register the correct user once
// =============================================================================
await runTest("MFA-19: Valid TOTP and recovery-code flows register the correct user once", async () => {
  const clientRegOnce = "client-public-reg-once";
  const clientRegOnceCb = "https://public-reg-once.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientRegOnce,
    clientId: clientRegOnce,
    name: "Public App Reg Once",
    redirectUris: [clientRegOnceCb],
    allowedOrigins: ["https://public-reg-once.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const uTotp = await createTestMfaUser("totp_once@example.com", "TotpOnce123!Aa", "TOTP Once User");
  const stateTotp = "state_totp_once_" + crypto.randomBytes(6).toString("hex");
  const pkceTotp = makePKCE();
  const authUrlTotp = makeAuthorizeUrl(clientRegOnce, clientRegOnceCb, stateTotp, pkceTotp.challenge);

  const authResTotp = await app.request(authUrlTotp, { method: "GET", headers: getTestHeaders() });
  const setCookieTotp = authResTotp.headers.get("set-cookie") || "";
  const txTotp = setCookieTotp.match(/oauth_transaction_id=[^;]+/)?.[0];
  const clientTotp = setCookieTotp.match(/current_client_id=[^;]+/)?.[0];
  const authCookiesTotp = [txTotp, clientTotp].filter(Boolean).join("; ");

  const loginResTotp = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookiesTotp }),
    body: JSON.stringify({ email: uTotp.email, password: uTotp.pass, callbackURL: authUrlTotp }),
  });
  assert.equal(loginResTotp.status, 200);

  const mfaCookieTotp = extractMfaCookie(loginResTotp);
  const combinedCookiesTotp = [mfaCookieTotp, authCookiesTotp].filter(Boolean).join("; ");
  const totpCode = await createOTP(uTotp.rawSecret, { digits: 6, period: 30 }).totp();

  const verifyResTotp = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: combinedCookiesTotp }),
    body: JSON.stringify({ code: totpCode }),
  });
  assert.equal(verifyResTotp.status, 200);

  const countTotp = await db.collection("user_app_registrations").countDocuments({
    userId: uTotp.userId,
    clientId: clientRegOnce,
  });
  assert.equal(countTotp, 1, "TOTP flow must register user exactly once");

  // Recovery code flow registration
  const clientRecOnce = "client-public-rec-once";
  const clientRecOnceCb = "https://public-rec-once.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientRecOnce,
    clientId: clientRecOnce,
    name: "Public App Recovery Once",
    redirectUris: [clientRecOnceCb],
    allowedOrigins: ["https://public-rec-once.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const uRec = await createTestMfaUser("rec_once@example.com", "RecOnce123!Aa", "Rec Once User");
  const stateRec = "state_rec_once_" + crypto.randomBytes(6).toString("hex");
  const pkceRec = makePKCE();
  const authUrlRec = makeAuthorizeUrl(clientRecOnce, clientRecOnceCb, stateRec, pkceRec.challenge);

  const authResRec = await app.request(authUrlRec, { method: "GET", headers: getTestHeaders() });
  const setCookieRec = authResRec.headers.get("set-cookie") || "";
  const txRec = setCookieRec.match(/oauth_transaction_id=[^;]+/)?.[0];
  const clientRec = setCookieRec.match(/current_client_id=[^;]+/)?.[0];
  const authCookiesRec = [txRec, clientRec].filter(Boolean).join("; ");

  const loginResRec = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookiesRec }),
    body: JSON.stringify({ email: uRec.email, password: uRec.pass, callbackURL: authUrlRec }),
  });
  assert.equal(loginResRec.status, 200);

  const mfaCookieRec = extractMfaCookie(loginResRec);
  const combinedCookiesRec = [mfaCookieRec, authCookiesRec].filter(Boolean).join("; ");

  const verifyResRec = await app.request("/api/auth/two-factor/verify-backup-code", {
    method: "POST",
    headers: getTestHeaders({ Cookie: combinedCookiesRec }),
    body: JSON.stringify({ code: uRec.backupCodes[0] }),
  });
  assert.equal(verifyResRec.status, 200);

  const countRec = await db.collection("user_app_registrations").countDocuments({
    userId: uRec.userId,
    clientId: clientRecOnce,
  });
  assert.equal(countRec, 1, "Recovery code flow must register user exactly once");
});

// =============================================================================
// TEST 20: Completed-session lookup failure creates no membership
// =============================================================================
await runTest("MFA-20: Completed-session lookup failure creates no membership", async () => {
  const clientLookupFail = "client-public-lookup-fail";
  const clientLookupFailCb = "https://public-lookup-fail.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientLookupFail,
    clientId: clientLookupFail,
    name: "Public App Lookup Fail",
    redirectUris: [clientLookupFailCb],
    allowedOrigins: ["https://public-lookup-fail.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const uFail = await createTestMfaUser("lookup_fail_u@example.com", "LookupFail123!Aa", "Lookup Fail User");
  const state = "state_lookup_fail_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientLookupFail, clientLookupFailCb, state, pkce.challenge);

  const authRes = await app.request(authUrl, { method: "GET", headers: getTestHeaders() });
  const setCookie = authRes.headers.get("set-cookie") || "";
  const txMatch = setCookie.match(/oauth_transaction_id=[^;]+/)?.[0];
  const clientMatch = setCookie.match(/current_client_id=[^;]+/)?.[0];
  const authCookies = [txMatch, clientMatch].filter(Boolean).join("; ");

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookies }),
    body: JSON.stringify({ email: uFail.email, password: uFail.pass, callbackURL: authUrl }),
  });
  assert.equal(loginRes.status, 200);

  const mfaCookie = extractMfaCookie(loginRes);
  const combinedCookies = [mfaCookie, authCookies].filter(Boolean).join("; ");
  const totpCode = await createOTP(uFail.rawSecret, { digits: 6, period: 30 }).totp();

  // Intercept session lookup to simulate completed-session lookup failure
  const origCollection = db.collection.bind(db);
  db.collection = ((name: string, ...args: any[]) => {
    const coll = origCollection(name, ...args);
    if (name === "session") {
      coll.findOne = (async () => null) as any;
    }
    return coll;
  }) as any;

  try {
    const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: getTestHeaders({ Cookie: combinedCookies }),
      body: JSON.stringify({ code: totpCode }),
    });
    assert.equal(verifyRes.status, 200);
  } finally {
    db.collection = origCollection;
  }

  // Verify that no membership was created and candidate fallback did NOT occur
  const reg = await db.collection("user_app_registrations").findOne({
    clientId: clientLookupFail,
  });
  assert.equal(reg, null, "Completed-session lookup failure must create no membership");
});

// =============================================================================
// TEST 21: Existing session for User A plus MFA continuation for User B never registers User A
// =============================================================================
await runTest("MFA-21: Existing session for User A plus MFA continuation for User B never registers User A as User B completed identity", async () => {
  const clientSwitch = "client-public-switch-isolation";
  const clientSwitchCb = "https://public-switch.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientSwitch,
    clientId: clientSwitch,
    name: "Public App Switch Isolation",
    redirectUris: [clientSwitchCb],
    allowedOrigins: ["https://public-switch.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  // User A: existing logged-in user with MFA enabled
  const userA = await createTestMfaUser("user_a_active@example.com", "UserAPass123!Aa", "User A Active");
  const userAPre = await authProvider.api.signInEmail({
    body: { email: userA.email, password: userA.pass },
    asResponse: true,
  });
  const userAMfaCookie = extractMfaCookie(userAPre);
  const codeA = await createOTP(userA.rawSecret, { digits: 6, period: 30 }).totp();
  const userAFull = await authProvider.api.verifyTOTP({
    body: { code: codeA },
    headers: new Headers({ cookie: userAMfaCookie }),
    asResponse: true,
  });
  const userACookie = extractSessionCookie(userAFull);
  assert.ok(userACookie, "User A must have active session cookie");

  // User B: MFA user starting OAuth continuation
  const userB = await createTestMfaUser("user_b_mfa@example.com", "UserBPass123!Aa", "User B MFA");
  const state = "state_user_b_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientSwitch, clientSwitchCb, state, pkce.challenge);

  const authRes = await app.request(authUrl, { method: "GET", headers: getTestHeaders() });
  const setCookie = authRes.headers.get("set-cookie") || "";
  const txMatch = setCookie.match(/oauth_transaction_id=[^;]+/)?.[0];
  const clientMatch = setCookie.match(/current_client_id=[^;]+/)?.[0];
  const authCookies = [txMatch, clientMatch].filter(Boolean).join("; ");

  const loginResB = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookies }),
    body: JSON.stringify({ email: userB.email, password: userB.pass, callbackURL: authUrl }),
  });
  assert.equal(loginResB.status, 200);

  const mfaCookieB = extractMfaCookie(loginResB);

  // Scenario 1: User A's session token sent with User B's OAuth continuation and User A's TOTP
  // Better Auth authenticates User A, but handler must reject membership due to bound identity mismatch
  const mixedCookiesA = [userACookie, mfaCookieB, authCookies].filter(Boolean).join("; ");
  const totpCodeA = await createOTP(userA.rawSecret, { digits: 6, period: 30 }).totp();

  const verifyResA = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mixedCookiesA }),
    body: JSON.stringify({ code: totpCodeA }),
  });
  assert.equal(verifyResA.status, 200);

  // User A must NEVER be registered for User B's OAuth client
  const regA = await db.collection("user_app_registrations").findOne({
    userId: userA.userId,
    clientId: clientSwitch,
  });
  assert.equal(regA, null, "User A must never be registered as User B completed identity");

  // Scenario 2: Valid completion by User B with their continuation
  const validCookiesB = [mfaCookieB, authCookies].filter(Boolean).join("; ");
  const totpCodeB = await createOTP(userB.rawSecret, { digits: 6, period: 30 }).totp();

  const verifyResB = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: validCookiesB }),
    body: JSON.stringify({ code: totpCodeB }),
  });
  assert.equal(verifyResB.status, 200);

  // User B must be registered
  const regB = await db.collection("user_app_registrations").findOne({
    userId: userB.userId,
    clientId: clientSwitch,
  });
  assert.ok(regB, "User B must be registered as completed identity");
});

// =============================================================================
// TEST 22: Missing or mismatched identity binding cannot create membership
// =============================================================================
await runTest("MFA-22: Missing or mismatched identity binding cannot create membership", async () => {
  const clientNobind = "client-public-nobind";
  const clientNobindCb = "https://public-nobind.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientNobind,
    clientId: clientNobind,
    name: "Public App No Bind",
    redirectUris: [clientNobindCb],
    allowedOrigins: ["https://public-nobind.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const uBinding = await createTestMfaUser("binding_test_u@example.com", "BindingPass123!Aa", "Binding User");

  // Part A: Missing boundUserId in pending transaction
  const txIdNoBind = "tx_nobind_" + crypto.randomBytes(8).toString("hex");
  await db.collection("oauth_transactions").insertOne({
    transactionId: txIdNoBind,
    clientId: clientNobind,
    redirectUri: clientNobindCb,
    state: "state_nobind",
    codeChallenge: "challenge_nobind",
    codeChallengeMethod: "S256",
    status: "pending",
    // No userId bound
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 600000),
  });

  // User logs in to get two_factor cookie
  const loginResA = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: uBinding.email, password: uBinding.pass }),
  });
  assert.equal(loginResA.status, 200);
  const mfaCookieA = extractMfaCookie(loginResA);
  const cookiesNoBind = [mfaCookieA, `oauth_transaction_id=${txIdNoBind}`].join("; ");

  const totpCodeA = await createOTP(uBinding.rawSecret, { digits: 6, period: 30 }).totp();
  const verifyResNoBind = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: cookiesNoBind }),
    body: JSON.stringify({ code: totpCodeA }),
  });
  assert.equal(verifyResNoBind.status, 200);

  const regNoBind = await db.collection("user_app_registrations").findOne({
    clientId: clientNobind,
  });
  assert.equal(regNoBind, null, "Missing identity binding must not create application membership");

  // Part B: Mismatched boundUserId in pending transaction
  const clientMismatch = "client-public-mismatch";
  const clientMismatchCb = "https://public-mismatch.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientMismatch,
    clientId: clientMismatch,
    name: "Public App Mismatch",
    redirectUris: [clientMismatchCb],
    allowedOrigins: ["https://public-mismatch.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const txIdMismatch = "tx_mismatch_" + crypto.randomBytes(8).toString("hex");
  await db.collection("oauth_transactions").insertOne({
    transactionId: txIdMismatch,
    clientId: clientMismatch,
    redirectUri: clientMismatchCb,
    state: "state_mismatch",
    codeChallenge: "challenge_mismatch",
    codeChallengeMethod: "S256",
    status: "pending",
    userId: "completely-different-user-id", // bound to someone else
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 600000),
  });

  const loginResB = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: uBinding.email, password: uBinding.pass }),
  });
  assert.equal(loginResB.status, 200);
  const mfaCookieB = extractMfaCookie(loginResB);
  const cookiesMismatch = [mfaCookieB, `oauth_transaction_id=${txIdMismatch}`].join("; ");

  const totpCodeB = await createOTP(uBinding.rawSecret, { digits: 6, period: 30 }).totp();
  const verifyResMismatch = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: cookiesMismatch }),
    body: JSON.stringify({ code: totpCodeB }),
  });
  assert.equal(verifyResMismatch.status, 200);

  const regMismatch = await db.collection("user_app_registrations").findOne({
    clientId: clientMismatch,
  });
  assert.equal(regMismatch, null, "Mismatched identity binding must not create application membership");
});

// =============================================================================
// TEST 23: Failed verification creates no membership (recovery code path)
// =============================================================================
await runTest("MFA-23: Failed verification creates no membership on recovery code path", async () => {
  const clientFailRec = "client-public-fail-rec";
  const clientFailRecCb = "https://public-fail-rec.example.com/oauth/callback";
  await db.collection("oauthClient").insertOne({
    id: clientFailRec,
    clientId: clientFailRec,
    name: "Public App Fail Recovery",
    redirectUris: [clientFailRecCb],
    allowedOrigins: ["https://public-fail-rec.example.com"],
    isPublic: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  });

  const uFailRec = await createTestMfaUser("fail_rec_u@example.com", "FailRec123!Aa", "Fail Rec User");
  const state = "state_fail_rec_" + crypto.randomBytes(6).toString("hex");
  const pkce = makePKCE();
  const authUrl = makeAuthorizeUrl(clientFailRec, clientFailRecCb, state, pkce.challenge);

  const authRes = await app.request(authUrl, { method: "GET", headers: getTestHeaders() });
  const setCookie = authRes.headers.get("set-cookie") || "";
  const txMatch = setCookie.match(/oauth_transaction_id=[^;]+/)?.[0];
  const clientMatch = setCookie.match(/current_client_id=[^;]+/)?.[0];
  const authCookies = [txMatch, clientMatch].filter(Boolean).join("; ");

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Cookie: authCookies }),
    body: JSON.stringify({ email: uFailRec.email, password: uFailRec.pass, callbackURL: authUrl }),
  });
  assert.equal(loginRes.status, 200);

  const mfaCookie = extractMfaCookie(loginRes);
  const combinedCookies = [mfaCookie, authCookies].filter(Boolean).join("; ");

  const verifyRes = await app.request("/api/auth/two-factor/verify-backup-code", {
    method: "POST",
    headers: getTestHeaders({ Cookie: combinedCookies }),
    body: JSON.stringify({ code: "invalid-backup-code-xyz" }),
  });
  assert.equal(verifyRes.status >= 400, true);

  const reg = await db.collection("user_app_registrations").findOne({
    clientId: clientFailRec,
  });
  assert.equal(reg, null, "Failed backup code verification must create no membership");
});

// =============================================================================
// TEST 24: Standalone MFA verification creates no unrelated app membership
// =============================================================================
await runTest("MFA-24: Standalone MFA verification creates no unrelated app membership", async () => {
  const uStandalone = await createTestMfaUser("standalone_u@example.com", "Standalone123!Aa", "Standalone User");

  // Sign in to initiate two factor challenge without any OAuth transaction or context
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: uStandalone.email, password: uStandalone.pass }),
  });
  assert.equal(loginRes.status, 200);

  const mfaCookie = extractMfaCookie(loginRes);
  const totpCode = await createOTP(uStandalone.rawSecret, { digits: 6, period: 30 }).totp();

  const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getTestHeaders({ Cookie: mfaCookie }),
    body: JSON.stringify({ code: totpCode }),
  });
  assert.equal(verifyRes.status, 200);

  const regCount = await db.collection("user_app_registrations").countDocuments({
    userId: uStandalone.userId,
  });
  assert.equal(regCount, 0, "Standalone MFA verification must create no app memberships");
});

// -----------------------------------------------------------------------------
// Teardown
// -----------------------------------------------------------------------------
await closeDb();
if (mongod) {
  await mongod.stop();
}

console.log("\n================================================================");
console.log(`  CONSUMER MFA CONTINUATION SUITE: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================\n");

if (failed > 0) {
  process.exit(1);
}
