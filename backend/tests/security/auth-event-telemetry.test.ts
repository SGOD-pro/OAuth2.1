import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId } from "mongodb";
import { SignJWT, generateKeyPair, exportJWK } from "jose";

// 1. Guaranteed disposable in-memory database
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;

const { assertIsMemoryServerUri } = await import("../fixtures/test-env-isolation");
assertIsMemoryServerUri(mongoUri);

process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
const GATEWAY_SECRET = "g".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = GATEWAY_SECRET;
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = "10.0.0.0/8,172.16.0.0/12";

const { getDb, closeDb } = await import("../../src/db/mongo");
const { default: app } = await import("../../src/app");
const { authProvider } = await import("../../src/utils/auth");
const {
  sanitizeAuthEvent,
  __simulateAuthEventStoreFailure,
  recordAuthEvent,
} = await import("../../src/db/state");

console.log("================================================================");
console.log("  SWYRA AUTH -- AUTHENTICATION EVENT TELEMETRY SUITE");
console.log("================================================================\n");

const db = await getDb();

// Generate genuine IdP RS256 keypair and store in jwks collection
const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
const jwkPublic = await exportJWK(publicKey);
const jwkPrivate = await exportJWK(privateKey);
const kid = "idp-telemetry-test-key";
jwkPublic.kid = kid;
jwkPublic.alg = "RS256";
jwkPublic.use = "sig";
jwkPrivate.kid = kid;
jwkPrivate.alg = "RS256";
jwkPrivate.use = "sig";

const { symmetricEncrypt } = await import("better-auth/crypto");
const enc = await symmetricEncrypt({
  key: process.env.BETTER_AUTH_SECRET!,
  data: JSON.stringify(jwkPrivate),
});

await db.collection("jwks").insertOne({
  _id: kid as any,
  id: kid,
  kid,
  alg: "RS256",
  publicKey: JSON.stringify(jwkPublic),
  privateKey: JSON.stringify(enc),
  createdAt: new Date(),
});

// Setup Super-Admin user in database
const superAdminId = new ObjectId().toString();
const superAdminEmail = "telemetry_superadmin@swyra.com";
await db.collection("user").insertOne({
  _id: new ObjectId(superAdminId),
  id: superAdminId,
  email: superAdminEmail,
  name: "Telemetry Super Admin",
  role: "super-admin",
  scopedClientId: null,
  emailVerified: true,
  createdAt: new Date(),
});

async function mintSuperAdminToken(): Promise<string> {
  return new SignJWT({
    sub: superAdminId,
    role: "super-admin",
    aud: "http://localhost:3000",
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer("http://localhost:3000")
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(privateKey);
}

const superAdminToken = await mintSuperAdminToken();

function getTestHeaders(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "x-internal-gateway-secret": GATEWAY_SECRET,
    "x-gateway-secret": GATEWAY_SECRET,
    "Origin": "http://localhost:5174",
    "Authorization": `Bearer ${superAdminToken}`,
    ...overrides,
  };
}

let testCount = 0;
async function runTest(num: number, title: string, fn: () => Promise<void>) {
  testCount++;
  console.log(`[TEST ${num}] ${title}`);
  try {
    await fn();
    console.log(`  -> PASS\n`);
  } catch (err) {
    console.error(`  -> FAIL:\n`, err);
    throw err;
  }
}

function makePKCE() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

// Register a test user for credential testing
const testUserEmail = "telemetry_user@example.com";
const testUserPassword = "Password123!Safe";
await authProvider.api.signUpEmail({
  body: { email: testUserEmail, password: testUserPassword, name: "Telemetry User" },
});
await authProvider.api.signUpEmail({
  body: { email: "lockout_test_user@example.com", password: "Password123!Lockout", name: "Lockout User" },
});

// Setup public and private OAuth clients
const publicClientId = "public-telemetry-app";
const privateClientId = "private-telemetry-app";
await db.collection("oauthClient").insertMany([
  {
    id: publicClientId,
    clientId: publicClientId,
    clientName: "Public Telemetry App",
    name: "Public Telemetry App",
    isPublic: true,
    redirectUris: ["https://public.example.com/callback"],
    allowedOrigins: ["https://public.example.com"],
    disabled: false,
    createdAt: new Date(),
  },
  {
    id: privateClientId,
    clientId: privateClientId,
    clientName: "Private Enterprise App",
    name: "Private Enterprise App",
    isPublic: false,
    redirectUris: ["https://private.example.com/callback"],
    allowedOrigins: ["https://private.example.com"],
    disabled: false,
    createdAt: new Date(),
  },
]);

// --------------------------------------------------------------------------
// TEST 1: Successful Sign-In Telemetry Logging
// --------------------------------------------------------------------------
await runTest(1, "Successful email sign-in records trustworthy audit event with no credentials", async () => {
  await db.collection("auth_events").deleteMany({});

  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Origin": "http://localhost:5174",
      "x-forwarded-for": "198.51.100.12",
      "user-agent": "TelemetryTester/1.0",
    },
    body: JSON.stringify({
      email: testUserEmail,
      password: testUserPassword,
    }),
  });

  assert.equal(res.status, 200, "Sign-in should succeed");

  const events = await db.collection("auth_events").find({ eventType: "sign_in" }).toArray();
  assert.equal(events.length, 1, "Exactly one sign_in event should be logged");

  const ev = events[0];
  assert.equal(ev.eventType, "sign_in");
  assert.equal(ev.outcome, "success");
  assert.equal(ev.targetIdentifier, testUserEmail);
  assert.equal(ev.ipAddress, "198.51.100.12");
  assert.ok(ev.timestamp instanceof Date, "Timestamp must be a real Date object");
  assert.equal(ev.userAgent, "TelemetryTester/1.0");

  // Invariant: No password, token, or cookie in event document
  const rawJson = JSON.stringify(ev);
  assert.ok(!rawJson.includes(testUserPassword), "Password must never be logged");
  assert.ok(!rawJson.includes("session_token"), "Session tokens must never be logged");
});

// --------------------------------------------------------------------------
// TEST 2: Failed Sign-In Telemetry Logging
// --------------------------------------------------------------------------
await runTest(2, "Failed sign-in records failure event with invalid_credentials reason", async () => {
  await db.collection("auth_events").deleteMany({});

  const badPassword = "CompletelyWrongPassword!999";
  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Origin": "http://localhost:5174",
      "x-forwarded-for": "203.0.113.44",
    },
    body: JSON.stringify({
      email: testUserEmail,
      password: badPassword,
    }),
  });

  assert.notEqual(res.status, 200, "Sign-in should fail with invalid password");

  const events = await db.collection("auth_events").find({ eventType: "sign_in" }).toArray();
  assert.equal(events.length, 1, "Exactly one sign_in event should be logged");

  const ev = events[0];
  assert.equal(ev.eventType, "sign_in");
  assert.equal(ev.outcome, "failure");
  assert.equal(ev.targetIdentifier, testUserEmail);
  assert.equal(ev.ipAddress, "203.0.113.44");
  assert.equal(ev.reason, "invalid_credentials");

  const rawJson = JSON.stringify(ev);
  assert.ok(!rawJson.includes(badPassword), "Bad password must never be logged");
});

// --------------------------------------------------------------------------
// TEST 3: Rate Limit Lockout Telemetry
// --------------------------------------------------------------------------
await runTest(3, "Target rate limit lockout logs account_lockout event with threshold details", async () => {
  await db.collection("auth_events").deleteMany({});
  await db.collection("rate_limits").deleteMany({});

  const lockoutEmail = "lockout_test_user@example.com";
  const targetHash = crypto.createHash("sha256").update(lockoutEmail.toLowerCase().trim()).digest("hex");
  const targetKey = `TARGET#${targetHash}`;

  // Pre-seed rate limit counts in storage to test lockout boundary instantaneously
  const { incrementRateLimit } = await import("../../src/db/state");
  for (let i = 0; i < 16; i++) {
    await incrementRateLimit(targetKey, Date.now(), 300 * 1000);
  }

  // Attempt 17 must be blocked with 429 and logged as account_lockout
  const blockedRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Origin": "http://localhost:5174",
      "x-forwarded-for": "192.0.2.99",
    },
    body: JSON.stringify({
      email: lockoutEmail,
      password: "PasswordToFailLockout!",
    }),
  });

  assert.equal(blockedRes.status, 429, "Target rate limit must trigger 429 lockout");

  const lockoutEvents = await db.collection("auth_events").find({ eventType: "account_lockout" }).toArray();
  assert.ok(lockoutEvents.length >= 1, "Must log account_lockout event when rate limit is exceeded");

  const lockout = lockoutEvents[0];
  assert.equal(lockout.outcome, "denied");
  assert.equal(lockout.reason, "rate_limit_exceeded");
  assert.equal(lockout.targetIdentifier, lockoutEmail);
  assert.equal(lockout.details?.threshold, 15);
  assert.equal(lockout.details?.windowSeconds, 300);
});

// --------------------------------------------------------------------------
// TEST 4: Private Application Denial Telemetry
// --------------------------------------------------------------------------
await runTest(4, "Private application access denial records oauth_authorize event with client info", async () => {
  await db.collection("auth_events").deleteMany({});

  // Sign in as test user to get session
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
    body: JSON.stringify({ email: testUserEmail, password: testUserPassword }),
  });
  const allSetCookies = loginRes.headers.getSetCookie ? loginRes.headers.getSetCookie() : [loginRes.headers.get("set-cookie") || ""];
  const cookieHeader = allSetCookies.map(c => c.split(";")[0]).join("; ");

  // Attempt OAuth authorize on private client without app registration
  const pkce = makePKCE();
  const authRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${privateClientId}&redirect_uri=https://private.example.com/callback&response_type=code&state=state_xyz123&code_challenge=${pkce.challenge}&code_challenge_method=S256&scope=openid+profile+email`,
    {
      method: "GET",
      headers: {
        Cookie: cookieHeader,
        "x-forwarded-for": "198.51.100.55",
      },
    }
  );

  assert.equal(authRes.status, 302, "Must redirect with error=access_denied");
  const location = authRes.headers.get("location") || "";
  assert.ok(location.includes("error=access_denied"), "Redirect location must contain access_denied");

  const events = await db.collection("auth_events").find({ eventType: "oauth_authorize" }).toArray();
  assert.equal(events.length, 1, "Must log private application authorization denial event");

  const ev = events[0];
  assert.equal(ev.outcome, "denied");
  assert.equal(ev.clientId, privateClientId);
  assert.equal(ev.clientName, "Private Enterprise App");
  assert.equal(ev.reason, "private_app_unauthorized");
  assert.equal(ev.targetIdentifier, testUserEmail);
  assert.equal(ev.ipAddress, "198.51.100.55");
});

// --------------------------------------------------------------------------
// TEST 5: Unknown Client Identifier Handling
// --------------------------------------------------------------------------
await runTest(5, "Unknown client ID records denied event without fabricating client name", async () => {
  await db.collection("auth_events").deleteMany({});

  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
    body: JSON.stringify({
      email: testUserEmail,
      password: testUserPassword,
      client_id: "non-existent-client-id",
    }),
  });

  assert.equal(res.status, 400, "Unknown client must be rejected with 400");
  const events = await db.collection("auth_events").find({ clientId: "non-existent-client-id" }).toArray();
  assert.equal(events.length, 1, "Must record event for rejected unknown client");

  const ev = events[0];
  assert.equal(ev.outcome, "denied");
  assert.equal(ev.clientId, "non-existent-client-id");
  assert.equal(ev.clientName, null, "Must never fabricate client name for non-existent client");
  assert.equal(ev.reason, "invalid_client");
});

// --------------------------------------------------------------------------
// TEST 6: Two-Factor Verification Telemetry Handlers
// --------------------------------------------------------------------------
await runTest(6, "Two-factor verification failure records event without OTP code", async () => {
  await db.collection("auth_events").deleteMany({});

  const bogusCode = "987654";
  const res = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Origin": "http://localhost:5174",
      "x-forwarded-for": "198.51.100.77",
    },
    body: JSON.stringify({ code: bogusCode }),
  });

  assert.notEqual(res.status, 200, "Verification with bogus code should fail");

  const events = await db.collection("auth_events").find({ eventType: "two_factor_verify" }).toArray();
  assert.equal(events.length, 1, "Must log two_factor_verify event");

  const ev = events[0];
  assert.equal(ev.outcome, "failure");
  assert.equal(ev.reason, "invalid_totp_code");
  assert.equal(ev.details?.method, "totp");
  assert.equal(ev.ipAddress, "198.51.100.77");

  const rawJson = JSON.stringify(ev);
  assert.ok(!rawJson.includes(bogusCode), "OTP code must NEVER be logged or stored in event");
});

// --------------------------------------------------------------------------
// TEST 7: Recovery Backup Code Telemetry Handlers
// --------------------------------------------------------------------------
await runTest(7, "Recovery code verification failure records event without backup code", async () => {
  await db.collection("auth_events").deleteMany({});

  const bogusBackupCode = "backup-secret-code-12345";
  const res = await app.request("/api/auth/two-factor/verify-backup-code", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Origin": "http://localhost:5174",
      "x-forwarded-for": "198.51.100.88",
    },
    body: JSON.stringify({ code: bogusBackupCode }),
  });

  assert.notEqual(res.status, 200, "Verification with bogus backup code should fail");

  const events = await db.collection("auth_events").find({ eventType: "recovery_code_verify" }).toArray();
  assert.equal(events.length, 1, "Must log recovery_code_verify event");

  const ev = events[0];
  assert.equal(ev.outcome, "failure");
  assert.equal(ev.reason, "invalid_backup_code");
  assert.equal(ev.details?.method, "backup_code");
  assert.equal(ev.ipAddress, "198.51.100.88");

  const rawJson = JSON.stringify(ev);
  assert.ok(!rawJson.includes(bogusBackupCode), "Recovery code must NEVER be logged or stored in event");
});

// --------------------------------------------------------------------------
// TEST 8: Admin Logs APIs - Super-Admin Access Gate
// --------------------------------------------------------------------------
await runTest(8, "Admin log endpoints strictly reject non-super-admin requests", async () => {
  // Non-authenticated request
  const unauthRes = await app.request("/api/admin/logs", { method: "GET" });
  assert.ok(unauthRes.status === 401 || unauthRes.status === 403, "Unauthenticated access must be rejected");

  const unauthV2Res = await app.request("/api/admin/v2/logs", { method: "GET" });
  assert.ok(unauthV2Res.status === 401 || unauthV2Res.status === 403, "Unauthenticated v2 access must be rejected");

  // Authenticated as Super Admin
  const authRes = await app.request("/api/admin/logs", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(authRes.status, 200, "Super admin must be granted access");
  assert.ok(Array.isArray(await authRes.json()), "Default endpoint must return an array for backwards compatibility");

  const authV2Res = await app.request("/api/admin/v2/logs", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(authV2Res.status, 200, "Super admin must be granted access to v2");
  const v2Body = await authV2Res.json();
  assert.ok(Array.isArray(v2Body.logs), "v2 endpoint must return structured object with logs array");
  assert.ok(typeof v2Body.pagination === "object", "v2 endpoint must return pagination metadata");
});

// --------------------------------------------------------------------------
// TEST 9: Bounded Pagination and Filtering in Admin Logs API
// --------------------------------------------------------------------------
await runTest(9, "Admin logs API supports bounded pagination and outcome/action/client filters", async () => {
  await db.collection("auth_events").deleteMany({});
  await db.collection("session").deleteMany({});
  await db.collection("admin_audit").deleteMany({});

  // Seed 5 test events
  await recordAuthEvent({
    eventType: "sign_in",
    outcome: "success",
    targetIdentifier: "user1@example.com",
    clientId: publicClientId,
    clientName: "Public Telemetry App",
    ipAddress: "198.51.100.1",
    timestamp: new Date("2026-03-01T10:00:00Z"),
  });
  await recordAuthEvent({
    eventType: "sign_in",
    outcome: "failure",
    targetIdentifier: "user2@example.com",
    clientId: publicClientId,
    clientName: "Public Telemetry App",
    ipAddress: "198.51.100.2",
    reason: "invalid_credentials",
    timestamp: new Date("2026-03-01T10:05:00Z"),
  });
  await recordAuthEvent({
    eventType: "oauth_authorize",
    outcome: "denied",
    targetIdentifier: "user3@example.com",
    clientId: privateClientId,
    clientName: "Private Enterprise App",
    ipAddress: "198.51.100.3",
    reason: "private_app_unauthorized",
    timestamp: new Date("2026-03-01T10:10:00Z"),
  });
  await recordAuthEvent({
    eventType: "sign_in",
    outcome: "success",
    targetIdentifier: "user4@example.com",
    clientId: publicClientId,
    clientName: "Public Telemetry App",
    ipAddress: "198.51.100.4",
    timestamp: new Date("2026-03-01T10:15:00Z"),
  });
  await recordAuthEvent({
    eventType: "two_factor_verify",
    outcome: "failure",
    targetIdentifier: "user5@example.com",
    ipAddress: "198.51.100.5",
    reason: "invalid_totp_code",
    timestamp: new Date("2026-03-01T10:20:00Z"),
  });

  // Test pagination: page=1&limit=2
  const page1Res = await app.request("/api/admin/logs?page=1&limit=2", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(page1Res.status, 200);
  const page1 = await page1Res.json();
  assert.equal(page1.length, 2, "Page 1 limit 2 must return exactly 2 items");
  assert.equal(page1Res.headers.get("X-Total-Count"), "5");
  assert.equal(page1Res.headers.get("X-Total-Pages"), "3");

  // Test filter by outcome=failure
  const failRes = await app.request("/api/admin/logs?outcome=failure", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(failRes.status, 200);
  const failLogs = await failRes.json();
  assert.equal(failLogs.length, 2, "Must return only the 2 failure events");
  failLogs.forEach((l: any) => assert.equal(l.outcome, "failure"));

  // Test filter by clientId
  const clientRes = await app.request(`/api/admin/logs?clientId=${privateClientId}`, {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(clientRes.status, 200);
  const clientLogs = await clientRes.json();
  assert.equal(clientLogs.length, 1, "Must return only the 1 private client event");
  assert.equal(clientLogs[0].clientId, privateClientId);

  // Test filter by date range
  const rangeRes = await app.request("/api/admin/logs?from=2026-03-01T10:04:00Z&to=2026-03-01T10:16:00Z", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(rangeRes.status, 200);
  const rangeLogs = await rangeRes.json();
  assert.equal(rangeLogs.length, 3, "Date range must match the 3 events within window");
});

// --------------------------------------------------------------------------
// TEST 10: Event Store Failure Resilience (Graceful Degradation)
// --------------------------------------------------------------------------
await runTest(10, "Authentication succeeds gracefully even when event logging store fails", async () => {
  __simulateAuthEventStoreFailure(true);
  try {
    const res = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: testUserEmail, password: testUserPassword }),
    });
    assert.equal(res.status, 200, "Sign-in MUST succeed even if auth event storage fails");
  } finally {
    __simulateAuthEventStoreFailure(false);
  }
});

// --------------------------------------------------------------------------
// TEST 11: Data Sanitization and Redaction Invariant
// --------------------------------------------------------------------------
await runTest(11, "Sanitizer strictly strips forbidden credentials from event details", async () => {
  const dirtyEvent: any = {
    eventType: "sign_in",
    outcome: "failure",
    targetIdentifier: "victim@example.com",
    details: {
      safeField: "safe value",
      password: "SuperSecretPassword123",
      otp: "123456",
      totp: "654321",
      token: "secret-token-xyz",
      cookie: "session=sensitive",
      clientSecret: "client-secret-abc",
    },
  };

  const clean = sanitizeAuthEvent(dirtyEvent);
  assert.equal(clean.details?.safeField, "safe value", "Safe fields must be preserved");
  assert.equal((clean.details as any)?.password, undefined, "password must be stripped");
  assert.equal((clean.details as any)?.otp, undefined, "otp must be stripped");
  assert.equal((clean.details as any)?.totp, undefined, "totp must be stripped");
  assert.equal((clean.details as any)?.token, undefined, "token must be stripped");
  assert.equal((clean.details as any)?.cookie, undefined, "cookie must be stripped");
  assert.equal((clean.details as any)?.clientSecret, undefined, "clientSecret must be stripped");
});

// Cleanup disposable Mongo
await closeDb();
await mongod.stop();

console.log("================================================================");
console.log(`  ALL ${testCount} AUTHENTICATION EVENT TELEMETRY TESTS PASSED`);
console.log("================================================================\n");
