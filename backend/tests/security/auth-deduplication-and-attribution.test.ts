import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId } from "mongodb";
import { SignJWT, generateKeyPair, exportJWK } from "jose";

console.log("================================================================");
console.log("  SWYRA AUTH -- AUTH LOG DEDUPLICATION & ATTRIBUTION TEST SUITE");
console.log("================================================================\n");

const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;
process.env.BETTER_AUTH_SECRET = "d".repeat(32);
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
const { recordAuthEvent } = await import("../../src/db/state");
const { createOTP } = await import("@better-auth/utils/otp");
const { base32 } = await import("@better-auth/utils/base32");

const db = await getDb();

// Generate test IdP RS256 keypair for super-admin token
const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
const jwkPublic = await exportJWK(publicKey);
const jwkPrivate = await exportJWK(privateKey);
const kid = "idp-dedup-test-key";
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

// Setup Super-Admin in DB
const superAdminId = new ObjectId().toString();
const superAdminEmail = "dedup_superadmin@swyra.com";
await db.collection("user").insertOne({
  _id: new ObjectId(superAdminId),
  id: superAdminId,
  email: superAdminEmail,
  name: "Dedup Super Admin",
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

function getAdminHeaders(): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "x-internal-gateway-secret": GATEWAY_SECRET,
    "x-gateway-secret": GATEWAY_SECRET,
    "Origin": "http://localhost:5174",
    "Authorization": `Bearer ${superAdminToken}`,
  };
}

let passed = 0;
async function runTest(title: string, fn: () => Promise<void>) {
  console.log(`[TEST] ${title}`);
  try {
    await fn();
    console.log(`  -> PASS\n`);
    passed++;
  } catch (err) {
    console.error(`  -> FAIL:\n`, err);
    throw err;
  }
}

// Register test application
const testClientId = "dedup-test-app";
await db.collection("oauthClient").insertOne({
  id: testClientId,
  clientId: testClientId,
  clientName: "Dedup Test Application",
  name: "Dedup Test Application",
  isPublic: true,
  redirectUris: ["https://dedup.example.com/callback"],
  allowedOrigins: ["https://dedup.example.com"],
  disabled: false,
  createdAt: new Date(),
});

// Register standard test user
const userEmail = "dedup_user@example.com";
const userPassword = "Password123!Normal";
await authProvider.api.signUpEmail({
  body: { email: userEmail, password: userPassword, name: "Dedup User" },
});

// Register user with MFA
const mfaUserEmail = "dedup_mfa_user@example.com";
const mfaUserPassword = "Password123!Mfa";
const mfaSignUp = await authProvider.api.signUpEmail({
  body: { email: mfaUserEmail, password: mfaUserPassword, name: "MFA User" },
});
const mfaUserId = String(mfaSignUp.user.id);

// Enable TOTP for MFA user
const preSignIn = await authProvider.api.signInEmail({
  body: { email: mfaUserEmail, password: mfaUserPassword },
  asResponse: true,
});
const preCookie = (preSignIn.headers.get("set-cookie") || "").split(";")[0];
const totpSetup = await authProvider.api.enableTwoFactor({
  body: { password: mfaUserPassword, method: "totp" },
  headers: new Headers({ cookie: preCookie }),
});
const b32Secret = new URL(totpSetup.totpURI).searchParams.get("secret")!;
const rawSecret = new TextDecoder().decode(base32.decode(b32Secret));
const enableCode = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
await authProvider.api.verifyTOTP({
  body: { code: enableCode },
  headers: new Headers({ cookie: preCookie }),
  asResponse: true,
});

// ============================================================================
// TEST 1: Single Successful Login Deduplication & Correlation
// ============================================================================
await runTest("Single successful login produces exactly 1 log record with application attribution (not duplicated by session doc)", async () => {
  await db.collection("auth_events").deleteMany({});
  await db.collection("session").deleteMany({});

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Origin": "http://localhost:5174",
      "x-forwarded-for": "198.51.100.55",
    },
    body: JSON.stringify({
      email: userEmail,
      password: userPassword,
      clientId: testClientId,
    }),
  });

  assert.equal(loginRes.status, 200, "Sign-in should succeed");

  // Verify auth_events has correlation sessionId
  const authEvents = await db.collection("auth_events").find({ eventType: "sign_in" }).toArray();
  assert.equal(authEvents.length, 1, "Exactly one auth_event must be recorded");
  assert.ok(authEvents[0].sessionId, "auth_event must capture correlation sessionId");

  // Query /api/admin/logs: must return exactly 1 record, not 2
  const logsRes = await app.request("/api/admin/logs", {
    method: "GET",
    headers: getAdminHeaders(),
  });
  assert.equal(logsRes.status, 200);
  const logs = await logsRes.json();
  assert.equal(logs.length, 1, "Logs must deduplicate session document and return exactly 1 entry for login");
  assert.equal(logs[0].action, "sign_in");
  assert.equal(logs[0].outcome, "success");
  assert.equal(logs[0].appName, "Dedup Test Application");
  assert.equal(logs[0].clientId, testClientId);
});

// ============================================================================
// TEST 2: MFA Login Stages & No Premature Success Record
// ============================================================================
await runTest("MFA login does NOT record completed sign_in success prior to MFA verification", async () => {
  await db.collection("auth_events").deleteMany({});
  await db.collection("session").deleteMany({});

  // 1. Submit email + password
  const step1Res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Origin": "http://localhost:5174",
      "x-forwarded-for": "198.51.100.56",
    },
    body: JSON.stringify({
      email: mfaUserEmail,
      password: mfaUserPassword,
      clientId: testClientId,
    }),
  });

  assert.equal(step1Res.status, 200);
  const step1Json = await step1Res.json();
  assert.equal(step1Json.twoFactorRedirect, true, "Must require two-factor verification");

  // Verify NO sign_in success was recorded
  const prematureSignIns = await db.collection("auth_events").find({
    eventType: "sign_in",
    outcome: "success",
  }).toArray();
  assert.equal(prematureSignIns.length, 0, "MUST NOT record sign_in success before MFA is verified");

  // Verify two_factor_challenge was recorded
  const challenges = await db.collection("auth_events").find({
    eventType: "two_factor_challenge",
  }).toArray();
  assert.equal(challenges.length, 1, "Must record two_factor_challenge event for first stage");
  assert.equal(challenges[0].reason, "two_factor_required");

  // 2. Submit TOTP code
  const mfaCookie = (step1Res.headers.get("set-cookie") || "")
    .split(",")
    .map((s) => s.trim().split(";")[0])
    .filter((c) => c.includes("better-auth.two_factor"))
    .join("; ");

  const totpCode = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
  const step2Res = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Origin": "http://localhost:5174",
      "Cookie": mfaCookie,
      "x-forwarded-for": "198.51.100.56",
    },
    body: JSON.stringify({
      code: totpCode,
    }),
  });

  assert.equal(step2Res.status, 200, "TOTP verification should succeed");

  // Verify completed two_factor_verify event
  const verifyEvents = await db.collection("auth_events").find({
    eventType: "two_factor_verify",
    outcome: "success",
  }).toArray();
  assert.equal(verifyEvents.length, 1, "Must record two_factor_verify success event");
  assert.ok(verifyEvents[0].sessionId, "two_factor_verify event must have correlated sessionId");

  // Verify /api/admin/logs returns challenge and verify events without raw session duplicates
  const logsRes = await app.request("/api/admin/logs", {
    method: "GET",
    headers: getAdminHeaders(),
  });
  const logs = await logsRes.json();
  // Expect 2 events: two_factor_challenge and two_factor_verify (no duplicate unmapped session)
  assert.equal(logs.length, 2, "Must return exactly 2 distinct lifecycle events for MFA login");
  const actions = logs.map((l: any) => l.action).sort();
  assert.deepEqual(actions, ["two_factor_challenge", "two_factor_verify"]);
});

// ============================================================================
// TEST 3: Pagination Beyond 1,000 Records
// ============================================================================
await runTest("Pagination beyond 1,000 records returns correct slices and total count without truncation", async () => {
  await db.collection("auth_events").deleteMany({});
  await db.collection("session").deleteMany({});
  await db.collection("admin_audit").deleteMany({});

  const totalToSeed = 1050;
  const baseTime = new Date("2026-03-01T00:00:00Z").getTime();
  const docs = [];

  for (let i = 0; i < totalToSeed; i++) {
    docs.push({
      eventType: "sign_in",
      outcome: "success",
      targetIdentifier: `user_${i}@example.com`,
      clientId: testClientId,
      clientName: "Dedup Test Application",
      ipAddress: "198.51.100.1",
      timestamp: new Date(baseTime + i * 1000), // increasing timestamps
    });
  }

  await db.collection("auth_events").insertMany(docs);

  // Request page 1 with limit 50
  const page1Res = await app.request("/api/admin/logs?page=1&limit=50", {
    method: "GET",
    headers: getAdminHeaders(),
  });
  assert.equal(page1Res.status, 200);
  const page1 = await page1Res.json();
  assert.equal(page1.length, 50, "Page 1 limit 50 must return 50 items");
  assert.equal(page1Res.headers.get("X-Total-Count"), "1050");
  assert.equal(page1Res.headers.get("X-Total-Pages"), "21");

  // Request page 21 with limit 50 (skip 1000 items -> covers items 1001-1050)
  const page21Res = await app.request("/api/admin/logs?page=21&limit=50", {
    method: "GET",
    headers: getAdminHeaders(),
  });
  assert.equal(page21Res.status, 200);
  const page21 = await page21Res.json();
  assert.equal(page21.length, 50, "Page 21 beyond 1,000 records must return remaining 50 items");
  assert.equal(page21Res.headers.get("X-Total-Count"), "1050");
  assert.equal(page21Res.headers.get("X-Total-Pages"), "21");
});

// ============================================================================
// TEST 4: Database Failure Produces Visible Error (HTTP 500)
// ============================================================================
await runTest("Database failure produces visible HTTP 500 error instead of empty 200 result", async () => {
  const { setTestDbOverride } = await import("../../src/db/mongo");
  const brokenDb = {
    collection: (name: string) => {
      if (name === "auth_events" || name === "admin_audit" || name === "session") {
        throw new Error("Simulated database failure inside logs query");
      }
      return (db as any).collection(name);
    },
  } as any;

  setTestDbOverride(brokenDb);
  try {
    const res = await app.request("/api/admin/logs", {
      method: "GET",
      headers: getAdminHeaders(),
    });
    assert.equal(res.status, 500, "Database failure must return HTTP 500");
    const body = await res.json();
    assert.equal(body.code, "ERR_DATABASE_ERROR", "Must return ERR_DATABASE_ERROR code");
  } finally {
    setTestDbOverride(null);
  }
});

// Cleanup
await closeDb();
await mongod.stop();

console.log("================================================================");
console.log(`  ALL ${passed} DEDUPLICATION & ATTRIBUTION TESTS PASSED CLEANLY`);
console.log("================================================================\n");
