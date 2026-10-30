import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId } from "mongodb";
import { SignJWT, generateKeyPair, exportJWK } from "jose";

// 1. Start disposable in-memory MongoDB
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
process.env.TRUSTED_PROXY_CIDRS = "127.0.0.1/32,10.0.0.0/8";

// 2. Import modules
const { getDb, closeDb } = await import("../../src/db/mongo");
const { default: app } = await import("../../src/app");

console.log("================================================================");
console.log("  NOSQL INJECTION & MASS ASSIGNMENT BOUNDARY TEST SUITE");
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

// Generate RS256 keypair for testing admin bearer tokens
const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwkPublic = await exportJWK(publicKey);
const kid = "nosql-test-key";
jwkPublic.kid = kid;
jwkPublic.alg = "RS256";
jwkPublic.use = "sig";

await db.collection("jwks").insertOne({
  _id: kid as any,
  id: kid,
  kid,
  publicKey: JSON.stringify(jwkPublic),
  createdAt: new Date(),
});

const now = new Date();
// Seed test client
await db.collection("oauthClient").insertOne({
  _id: new ObjectId(),
  clientId: "app-alpha",
  id: "app-alpha",
  name: "Application Alpha",
  redirectUris: ["http://localhost:3000/callback"],
  allowedOrigins: ["http://localhost:3000"],
  isPublic: true,
  isDev: true,
  createdAt: now,
});

// Seed super admin
const superAdminId = new ObjectId().toString();
await db.collection("user").insertOne({
  _id: new ObjectId(superAdminId),
  id: superAdminId,
  email: "swyra@auth2.1.com",
  role: "super-admin",
  scopedClientId: null,
  emailVerified: true,
  createdAt: now,
});

// Helper to mint signed RS256 token
async function mintSuperToken(): Promise<string> {
  return new SignJWT({
    sub: superAdminId,
    role: "super-admin",
    scoped_client_id: null,
    aud: "http://localhost:3000",
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer("http://localhost:3000")
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(privateKey);
}

const superToken = await mintSuperToken();

// ==============================================================================
// 1. Sign-In Operator Injections ($ne, $gt)
// ==============================================================================

await runTest("NOSQL-1: Sign-in rejects email operator object {'$ne': null} with 400", async () => {
  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: { $ne: null },
      password: "some-password",
    }),
  });
  assert.equal(res.status, 400, "Sign-in with operator object must return 400 Bad Request");
  const data = await res.json();
  assert.equal(data.error, "invalid_input");
});

await runTest("NOSQL-2: Sign-in rejects email operator object {'$gt': ''} with 400", async () => {
  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: { $gt: "" },
      password: "some-password",
    }),
  });
  assert.equal(res.status, 400, "Sign-in with operator object must return 400 Bad Request");
});

// ==============================================================================
// 2. Sign-Up Operator Injections
// ==============================================================================

await runTest("NOSQL-3: Sign-up rejects operator injection {'$ne': null} with 400", async () => {
  const res = await app.request("/api/auth/sign-up/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({
      email: { $ne: null },
      password: "StrongPassword123!Aa",
      name: "Attacker",
    }),
  });
  assert.equal(res.status, 400, "Sign-up with operator object must return 400 Bad Request");
});

// ==============================================================================
// 3. Admin Endpoints: Operator Injections & Mass Assignment ($set, $gt)
// ==============================================================================

await runTest("NOSQL-4: Admin user provision rejects operator injection in body with 400", async () => {
  const res = await app.request("/api/admin/users", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${superToken}` }),
    body: JSON.stringify({
      email: { $ne: null },
      name: "Injected User",
    }),
  });
  assert.equal(res.status, 400, "User provision with operator keys must return 400");
  const data = await res.json();
  assert.equal(data.code, "ERR_INVALID_INPUT");
});

await runTest("NOSQL-5: Admin client update rejects operator injection {'$set': ...} with 400", async () => {
  const res = await app.request("/api/admin/clients/app-alpha", {
    method: "PATCH",
    headers: getTestHeaders({ Authorization: `Bearer ${superToken}` }),
    body: JSON.stringify({
      $set: { role: "super-admin" },
    }),
  });
  assert.equal(res.status, 400, "PATCH client with $set operator must return 400");
  const data = await res.json();
  assert.equal(data.code, "ERR_INVALID_INPUT");
});

await runTest("NOSQL-6: Admin app-admin creation rejects operator injection with 400", async () => {
  const res = await app.request("/api/admin/clients/app-alpha/app-admins", {
    method: "POST",
    headers: getTestHeaders({ Authorization: `Bearer ${superToken}` }),
    body: JSON.stringify({
      email: { $ne: null },
      password: "StrongPassword123!Aa",
    }),
  });
  assert.equal(res.status, 400, "App admin creation with operator injection must return 400");
  const data = await res.json();
  assert.equal(data.code, "ERR_INVALID_INPUT");
});

// ==============================================================================
// 4. Prototype Pollution & Dotted Keys Defense
// ==============================================================================

await runTest("NOSQL-7: Body containing '__proto__' key is strictly rejected with 400", async () => {
  const maliciousPayload = '{"__proto__": {"isAdmin": true}, "name": "Hacked Client"}';
  const res = await app.request("/api/admin/clients/app-alpha", {
    method: "PATCH",
    headers: getTestHeaders({ Authorization: `Bearer ${superToken}` }),
    body: maliciousPayload,
  });
  assert.equal(res.status, 400, "Prototype pollution key must be rejected with 400");
  const data = await res.json();
  assert.equal(data.code, "ERR_INVALID_INPUT");
});

await runTest("NOSQL-8: Body containing dotted key 'user.role' is strictly rejected with 400", async () => {
  const res = await app.request("/api/admin/clients/app-alpha", {
    method: "PATCH",
    headers: getTestHeaders({ Authorization: `Bearer ${superToken}` }),
    body: JSON.stringify({
      "user.role": "super-admin",
    }),
  });
  assert.equal(res.status, 400, "Dotted path keys must be rejected with 400");
  const data = await res.json();
  assert.equal(data.code, "ERR_INVALID_INPUT");
});

// ==============================================================================
// 5. Query Parameter & Parameter Type Boundaries
// ==============================================================================

await runTest("NOSQL-9: Query param with operator injection is rejected with 400", async () => {
  const res = await app.request("/api/admin/clients/app-alpha/users?userId=%24gt", {
    method: "GET",
    headers: getTestHeaders({ Authorization: `Bearer ${superToken}` }),
  });
  assert.equal(res.status, 400, "Query parameter starting with '$' must return 400");
  const data = await res.json();
  assert.equal(data.code, "ERR_INVALID_INPUT");
});

await runTest("NOSQL-10: Conflicting route client ID vs body client ID is rejected with 400", async () => {
  const res = await app.request("/api/admin/clients/app-alpha", {
    method: "PATCH",
    headers: getTestHeaders({ Authorization: `Bearer ${superToken}` }),
    body: JSON.stringify({
      clientId: "app-beta",
      name: "Conflicting Client Attempt",
    }),
  });
  assert.equal(res.status, 400, "Conflicting client ID between route and body must return 400");
  const data = await res.json();
  assert.equal(data.code, "ERR_CONFLICTING_CLIENT_ID");
});

console.log("\n================================================================");
console.log(`  NOSQL INJECTION BOUNDARY RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================\n");

await closeDb();
await mongod.stop();

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
