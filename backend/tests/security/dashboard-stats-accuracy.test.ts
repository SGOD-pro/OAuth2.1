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

// Prove MONGO_URI matches the in-process disposable server
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
const { getTrustedClientIp } = await import("../../src/utils/security");

console.log("================================================================");
console.log("  SWYRA AUTH -- DASHBOARD STATS ACCURACY & HONEST DATA SUITE");
console.log("================================================================\n");

const db = await getDb();

// Generate genuine IdP RS256 keypair and store in jwks collection
const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwkPublic = await exportJWK(publicKey);
const kid = "idp-stats-test-key";
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

// Setup Super-Admin user in database
const superAdminId = new ObjectId().toString();
const superAdminEmail = "superadmin@swyra.com";
await db.collection("user").insertOne({
  _id: new ObjectId(superAdminId),
  id: superAdminId,
  email: superAdminEmail,
  name: "Super Admin",
  role: "super-admin",
  scopedClientId: null,
  emailVerified: true,
  createdAt: new Date(),
});

// Helper to mint signed RS256 token for Super Admin
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

// --------------------------------------------------------------------------
// TEST 1: Accurate Counts: Real Zero Values Preserved
// --------------------------------------------------------------------------
await runTest(1, "GET /api/admin/stats preserves real zero values without fallbacks", async () => {
  // Ensure no clients, no sessions
  await db.collection("oauthClient").deleteMany({});
  await db.collection("session").deleteMany({});

  const res = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(res.status, 200, "Super admin must be able to fetch stats");
  const data = await res.json();

  assert.equal(data.totalClients, 0, "totalClients must be strictly 0");
  assert.equal(
    data.activeClients,
    0,
    "activeClients must be strictly 0; MUST NOT fallback to totalClients or 1"
  );
  assert.equal(
    data.recentLogins,
    0,
    "recentLogins must be strictly 0; MUST NOT fallback to activeSessions or 1"
  );
  assert.equal(data.recentSessions24h, 0, "recentSessions24h must be strictly 0");
  assert.equal(data.activeSessions, 0, "activeSessions must be strictly 0");
  assert.ok(Array.isArray(data.recentActivity), "recentActivity must be an array");
  assert.equal(data.recentActivity.length, 0, "recentActivity must be empty");
});

// --------------------------------------------------------------------------
// TEST 2: Active Clients Determination: Disabled Clients Excluded
// --------------------------------------------------------------------------
await runTest(2, "GET /api/admin/stats correctly excludes disabled clients from activeClients", async () => {
  await db.collection("oauthClient").deleteMany({});

  // Insert 6 clients in various disabled/inactive states
  await db.collection("oauthClient").insertMany([
    { clientId: "c1", name: "Client 1", disabled: true },
    { clientId: "c2", name: "Client 2", is_active: false },
    { clientId: "c3", name: "Client 3", isActive: false },
    { clientId: "c4", name: "Client 4", status: "disabled" },
    { clientId: "c5", name: "Client 5", status: "inactive" },
    { clientId: "c6", name: "Client 6", status: "revoked" },
  ]);

  const res = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(res.status, 200);
  const data = await res.json();

  assert.equal(data.totalClients, 6, "totalClients must be 6");
  assert.equal(
    data.activeClients,
    0,
    "activeClients must be strictly 0 when all registered clients are disabled or inactive"
  );

  // Now insert 2 active clients
  await db.collection("oauthClient").insertMany([
    { clientId: "c7", name: "Active Client 7", disabled: false, status: "active" },
    { clientId: "c8", name: "Active Client 8" }, // default active
  ]);

  const res2 = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders(),
  });
  const data2 = await res2.json();

  assert.equal(data2.totalClients, 8, "totalClients must now be 8");
  assert.equal(data2.activeClients, 2, "activeClients must be strictly 2");
});

// --------------------------------------------------------------------------
// TEST 3: Zero Recent Sessions With Older Active Sessions
// --------------------------------------------------------------------------
await runTest(3, "GET /api/admin/stats preserves recentLogins=0 when active sessions are older than 24h", async () => {
  await db.collection("session").deleteMany({});

  // Insert 2 active sessions created 3 days ago (expires in 2 days)
  const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
  const futureExpiry = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);

  await db.collection("session").insertMany([
    {
      userId: "u1",
      token: "sess-tok-1",
      createdAt: threeDaysAgo,
      expiresAt: futureExpiry,
      ipAddress: "203.0.113.10",
    },
    {
      userId: "u2",
      token: "sess-tok-2",
      createdAt: threeDaysAgo,
      expiresAt: futureExpiry,
      ipAddress: "203.0.113.11",
    },
  ]);

  const res = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(res.status, 200);
  const data = await res.json();

  assert.equal(data.activeSessions, 2, "activeSessions must be 2");
  assert.equal(
    data.recentLogins,
    0,
    "recentLogins must be strictly 0; MUST NOT fallback to activeSessions (2) or 1"
  );
  assert.equal(data.recentSessions24h, 0, "recentSessions24h must be strictly 0");

  // Now insert a session created 1 hour ago
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  await db.collection("session").insertOne({
    userId: "u3",
    token: "sess-tok-3",
    createdAt: oneHourAgo,
    expiresAt: futureExpiry,
    ipAddress: "203.0.113.12",
  });

  const res2 = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders(),
  });
  const data2 = await res2.json();

  assert.equal(data2.activeSessions, 3, "activeSessions must be 3");
  assert.equal(data2.recentLogins, 1, "recentLogins must be strictly 1");
  assert.equal(data2.recentSessions24h, 1, "recentSessions24h must be strictly 1");
});

// --------------------------------------------------------------------------
// TEST 4: Honest IP Addresses and Timestamps in /api/admin/logs
// --------------------------------------------------------------------------
await runTest(4, "GET /api/admin/logs returns null for missing IPs and timestamps (no 127.0.0.1 fabrication)", async () => {
  await db.collection("session").deleteMany({});
  await db.collection("admin_audit").deleteMany({});

  const fixedHistoricTime = new Date("2026-01-15T12:00:00.000Z");

  // Insert test sessions:
  // 1. Explicit loopback IP
  // 2. Explicit external IP
  // 3. Missing IP and missing timestamp
  // 4. "unknown" IP string
  await db.collection("session").insertMany([
    {
      userId: "user_loopback",
      ipAddress: "127.0.0.1",
      createdAt: fixedHistoricTime,
    },
    {
      userId: "user_external",
      ipAddress: "198.51.100.99",
      createdAt: fixedHistoricTime,
    },
    {
      userId: "user_no_ip_no_time",
      // ipAddress omitted
      // createdAt omitted
    },
    {
      userId: "user_unknown_ip",
      ipAddress: "unknown",
      createdAt: fixedHistoricTime,
    },
  ]);

  // Insert test audit records:
  // 1. Missing IP, explicit timestamp
  // 2. Explicit loopback IP, missing timestamp
  await db.collection("admin_audit").insertMany([
    {
      actorUserId: "admin_1",
      action: "client_create",
      // ipAddress omitted
      timestamp: fixedHistoricTime,
    },
    {
      actorUserId: "admin_2",
      action: "client_update",
      ipAddress: "127.0.0.1",
      // timestamp omitted
    },
  ]);

  const res = await app.request("/api/admin/logs", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(res.status, 200);
  const logs = await res.json();
  assert.equal(logs.length, 6, "Must retrieve all 6 log items");

  const loopbackSession = logs.find((l: any) => l.userId === "user_loopback");
  assert.ok(loopbackSession, "Loopback session must exist");
  assert.equal(loopbackSession.ipAddress, "127.0.0.1", "Real loopback IP must be preserved as 127.0.0.1");
  assert.equal(loopbackSession.createdAt, fixedHistoricTime.toISOString());

  const externalSession = logs.find((l: any) => l.userId === "user_external");
  assert.ok(externalSession);
  assert.equal(externalSession.ipAddress, "198.51.100.99", "Real external IP must be preserved");

  const noIpSession = logs.find((l: any) => l.userId === "user_no_ip_no_time");
  assert.ok(noIpSession);
  assert.equal(noIpSession.ipAddress, null, "Missing IP MUST return null, NEVER 127.0.0.1");
  assert.equal(noIpSession.createdAt, null, "Missing timestamp MUST return null, NEVER current time");

  const unknownIpSession = logs.find((l: any) => l.userId === "user_unknown_ip");
  assert.ok(unknownIpSession);
  assert.equal(unknownIpSession.ipAddress, null, "String 'unknown' IP MUST normalize to null");

  const auditMissingIp = logs.find((l: any) => l.userId === "admin_1");
  assert.ok(auditMissingIp);
  assert.equal(auditMissingIp.ipAddress, null, "Audit log with missing IP MUST return null");
  assert.equal(auditMissingIp.createdAt, fixedHistoricTime.toISOString());

  const auditMissingTime = logs.find((l: any) => l.userId === "admin_2");
  assert.ok(auditMissingTime);
  assert.equal(auditMissingTime.ipAddress, "127.0.0.1", "Real loopback audit IP preserved");
  assert.equal(auditMissingTime.createdAt, null, "Audit log with missing timestamp MUST return null");
});

// --------------------------------------------------------------------------
// TEST 5: Honest IP Addresses and Timestamps in /api/admin/stats recentActivity
// --------------------------------------------------------------------------
await runTest(5, "GET /api/admin/stats recentActivity maps missing IPs and timestamps to null", async () => {
  await db.collection("session").deleteMany({});

  await db.collection("session").insertMany([
    {
      userId: "u_real",
      ipAddress: "127.0.0.1",
      createdAt: new Date("2026-01-10T10:00:00.000Z"),
      userAgent: "Mozilla/5.0 Chrome/120.0",
    },
    {
      userId: "u_missing",
      // ipAddress omitted
      // createdAt omitted
      // userAgent omitted
    },
  ]);

  const res = await app.request("/api/admin/stats", {
    method: "GET",
    headers: getTestHeaders(),
  });
  assert.equal(res.status, 200);
  const data = await res.json();
  const items = data.recentActivity;

  const realItem = items.find((i: any) => i.userId === "u_real");
  assert.ok(realItem);
  assert.equal(realItem.ipAddress, "127.0.0.1");
  assert.equal(realItem.timestamp, "2026-01-10T10:00:00.000Z");
  assert.equal(realItem.userAgent, "Mozilla/5.0");

  const missingItem = items.find((i: any) => i.userId === "u_missing");
  assert.ok(missingItem);
  assert.equal(missingItem.ipAddress, null, "Missing IP in recentActivity must be null");
  assert.equal(missingItem.timestamp, null, "Missing timestamp in recentActivity must be null");
  assert.equal(missingItem.userAgent, null, "Missing userAgent in recentActivity must be null");
});

// --------------------------------------------------------------------------
// TEST 6: getTrustedClientIp Resolution & Trusted Proxy Isolation
// --------------------------------------------------------------------------
await runTest(6, "getTrustedClientIp distinguishes missing headers, real loopback, and proxy chains", async () => {
  const trustedProxies = ["10.0.0.0/8", "172.16.0.0/12"];

  // 1. Missing forwarding headers completely
  const emptyHeaders = new Headers();
  const missingResult = getTrustedClientIp(emptyHeaders, trustedProxies);
  assert.equal(missingResult, "unknown", "Missing forwarding headers must resolve to 'unknown', NEVER '127.0.0.1'");

  // 2. Explicit real loopback IP via X-Forwarded-For
  const loopbackXff = new Headers({ "x-forwarded-for": "127.0.0.1" });
  const loopbackResult = getTrustedClientIp(loopbackXff, trustedProxies);
  assert.equal(loopbackResult, "127.0.0.1", "Explicit 127.0.0.1 header must resolve to '127.0.0.1'");

  // 3. Explicit real loopback IP via X-Real-IP
  const loopbackRealIp = new Headers({ "x-real-ip": "127.0.0.1" });
  assert.equal(getTrustedClientIp(loopbackRealIp, trustedProxies), "127.0.0.1");

  // 4. Empty trustedProxyCidrs collapses any external IP to "unknown"
  const untrustedXff = new Headers({ "x-forwarded-for": "203.0.113.50" });
  assert.equal(getTrustedClientIp(untrustedXff, []), "unknown", "Empty trustedProxyCidrs must collapse to 'unknown'");

  // 5. Multi-hop chain through trusted proxy extracts first untrusted hop from right
  const proxyChain = new Headers({
    "x-forwarded-for": "198.51.100.22, 10.0.0.1",
  });
  assert.equal(getTrustedClientIp(proxyChain, trustedProxies), "198.51.100.22");

  // 6. Chain where all hops match trusted proxy CIDRs resolves to leftmost hop
  const allTrustedChain = new Headers({
    "x-forwarded-for": "10.0.0.2, 10.0.0.1",
  });
  assert.equal(
    getTrustedClientIp(allTrustedChain, trustedProxies),
    "10.0.0.2",
    "Chain with only trusted proxy hops resolves to leftmost hop (origin client)"
  );
});

// --------------------------------------------------------------------------
// TEST 7: Rate-Limiting Behavior with Missing vs Real IP
// --------------------------------------------------------------------------
await runTest(7, "Rate limiting operates safely on 'unknown' IP without crashing or bypassing", async () => {
  // Test multiple requests with missing IP headers
  const reqHeadersWithoutIp = getTestHeaders();

  const res1 = await app.request("/api/admin/stats", {
    method: "GET",
    headers: reqHeadersWithoutIp,
  });
  assert.equal(res1.status, 200, "Request without IP headers must succeed and bucket safely");

  // Test request with explicit loopback header
  const reqHeadersWithLoopback = getTestHeaders({
    "x-forwarded-for": "127.0.0.1",
  });

  const res2 = await app.request("/api/admin/stats", {
    method: "GET",
    headers: reqHeadersWithLoopback,
  });
  assert.equal(res2.status, 200, "Request with explicit loopback must succeed");
});

// --------------------------------------------------------------------------
// TEST 8: UI Logic Verification: Zero and Unknown Formatting
// --------------------------------------------------------------------------
await runTest(8, "UI helper logic correctly formats zero and unknown values", async () => {
  // Simulate StatCard value rendering: value ?? '—'
  function renderStatValue(value: number | null | undefined): string | number {
    return value ?? "—";
  }

  assert.equal(renderStatValue(0), 0, "StatCard MUST display 0 when value is 0");
  assert.equal(renderStatValue(5), 5, "StatCard MUST display 5 when value is 5");
  assert.equal(renderStatValue(null), "—", "StatCard displays '—' when value is null");
  assert.equal(renderStatValue(undefined), "—", "StatCard displays '—' when value is undefined");

  // Simulate formatDate helper in AdminLogs:
  function formatDate(iso: string | null | undefined): string {
    if (!iso) return "Unknown";
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return "Unknown";
      return d.toLocaleString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
    } catch {
      return "Unknown";
    }
  }

  assert.equal(formatDate(null), "Unknown", "formatDate(null) returns 'Unknown'");
  assert.equal(formatDate(undefined), "Unknown", "formatDate(undefined) returns 'Unknown'");
  assert.equal(formatDate(""), "Unknown", "formatDate('') returns 'Unknown'");
  assert.equal(formatDate("not-a-date"), "Unknown", "formatDate(invalid) returns 'Unknown'");
  assert.ok(formatDate("2026-01-15T12:00:00.000Z").includes("2026"), "Valid date formats properly");

  // Simulate TableCell IP display:
  function renderIpDisplay(ip: string | null | undefined): string {
    return ip && ip.toLowerCase() !== "unknown" ? ip : "Unknown";
  }

  assert.equal(renderIpDisplay(null), "Unknown", "null IP renders 'Unknown'");
  assert.equal(renderIpDisplay(undefined), "Unknown", "undefined IP renders 'Unknown'");
  assert.equal(renderIpDisplay("unknown"), "Unknown", "'unknown' IP renders 'Unknown'");
  assert.equal(renderIpDisplay("127.0.0.1"), "127.0.0.1", "Real loopback IP renders '127.0.0.1'");
  assert.equal(renderIpDisplay("203.0.113.1"), "203.0.113.1", "Real external IP renders '203.0.113.1'");
});

// Teardown
await closeDb();
await mongod.stop();

console.log("================================================================");
console.log(`  ALL ${testCount} DASHBOARD STATS ACCURACY TESTS PASSED`);
console.log("================================================================\n");
