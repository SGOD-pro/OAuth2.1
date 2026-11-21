import dotenv from "dotenv";
dotenv.config();

import assert from "node:assert/strict";
import crypto from "crypto";
import { MongoMemoryServer } from "mongodb-memory-server";

// Start disposable in-memory MongoDB before importing any application modules
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

// Configure test environment
process.env.NODE_ENV = "test";
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;
process.env.MONGO_URI = mongoUri;
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "https://auth.example.com";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "https://app.example.com";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32";
process.env.APP_ADMIN_JWT_SECRET = process.env.APP_ADMIN_JWT_SECRET || "b".repeat(32);
process.env.APP_ADMIN_TOTP_KEY = process.env.APP_ADMIN_TOTP_KEY || "c".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");
const stateModule = await import("../../src/db/state");
const {
  BoundedEmergencyLimiter,
  emergencyRateLimiter,
  createRateLimiter,
} = await import("../../src/middleware/rate-limit");
const { config } = await import("../../src/config");
const { Hono } = await import("hono");

console.log("================================================================");
console.log("  SWYRA AUTH -- RATE LIMITING STORE FAILURE & SECURITY MODES");
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

function getTestHeaders(clientIp: string, overrides: Record<string, string> = {}): Headers {
  const h = new Headers();
  h.set("host", "auth.example.com");
  h.set("content-type", "application/json");
  h.set("x-forwarded-for", clientIp);
  for (const [k, v] of Object.entries(overrides)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

// --------------------------------------------------------------------------
// TEST 1: Redis Failure -> Mongo Fallback Works
// --------------------------------------------------------------------------
await runTest("RATE-1: Redis failure + Mongo fallback properly enforces limit and blocks with 429", async () => {
  const testIp = `10.42.1.${Math.floor(Math.random() * 200) + 1}`;
  const prefix = `test_mongo_fallback_${crypto.randomBytes(4).toString("hex")}`;
  const limit = 3;
  const windowMs = 60 * 1000;

  const testApp = new Hono();
  testApp.use(
    "/test-endpoint",
    createRateLimiter({
      windowMs,
      limit,
      prefix,
      sensitivity: "public",
    })
  );
  testApp.get("/test-endpoint", (c) => c.json({ status: "ok" }, 200));

  // Requests 1..3 should succeed
  for (let i = 1; i <= limit; i++) {
    const res = await testApp.request("/test-endpoint", {
      method: "GET",
      headers: getTestHeaders(testIp),
    });
    assert.equal(res.status, 200, `Request ${i} should succeed within limit`);
  }

  // Request 4 should be blocked with 429
  const blockedRes = await testApp.request("/test-endpoint", {
    method: "GET",
    headers: getTestHeaders(testIp),
  });
  assert.equal(blockedRes.status, 429, "Request exceeding limit must return HTTP 429");
  const data = await blockedRes.json();
  assert.equal(data.error, "too_many_requests");
});

// --------------------------------------------------------------------------
// TEST 2: Dual Failure (Redis + Mongo) on Admin Endpoint -> FAILS CLOSED
// --------------------------------------------------------------------------
await runTest("RATE-2: Redis failure + Mongo failure -> Admin endpoint FAILS CLOSED (never unlimited)", async () => {
  const testIp = `10.42.2.${Math.floor(Math.random() * 200) + 1}`;
  const prefix = `test_admin_failclosed_${crypto.randomBytes(4).toString("hex")}`;

  const testApp = new Hono();
  testApp.use(
    "/admin-endpoint",
    createRateLimiter({
      windowMs: 60 * 1000,
      limit: 5,
      prefix,
      sensitivity: "admin",
    })
  );
  testApp.post("/admin-endpoint", (c) => c.json({ status: "provisioned" }, 200));

  // Simulate total MongoDB store failure
  stateModule.__simulateRateLimitStoreFailure(true);

  try {
    // Under dual failure, admin request must immediately fail closed with 429
    const res = await testApp.request("/admin-endpoint", {
      method: "POST",
      headers: getTestHeaders(testIp),
    });

    assert.equal(res.status, 429, "Admin endpoint must fail closed (429) when rate limit store is down");
    const data = await res.json();
    assert.equal(data.error, "too_many_requests");
    assert.ok(data.message.includes("administrative operations"), "Message must explain admin protection");
  } finally {
    stateModule.__simulateRateLimitStoreFailure(false);
  }
});

// --------------------------------------------------------------------------
// TEST 3: Dual Failure (Redis + Mongo) on Auth Endpoint -> FAILS CLOSED Immediately with Zero Handler Executions
// --------------------------------------------------------------------------
await runTest("RATE-3: Redis failure + Mongo failure -> Auth endpoint FAILS CLOSED immediately with zero handler executions, multi-worker safe, while public endpoint engages emergency fallback", async () => {
  const testIp = `10.42.3.${Math.floor(Math.random() * 200) + 1}`;
  const prefix = `test_auth_emerg_${crypto.randomBytes(4).toString("hex")}`;
  const limit = 4;
  const windowMs = 60 * 1000;
  let authHandlerExecutions = 0;
  let worker1HandlerExecutions = 0;
  let worker2HandlerExecutions = 0;
  let publicHandlerExecutions = 0;

  const testApp = new Hono();
  testApp.use(
    "/auth-endpoint",
    createRateLimiter({
      windowMs,
      limit,
      prefix,
      sensitivity: "auth",
    })
  );
  testApp.post("/auth-endpoint", (c) => {
    authHandlerExecutions++;
    return c.json({ status: "authenticated" }, 200);
  });

  // Two-worker regression: simulate two independent worker instances under store outage
  // In serverless / multi-process architectures, in-process limiters allow N * limit requests.
  // Immediate fail-closed ensures neither worker permits any requests.
  const worker1App = new Hono();
  worker1App.use(
    "/auth-worker",
    createRateLimiter({
      windowMs,
      limit,
      prefix: "test_worker_auth",
      sensitivity: "auth",
    })
  );
  worker1App.post("/auth-worker", (c) => {
    worker1HandlerExecutions++;
    return c.json({ status: "worker1_ok" }, 200);
  });

  const worker2App = new Hono();
  worker2App.use(
    "/auth-worker",
    createRateLimiter({
      windowMs,
      limit,
      prefix: "test_worker_auth",
      sensitivity: "auth",
    })
  );
  worker2App.post("/auth-worker", (c) => {
    worker2HandlerExecutions++;
    return c.json({ status: "worker2_ok" }, 200);
  });

  // Public endpoint with emergency limiter fallback
  const publicApp = new Hono();
  publicApp.use(
    "/public-endpoint",
    createRateLimiter({
      windowMs,
      limit,
      prefix: "test_public_emerg",
      sensitivity: "public",
    })
  );
  publicApp.get("/public-endpoint", (c) => {
    publicHandlerExecutions++;
    return c.json({ status: "public_ok" }, 200);
  });

  // Simulate MongoDB failure
  stateModule.__simulateRateLimitStoreFailure(true);

  try {
    // 1. Immediate denial on Auth Endpoint: request 1 must be rejected with 429
    const authRes = await testApp.request("/auth-endpoint", {
      method: "POST",
      headers: getTestHeaders(testIp),
    });
    assert.equal(authRes.status, 429, "Auth request under store failure must immediately return 429");
    assert.equal(authHandlerExecutions, 0, "Protected auth handler must NEVER execute under store failure");
    const authData = await authRes.json();
    assert.equal(authData.error, "too_many_requests");

    // 2. Two-Worker Regression: neither Worker 1 nor Worker 2 executes protected handler
    for (let i = 0; i < 3; i++) {
      const w1Res = await worker1App.request("/auth-worker", {
        method: "POST",
        headers: getTestHeaders(`10.42.3.${10 + i}`),
      });
      assert.equal(w1Res.status, 429, "Worker 1 must immediately deny auth request under store failure");

      const w2Res = await worker2App.request("/auth-worker", {
        method: "POST",
        headers: getTestHeaders(`10.42.3.${20 + i}`),
      });
      assert.equal(w2Res.status, 429, "Worker 2 must immediately deny auth request under store failure");
    }
    assert.equal(worker1HandlerExecutions, 0, "Worker 1 protected handler execution count must be 0");
    assert.equal(worker2HandlerExecutions, 0, "Worker 2 protected handler execution count must be 0");

    // 3. Preserve Bounded Public-Endpoint Fallback:
    // Public endpoint engages emergency limiter: requests 1..limit allowed (200), request limit+1 blocked (429)
    const publicIp = "10.42.3.99";
    for (let i = 1; i <= limit; i++) {
      const pubRes = await publicApp.request("/public-endpoint", {
        method: "GET",
        headers: getTestHeaders(publicIp),
      });
      assert.equal(pubRes.status, 200, `Public request ${i} should be allowed by emergency limiter`);
    }
    assert.equal(publicHandlerExecutions, limit, "Public handler must execute for allowed emergency requests");

    const pubBlocked = await publicApp.request("/public-endpoint", {
      method: "GET",
      headers: getTestHeaders(publicIp),
    });
    assert.equal(pubBlocked.status, 429, "Public request exceeding emergency limit must return 429");
    assert.equal(publicHandlerExecutions, limit, "Public handler must not execute when emergency limit exceeded");
  } finally {
    stateModule.__simulateRateLimitStoreFailure(false);
  }
});

// --------------------------------------------------------------------------
// TEST 4: Target-Keyed Credential Stuffing Defense with Rotating IPs under Store Failure
// --------------------------------------------------------------------------
await runTest("RATE-4: Credential stuffing target defense blocks brute force across rotating IPs even when stores fail", async () => {
  const victimEmail = `victim_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const targetHash = crypto.createHash("sha256").update(victimEmail).digest("hex");
  const targetKey = `TARGET#${targetHash}`;
  const targetLimit = 15;
  const targetWindowMs = 300 * 1000;

  // Clear any existing emergency record for this target key
  emergencyRateLimiter.clear();

  // Part A: Under normal Mongo fallback (Redis unavailable), target defense caps rotating IPs at 15
  for (let i = 1; i <= targetLimit; i++) {
    const rotatingIp = `198.51.${Math.floor(i / 250)}.${i % 250}`;
    const res = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders(rotatingIp, { Origin: config.frontendUrl }),
      body: JSON.stringify({ email: victimEmail, password: `WrongPass${i}!` }),
    });
    // Should fail credentials (400 / 401), NOT 429 yet
    assert.notEqual(res.status, 429, `Attempt ${i} should be processed before reaching target threshold`);
  }

  // Attempt 16 from yet another new IP address must be BLOCKED with 429
  const blockedRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders("198.51.99.99", { Origin: config.frontendUrl }),
    body: JSON.stringify({ email: victimEmail, password: "AnotherWrongPass!" }),
  });

  assert.equal(blockedRes.status, 429, "Target-keyed brute-force attempt 16 across rotating IPs must be blocked with 429");
  const data = await blockedRes.json();
  assert.equal(data.error, "too_many_requests");

  // Part B: Under total store outage (both Redis and Mongo failing), auth immediately fails closed on attempt 1
  stateModule.__simulateRateLimitStoreFailure(true);
  try {
    const outageRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders("198.51.100.1", { Origin: config.frontendUrl }),
      body: JSON.stringify({ email: `victim2_${crypto.randomBytes(4).toString("hex")}@example.com`, password: "WrongPass!" }),
    });
    assert.equal(outageRes.status, 429, "Auth sign-in under total store failure must fail closed on attempt 1");
  } finally {
    stateModule.__simulateRateLimitStoreFailure(false);
    emergencyRateLimiter.clear();
  }
});

// --------------------------------------------------------------------------
// TEST 5: BoundedEmergencyLimiter Memory Safety & Capacity Bounds
// --------------------------------------------------------------------------
await runTest("RATE-5: BoundedEmergencyLimiter strictly caps entry count and prunes expired keys", async () => {
  const maxCapacity = 50;
  const limiter = new BoundedEmergencyLimiter(maxCapacity);
  const now = Date.now();

  // Insert 100 distinct keys into a limiter capped at 50
  for (let i = 0; i < 100; i++) {
    limiter.increment(`key_${i}`, now, 60000, 10);
  }

  // Size must never exceed maxCapacity
  assert.ok(
    limiter.size() <= maxCapacity,
    `Limiter size (${limiter.size()}) must not exceed maxCapacity (${maxCapacity})`
  );

  // Advance time past TTL and prune
  limiter.prune(now + 65000);
  assert.equal(limiter.size(), 0, "All expired keys must be pruned after TTL expires");
});

console.log("================================================================");
console.log(`  RATE LIMITING FAILURE MODES SUITE: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

await mongod.stop();
process.exit(failed > 0 ? 1 : 0);
