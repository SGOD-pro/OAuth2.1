// Guaranteed clean environment: never inherit external Redis credentials
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { fork } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId } from "mongodb";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 1. Guaranteed disposable in-memory database
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;

// Prove MONGO_URI matches the in-process disposable server, not any other loopback listener.
const { assertIsMemoryServerUri } = await import("../fixtures/test-env-isolation");
assertIsMemoryServerUri(mongoUri);
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
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
const { isOriginAllowed } = await import("../../src/middleware/cors");
const {
  getCachedOrigin,
  setCachedOrigin,
  invalidateOrigins,
  invalidateClientOrigins,
  extractClientOrigins,
  clearOriginCache,
  startOriginCheck,
  getRedisOutageDetected,
  setRedisOutageDetectedForTesting,
  getInvalidationMapSizeForTesting,
  clearInvalidationMapForTesting,
  setPreRedisWriteHookForTesting,
  setPostMongoCheckHookForTesting,
} = await import("../../src/cache/origin-cache");
const { setRedisClientForTesting, invalidateCachedOriginRedis, getCachedOriginRedis, setCachedOriginRedis } = await import("../../src/cache/redis");
const { getSharedRedisOutage, markSharedRedisOutage, putOriginCache, getOriginCache: getOriginCacheMongo, getNextAuthoritativeVersion, invalidateOriginCache } = await import("../../src/db/state");
const { Redis } = await import("@upstash/redis");
const { createMockRedisServer } = await import("../fixtures/mock-redis-server");

console.log("================================================================");
console.log("  SWYRA AUTH -- CORS CACHE & INVALIDATION CORRECTNESS SUITE");
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

const db = await getDb();

// Seed Super-Admin for management operations
const superEmail = "super_cors@swyra.com";
const superPass = "SuperCorsPass123!Aa";
const superSignUp = await authProvider.api.signUpEmail({
  body: { email: superEmail, password: superPass, name: "Super Admin CORS" },
});
const superId = String(superSignUp.user.id);
await db.collection("user").updateOne(
  { email: superEmail },
  { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
);

let ipCounter = 200;
function getTestHeaders(extra: Record<string, string> = {}): Headers {
  const h = new Headers();
  const ip = `198.51.100.${++ipCounter % 240 + 1}`;
  h.set("content-type", "application/json");
  h.set("host", "localhost:3000");
  h.set("origin", process.env.FRONTEND_URL || "http://localhost:5174");
  h.set("referer", (process.env.FRONTEND_URL || "http://localhost:5174") + "/");
  h.set("x-forwarded-for", `${ip}, 10.0.0.1`);
  h.set("x-gateway-secret", GATEWAY_SECRET);
  for (const [k, v] of Object.entries(extra)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

const superLoginRes = await app.request("/api/auth/sign-in/email", {
  method: "POST",
  headers: getTestHeaders(),
  body: JSON.stringify({ email: superEmail, password: superPass }),
});
const superCookie = (superLoginRes.headers.get("set-cookie") || "").split(";")[0];

function getAdminHeaders(extra: Record<string, string> = {}): Headers {
  return getTestHeaders({
    Cookie: superCookie,
    ...extra,
  });
}

// =============================================================================
// TEST 1: Positive and negative cache behavior in origin cache
// =============================================================================
await runTest("CORS-1: Positive and negative results are cached and retrieved correctly", async () => {
  await clearOriginCache();

  const testOriginA = "https://positive-test-app.example.com";
  const testOriginB = "https://negative-test-app.example.com";

  // Initially uncached
  assert.equal(await getCachedOrigin(testOriginA), null);
  assert.equal(await getCachedOrigin(testOriginB), null);

  // Store positive result
  await setCachedOrigin(testOriginA, true);
  assert.equal(await getCachedOrigin(testOriginA), true);

  // Store negative result
  await setCachedOrigin(testOriginB, false);
  assert.equal(await getCachedOrigin(testOriginB), false);

  // Invalidate specific origin
  await invalidateOrigins([testOriginA]);
  assert.equal(await getCachedOrigin(testOriginA), null);
  assert.equal(await getCachedOrigin(testOriginB), false); // B remains cached

  // Invalidate with empty array should clear all entries per documentation
  await setCachedOrigin(testOriginA, true);
  assert.equal(await getCachedOrigin(testOriginA), true);
  await invalidateOrigins([]);
  assert.equal(await getCachedOrigin(testOriginA), null);
  assert.equal(await getCachedOrigin(testOriginB), null);

  await clearOriginCache();
  assert.equal(await getCachedOrigin(testOriginB), null);
});

// =============================================================================
// TEST 2: extractClientOrigins extracts both allowedOrigins and redirect URI origins
// =============================================================================
await runTest("CORS-2: extractClientOrigins extracts all explicit and derived origins", async () => {
  const clientObj = {
    allowedOrigins: [
      "https://app1.example.com",
      "https://app2.example.com/",
      "https://app6.example.com/deep/resource/path",
      "https://app7.example.com/portal?foo=bar",
    ],
    allowed_origins: ["https://app3.example.com"],
    redirectUris: ["https://app4.example.com/oauth/callback", "https://app1.example.com/callback"],
    redirect_uris: ["https://app5.example.com:8443/cb"],
  };

  const extracted = extractClientOrigins(clientObj);
  assert.ok(extracted.includes("https://app1.example.com"));
  assert.ok(extracted.includes("https://app2.example.com"));
  assert.ok(extracted.includes("https://app3.example.com"));
  assert.ok(extracted.includes("https://app4.example.com"));
  assert.ok(extracted.includes("https://app5.example.com:8443"));
  assert.ok(extracted.includes("https://app6.example.com"), "Full URL in allowedOrigins must be extracted to its web origin");
  assert.ok(extracted.includes("https://app7.example.com"), "URL with query params must be extracted to its web origin");
  assert.equal(extracted.length, 7); // app1 deduplicated
});

// =============================================================================
// TEST 3: Client creation invalidates origins and allows CORS request
// =============================================================================
await runTest("CORS-3: Client creation invalidates origins across cache layers", async () => {
  const origin = "https://newly-created-app.example.com";
  // Pre-seed negative cache to test invalidation on creation
  await setCachedOrigin(origin, false);
  assert.equal(await getCachedOrigin(origin), false);

  const createRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Created App",
      redirect_uris: [`${origin}/callback`],
      allowed_origins: [origin],
      is_public: false,
    }),
  });
  assert.equal(createRes.status, 201);

  // Cache entry should be invalidated on creation
  const cachedAfter = await getCachedOrigin(origin);
  assert.equal(cachedAfter, null, "Origin cache entry must be invalidated upon client creation");

  // Dynamic CORS preflight must now succeed
  const corsRes = await app.request("/api/auth/oauth2/authorize", {
    method: "OPTIONS",
    headers: new Headers({
      Origin: origin,
      "Access-Control-Request-Method": "GET",
    }),
  });
  assert.equal(corsRes.status, 204);
  assert.equal(corsRes.headers.get("access-control-allow-origin"), origin);
});

// =============================================================================
// TEST 4: Client update invalidates both old and new origins
// =============================================================================
await runTest("CORS-4: Client update invalidates old and new origins", async () => {
  const oldOrigin = "https://old-client-origin.example.com";
  const newOrigin = "https://new-client-origin.example.com";

  // Create client with oldOrigin
  const createRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Update Test App",
      redirect_uris: [`${oldOrigin}/callback`],
      allowed_origins: [oldOrigin],
      is_public: false,
    }),
  });
  assert.equal(createRes.status, 201);
  const created = await createRes.json();
  const clientId = created.client_id || created.clientId || created.id;

  // Populate cache for old origin
  assert.equal(await isOriginAllowed(oldOrigin), true);
  await setCachedOrigin(oldOrigin, true);
  await setCachedOrigin(newOrigin, false);

  // Patch client to use newOrigin instead
  const patchRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      redirect_uris: [`${newOrigin}/callback`],
      allowed_origins: [newOrigin],
    }),
  });
  assert.equal(patchRes.status, 200);

  // Both old and new origins must be invalidated in cache
  assert.equal(await getCachedOrigin(oldOrigin), null, "Old origin must be invalidated");
  assert.equal(await getCachedOrigin(newOrigin), null, "New origin must be invalidated");

  // Old origin is no longer allowed, new origin is allowed
  assert.equal(await isOriginAllowed(oldOrigin), false);
  assert.equal(await isOriginAllowed(newOrigin), true);
});

// =============================================================================
// TEST 5: Disabled client cannot keep origin allowed; active client preserves it
// =============================================================================
await runTest("CORS-5: Disabled client cannot keep origin allowed; multi-client overlap preserved", async () => {
  const sharedOrigin = "https://shared-origin.example.com";

  // Create Client A with sharedOrigin
  const createARes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Shared App A",
      redirect_uris: [`${sharedOrigin}/callback-a`],
      allowed_origins: [sharedOrigin],
      is_public: false,
    }),
  });
  assert.equal(createARes.status, 201);
  const createdA = await createARes.json();
  const clientAId = createdA.client_id || createdA.clientId || createdA.id;

  // Create Client B with sharedOrigin
  const createBRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Shared App B",
      redirect_uris: [`${sharedOrigin}/callback-b`],
      allowed_origins: [sharedOrigin],
      is_public: false,
    }),
  });
  assert.equal(createBRes.status, 201);
  const createdB = await createBRes.json();
  const clientBId = createdB.client_id || createdB.clientId || createdB.id;

  assert.equal(await isOriginAllowed(sharedOrigin), true);

  // Disable Client A
  const disableARes = await app.request(`/api/admin/clients/${clientAId}`, {
    method: "PATCH",
    headers: getAdminHeaders(),
    body: JSON.stringify({ disabled: true }),
  });
  assert.equal(disableARes.status, 200);

  // Shared origin MUST STILL BE ALLOWED because Client B is active
  assert.equal(
    await isOriginAllowed(sharedOrigin),
    true,
    "Active Client B must preserve origin access even when Client A is disabled"
  );

  // Now disable Client B
  const disableBRes = await app.request(`/api/admin/clients/${clientBId}`, {
    method: "PATCH",
    headers: getAdminHeaders(),
    body: JSON.stringify({ disabled: true }),
  });
  assert.equal(disableBRes.status, 200);

  // Shared origin MUST NOW BE DENIED because no active client uses it
  assert.equal(
    await isOriginAllowed(sharedOrigin),
    false,
    "Origin must be denied when all clients using it are disabled"
  );
});

// =============================================================================
// TEST 6: Client deletion invalidates all explicit and redirect-derived origins
// =============================================================================
await runTest("CORS-6: Client deletion invalidates explicit and derived origins", async () => {
  const deleteOrigin = "https://delete-me-origin.example.com";
  const deleteRedirectOrigin = "https://delete-redirect-origin.example.com";

  const createRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Delete Me App",
      redirect_uris: [`${deleteRedirectOrigin}/auth/callback`],
      allowed_origins: [deleteOrigin],
      is_public: false,
    }),
  });
  assert.equal(createRes.status, 201);
  const created = await createRes.json();
  const clientId = created.client_id || created.clientId || created.id;

  // Pre-seed positive cache
  await setCachedOrigin(deleteOrigin, true);
  await setCachedOrigin(deleteRedirectOrigin, true);

  // Delete client
  const delRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "DELETE",
    headers: getAdminHeaders(),
  });
  assert.equal(delRes.status, 200);

  // Both origins must be invalidated in cache
  assert.equal(await getCachedOrigin(deleteOrigin), null);
  assert.equal(await getCachedOrigin(deleteRedirectOrigin), null);

  // Both origins are no longer allowed
  assert.equal(await isOriginAllowed(deleteOrigin), false);
  assert.equal(await isOriginAllowed(deleteRedirectOrigin), false);
});

// =============================================================================
// TEST 7: Scoped app config patch invalidates origins
// =============================================================================
await runTest("CORS-7: Scoped app config patch invalidates origins", async () => {
  const scopedOrigin = "https://scoped-app.example.com";
  const patchedOrigin = "https://scoped-app-patched.example.com";

  const createRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Scoped App",
      redirect_uris: [`${scopedOrigin}/callback`],
      allowed_origins: [scopedOrigin],
      is_public: false,
    }),
  });
  assert.equal(createRes.status, 201);
  const created = await createRes.json();
  const clientId = created.client_id || created.clientId || created.id;

  // Seed App Admin for this specific client
  const appAdminEmail = `app_admin_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const appAdminPass = "AppAdminPass123!Aa";
  const signUpRes = await authProvider.api.signUpEmail({
    body: { email: appAdminEmail, password: appAdminPass, name: "App Admin Scoped" },
  });
  const appAdminUserId = String(signUpRes.user.id);
  await db.collection("user").updateOne(
    { email: appAdminEmail },
    { $set: { role: "admin", scopedClientId: clientId, emailVerified: true } }
  );
  await db.collection("app_admins").insertOne({
    userId: appAdminUserId,
    clientId: clientId,
    role: "admin",
    createdAt: new Date(),
  });

  const appAdminLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPass }),
  });
  assert.equal(appAdminLoginRes.status, 200);
  const appAdminCookie = (appAdminLoginRes.headers.get("set-cookie") || "").split(";")[0];

  await setCachedOrigin(scopedOrigin, true);
  await setCachedOrigin(patchedOrigin, false);

  const patchRes = await app.request(`/api/admin/app/${clientId}/config`, {
    method: "PATCH",
    headers: getTestHeaders({
      Cookie: appAdminCookie,
    }),
    body: JSON.stringify({
      redirect_uris: [`${patchedOrigin}/callback`],
      allowed_origins: [patchedOrigin],
    }),
  });
  assert.equal(patchRes.status, 200);

  assert.equal(await getCachedOrigin(scopedOrigin), null);
  assert.equal(await getCachedOrigin(patchedOrigin), null);
  assert.equal(await isOriginAllowed(patchedOrigin), true);
  assert.equal(await isOriginAllowed(scopedOrigin), false);
});

// =============================================================================
// TEST 8: Cache functions operate safely when Redis is unavailable
// =============================================================================
await runTest("CORS-8: Cache functions fall back safely when Redis is unavailable", async () => {
  // In our test environment, Upstash Redis env vars were deleted, so Redis is null / unavailable.
  // Verify that getCachedOrigin, setCachedOrigin, and invalidateOrigins execute without throwing.
  const fallbackOrigin = "https://fallback-test.example.com";

  await setCachedOrigin(fallbackOrigin, true);
  const cachedVal = await getCachedOrigin(fallbackOrigin);
  assert.equal(cachedVal, true, "MongoDB cache fallback must return stored value when Redis is unavailable");

  await invalidateOrigins([fallbackOrigin]);
  const invalidatedVal = await getCachedOrigin(fallbackOrigin);
  assert.equal(invalidatedVal, null, "MongoDB invalidation must succeed when Redis is unavailable");
});

// =============================================================================
// TEST 9: Deterministic race test: in-flight read cannot repopulate stale cache after client mutation
// =============================================================================
await runTest("CORS-9: Stale cache repopulation is strictly prevented during concurrent reads and client mutations", async () => {
  const raceOrigin = "https://race-test.example.com";

  // Create a client with raceOrigin
  const createRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Race Test Client",
      redirect_uris: [`${raceOrigin}/callback`],
      allowed_origins: [raceOrigin],
      is_public: false,
    }),
  });
  assert.equal(createRes.status, 201);
  const created = await createRes.json();
  const clientId = created.client_id || created.clientId || created.id;

  // Verify origin is initially allowed and uncached
  await clearOriginCache();
  assert.equal(await getCachedOrigin(raceOrigin), null);
  assert.equal(await isOriginAllowed(raceOrigin), true);

  // 1. Thread A: In-flight read begins at t1
  const inFlightCheck = await startOriginCheck(raceOrigin);
  assert.ok((inFlightCheck.startVersion ?? inFlightCheck.startTime) > 0);

  // 2. Thread B: Concurrent mutation: client is disabled and cache is invalidated at t2
  const disableRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      disabled: true,
    }),
  });
  assert.equal(disableRes.status, 200);

  // 3. Thread A: Read check finishes and attempts to write stale 'true' with t1 context
  await setCachedOrigin(raceOrigin, true, inFlightCheck);

  // 4. Assert: Stale 'true' MUST NOT be cached!
  const cachedAfterRace = await getCachedOrigin(raceOrigin);
  assert.equal(cachedAfterRace, null, "Cache must NOT be repopulated with stale allowed entry after concurrent invalidation");

  // Subsequent check must return false
  assert.equal(await isOriginAllowed(raceOrigin), false, "Disabled client origin must be disallowed");
});

// =============================================================================
// TEST 10: Redis-backed cache with disposable Redis mock: outage and recovery consistency
// =============================================================================
await runTest("CORS-10: Disposable Redis mock verifies outage fallback, invalidation recovery, and stale key purging", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  try {
    const redisOrigin = "https://redis-disposable.example.com";

    // 1. Write an entry to mock Redis and verify read hit
    await setCachedOrigin(redisOrigin, true);
    assert.equal(await getCachedOrigin(redisOrigin), true);
    assert.equal(mockRedis.has(`swyra:origin:${redisOrigin}`), true);

    // 2. Simulate Redis Outage during client invalidation
    mockRedis.simulateOutage();

    // Invalidation during outage fails for Redis but marks outage detected
    await invalidateOrigins([redisOrigin]);
    assert.equal(getRedisOutageDetected(), true, "Redis outage must be detected and recorded");

    // During outage: getCachedOrigin must fall back cleanly to MongoDB
    const fallbackVal = await getCachedOrigin(redisOrigin);
    assert.equal(fallbackVal, null, "Must fall back to MongoDB during Redis outage");

    // 3. Simulate Redis Recovery: Redis is reachable again with stale keys
    mockRedis.simulateRecovery();
    // Simulate that stale key survived in Redis because invalidation missed it
    mockRedis.set(`swyra:origin:${redisOrigin}`, true, 300);
    assert.equal(mockRedis.has(`swyra:origin:${redisOrigin}`), true);

    // When getCachedOrigin is called, recovery logic detects outage and flushes Redis
    const postRecoveryVal = await getCachedOrigin(redisOrigin);
    assert.equal(postRecoveryVal, null, "Stale key must not be returned upon Redis recovery");
    assert.equal(mockRedis.has(`swyra:origin:${redisOrigin}`), false, "Stale key must be purged from Redis during recovery");
    assert.equal(getRedisOutageDetected(), false, "Redis outage state must be cleared after recovery flush");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await markSharedRedisOutage(db, false);
    setRedisOutageDetectedForTesting(false);
  }
});

// =============================================================================
// TEST 11: Deterministic cross-process race test with disposable services
// =============================================================================
await runTest("CORS-11: Cross-process race condition: in-flight worker read rejected after parent client mutation", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const workerPath = path.resolve(__dirname, "../fixtures/cors-multi-process-worker.ts");
  const child = fork(workerPath, [], {
    execPath: process.execPath,
    execArgv: process.execArgv,
    env: {
      ...process.env,
      MONGO_URI: mongoUri,
      NODE_ENV: "test",
    },
    stdio: ["ignore", "inherit", "inherit", "ipc"],
  });

  const sendToChild = (msg: any): Promise<any> => {
    return new Promise((resolve, reject) => {
      const handler = (res: any) => {
        if (res.type === "ERROR") {
          child.off("message", handler);
          reject(new Error(res.error));
        } else {
          child.off("message", handler);
          resolve(res);
        }
      };
      child.on("message", handler);
      child.send(msg);
    });
  };

  try {
    // 1. Initialize worker with disposable Mongo and Redis
    const initRes = await sendToChild({
      type: "INIT",
      redisUrl: mockRedis.url,
      redisToken: mockRedis.token,
    });
    assert.equal(initRes.type, "INIT_OK");

    const multiProcessOrigin = "https://multi-process-race.example.com";

    // 2. Parent creates client with multiProcessOrigin
    const createRes = await app.request("/api/admin/clients", {
      method: "POST",
      headers: getAdminHeaders(),
      body: JSON.stringify({
        client_name: "Multi Process Client",
        redirect_uris: [`${multiProcessOrigin}/callback`],
        allowed_origins: [multiProcessOrigin],
        is_public: false,
      }),
    });
    assert.equal(createRes.status, 201);
    const created = await createRes.json();
    const clientId = created.client_id || created.clientId || created.id;

    // 3. Child Process A initiates check at t1 (reading state before mutation)
    const startRes = await sendToChild({
      type: "START_CHECK",
      origin: multiProcessOrigin,
    });
    assert.equal(startRes.type, "CHECK_STARTED");
    const t1 = startRes.startTime;
    assert.ok(t1 > 0);

    // 4. Parent Process B mutates client at t2 (disables client and invalidates origin)
    const disableRes = await app.request(`/api/admin/clients/${clientId}`, {
      method: "PATCH",
      headers: getAdminHeaders(),
      body: JSON.stringify({ disabled: true }),
    });
    assert.equal(disableRes.status, 200);

    // 5. Child Process A completes stale write at t3 with context { startTime: t1 }
    const writeRes = await sendToChild({
      type: "COMPLETE_WRITE",
      origin: multiProcessOrigin,
      allowed: true,
      startTime: t1,
    });
    assert.equal(writeRes.type, "WRITE_COMPLETED");

    // 6. Parent checks cache: must NOT be repopulated with true
    const parentCached = await getCachedOrigin(multiProcessOrigin);
    assert.equal(parentCached, null, "Parent cache must not have stale true from worker process");

    // 7. Child checks cache: must NOT return true
    const childCacheRes = await sendToChild({
      type: "CHECK_CACHE",
      origin: multiProcessOrigin,
    });
    assert.equal(childCacheRes.value, null, "Child cache lookup must not return stale true");

    // 8. Shared Redis Outage propagation across processes
    // Child triggers Redis outage in shared MongoDB state
    const outageRes = await sendToChild({
      type: "TRIGGER_OUTAGE",
    });
    assert.equal(outageRes.type, "OUTAGE_TRIGGERED");

    // Parent verifies that it detects the shared Redis outage via MongoDB state
    const sharedOutage = await getSharedRedisOutage(db);
    assert.equal(sharedOutage, true, "Parent process must detect Redis outage marked by worker process");
  } finally {
    try {
      child.send({ type: "EXIT" });
      await new Promise<void>((r) => {
        const timer = setTimeout(() => {
          child.kill();
          r();
        }, 1000);
        child.on("exit", () => {
          clearTimeout(timer);
          r();
        });
      });
    } catch {}
    setRedisClientForTesting(null);
    await mockRedis.close();
    await markSharedRedisOutage(db, false);
    setRedisOutageDetectedForTesting(false);
  }
});

// =============================================================================
// TEST 12: Invalidation map strict hard bounded cap of 1,000 entries
// =============================================================================
await runTest("CORS-12: Strict hard bounded cap of 1,000 entries on lastInvalidatedAt map", async () => {
  clearInvalidationMapForTesting();
  assert.equal(getInvalidationMapSizeForTesting(), 0);

  // Invalidate 1,200 unique origins in batches
  const batchSize = 100;
  for (let b = 0; b < 12; b++) {
    const origins: string[] = [];
    for (let i = 0; i < batchSize; i++) {
      origins.push(`https://bounded-test-${b}-${i}.example.com`);
    }
    await invalidateOrigins(origins);
  }

  // Map size must strictly be capped at 1,000
  const finalSize = getInvalidationMapSizeForTesting();
  assert.ok(finalSize <= 1000, `Map size must not exceed 1000 (actual: ${finalSize})`);
  assert.equal(finalSize, 1000, `Map size must be exactly 1000 when 1200 items inserted`);

  clearInvalidationMapForTesting();
});

// =============================================================================
// TEST 13: Atomic Lua invalidation combining key deletion and marker write
// =============================================================================
await runTest("CORS-13: Atomic Redis Lua invalidation script prevents stale repopulation during concurrent write", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  try {
    const atomicOrigin = "https://atomic-lua-race.example.com";

    // 1. Initial cached write
    await setCachedOrigin(atomicOrigin, true);
    assert.equal(await getCachedOrigin(atomicOrigin), true);
    assert.equal(mockRedis.has(`swyra:origin:${atomicOrigin}`), true);

    // 2. Start a read context at t1
    const ctx = await startOriginCheck(atomicOrigin);
    const t1 = ctx.startVersion ?? ctx.startTime;

    // Small delay to ensure timestamp difference
    await new Promise((r) => setTimeout(r, 10));

    // 3. Invalidate via atomic Lua script
    await invalidateOrigins([atomicOrigin]);

    // Verify atomic state in mock Redis: origin key deleted, invalidation marker set
    assert.equal(mockRedis.has(`swyra:origin:${atomicOrigin}`), false, "Origin cache key must be deleted atomically");
    assert.equal(mockRedis.has(`swyra:origin:inv:${atomicOrigin}`), true, "Invalidation marker must be set atomically");

    // 4. Stale write attempt with context from t1
    await setCachedOrigin(atomicOrigin, true, ctx);

    // Stale write must be rejected by Lua script!
    assert.equal(mockRedis.has(`swyra:origin:${atomicOrigin}`), false, "Stale origin must NOT be written to Redis");
    assert.equal(await getCachedOrigin(atomicOrigin), null, "Origin lookup must return null after invalidation");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await markSharedRedisOutage(db, false);
    setRedisOutageDetectedForTesting(false);
  }
});

await runTest("CORS-14: Global Redis invalidation preserves swyra:inv:global marker without deletion by scan", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  try {
    const o1 = "https://global-test-1.example.com";
    const o2 = "https://global-test-2.example.com";
    await setCachedOrigin(o1, true);
    await setCachedOrigin(o2, true);

    assert.equal(mockRedis.has(`swyra:origin:${o1}`), true);
    assert.equal(mockRedis.has(`swyra:origin:${o2}`), true);

    // Start in-flight check before global invalidation
    const inFlight = await startOriginCheck(o1);

    // Perform global invalidation (no origins passed)
    await invalidateOrigins();

    // Verify: origin keys deleted
    assert.equal(mockRedis.has(`swyra:origin:${o1}`), false, "Origin 1 must be deleted by scan");
    assert.equal(mockRedis.has(`swyra:origin:${o2}`), false, "Origin 2 must be deleted by scan");

    // CRITICAL: swyra:inv:global must SURVIVE the scan and NOT be deleted!
    assert.equal(mockRedis.has("swyra:inv:global"), true, "Global invalidation marker must NOT be deleted by swyra:origin:* scan");

    // An in-flight write from before the global invalidation must be rejected
    await setCachedOrigin(o1, true, inFlight);
    assert.equal(mockRedis.has(`swyra:origin:${o1}`), false, "In-flight write before global invalidation must be rejected");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await markSharedRedisOutage(db, false);
    setRedisOutageDetectedForTesting(false);
  }
});

await runTest("CORS-15: Shared monotonic versioning protects against stale writes regardless of clock differences", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  try {
    const skewedOrigin = "https://skewed-clock.example.com";

    // 1. Check starts and obtains version v1
    const ctx = await startOriginCheck(skewedOrigin);
    assert.ok(ctx.startVersion > 0, "startVersion must be positive integer");

    // 2. Invalidation occurs and increments version to v2
    await invalidateOrigins([skewedOrigin]);

    // 3. Stale write with startVersion v1 must be rejected by version ordering
    await setCachedOrigin(skewedOrigin, true, ctx);

    assert.equal(mockRedis.has(`swyra:origin:${skewedOrigin}`), false, "Stale write with earlier startVersion must be rejected");
    assert.equal(await getCachedOrigin(skewedOrigin), null, "Lookup must return null");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await markSharedRedisOutage(db, false);
    setRedisOutageDetectedForTesting(false);
  }
});

await runTest("CORS-16: Redis-to-MongoDB fallback and recovery with delayed writes and different counter values", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  try {
    const fallbackOrigin = "https://fallback-recovery.example.com";

    // 1. In-flight check begins at v1 while Redis is active
    const delayedCheckBeforeOutage = await startOriginCheck(fallbackOrigin);
    assert.ok(delayedCheckBeforeOutage.startVersion > 0);

    // 2. Redis experiences outage
    mockRedis.simulateOutage();
    setRedisOutageDetectedForTesting(true);
    await markSharedRedisOutage(db, true);

    // 3. During outage: invalidation occurs at v2 (MongoDB authoritative counter increments)
    await invalidateOrigins([fallbackOrigin]);

    // 4. Delayed write from before outage attempts to write with v1
    await setCachedOrigin(fallbackOrigin, true, delayedCheckBeforeOutage);

    // Verify: stale write rejected in MongoDB cache!
    assert.equal(await getCachedOrigin(fallbackOrigin), null, "Delayed write from before outage must be rejected by Mongo cache");

    // 5. Fresh check during outage gets current version v3
    const freshCheckDuringOutage = await startOriginCheck(fallbackOrigin);
    assert.ok(freshCheckDuringOutage.startVersion > delayedCheckBeforeOutage.startVersion);

    // Fresh write during outage succeeds in Mongo cache
    await setCachedOrigin(fallbackOrigin, true, freshCheckDuringOutage);
    assert.equal(await getCachedOrigin(fallbackOrigin), true, "Fresh write during outage must succeed in Mongo cache");

    // 6. Redis recovers
    mockRedis.simulateRecovery();
    // getCachedOrigin triggers recovery flush
    const cachedAfterRecovery = await getCachedOrigin(fallbackOrigin);

    // 7. Delayed write with pre-recovery version must NOT pollute recovered Redis
    await setCachedOrigin(fallbackOrigin, true, delayedCheckBeforeOutage);
    assert.equal(mockRedis.has(`swyra:origin:${fallbackOrigin}`), false, "Old pre-outage write must NOT pollute recovered Redis");

    // 8. Normal fresh check after recovery writes and caches in Redis
    const checkAfterRecovery = await startOriginCheck(fallbackOrigin);
    await setCachedOrigin(fallbackOrigin, true, checkAfterRecovery);
    assert.equal(mockRedis.has(`swyra:origin:${fallbackOrigin}`), true, "Normal write after recovery must populate Redis");
    assert.equal(await getCachedOrigin(fallbackOrigin), true, "Lookup after recovery returns true");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await markSharedRedisOutage(db, false);
    setRedisOutageDetectedForTesting(false);
  }
});

await runTest("CORS-17: Shared origin used by multiple clients preserved when one is disabled", async () => {
  const sharedOrigin = "https://multi-client-shared.example.com";
  const client1Id = "c1_" + crypto.randomBytes(4).toString("hex");
  const client2Id = "c2_" + crypto.randomBytes(4).toString("hex");

  // Create Client 1 with shared origin
  await db.collection("oauthClient").insertOne({
    clientId: client1Id,
    name: "Client 1",
    allowedOrigins: [sharedOrigin],
    redirectUris: ["https://client1.example.com/callback"],
    disabled: false,
    createdAt: new Date(),
  });

  // Create Client 2 with same shared origin
  await db.collection("oauthClient").insertOne({
    clientId: client2Id,
    name: "Client 2",
    allowedOrigins: [sharedOrigin],
    redirectUris: ["https://client2.example.com/callback"],
    disabled: false,
    createdAt: new Date(),
  });

  // Clear cache and verify allowed
  await invalidateOrigins([sharedOrigin]);
  assert.equal(await isOriginAllowed(sharedOrigin), true, "Shared origin initially allowed by both clients");

  const check1 = await startOriginCheck(sharedOrigin);
  await setCachedOrigin(sharedOrigin, true, check1);
  assert.equal(await getCachedOrigin(sharedOrigin), true, "Shared origin cached as allowed");

  // Disable Client 1 and invalidate
  await db.collection("oauthClient").updateOne({ clientId: client1Id }, { $set: { disabled: true } });
  await invalidateOrigins([sharedOrigin]);

  // Origin MUST STILL BE ALLOWED because Client 2 is active!
  assert.equal(await isOriginAllowed(sharedOrigin), true, "Shared origin remains allowed because Client 2 is active");

  // Fresh check caches true
  const check2 = await startOriginCheck(sharedOrigin);
  await setCachedOrigin(sharedOrigin, true, check2);
  assert.equal(await getCachedOrigin(sharedOrigin), true, "Shared origin re-cached as allowed");

  // Disable Client 2 and invalidate
  await db.collection("oauthClient").updateOne({ clientId: client2Id }, { $set: { disabled: true } });
  await invalidateOrigins([sharedOrigin]);

  // Now origin must be disallowed
  assert.equal(await isOriginAllowed(sharedOrigin), false, "Shared origin disallowed when all clients are disabled");

  // Negative cache check
  const check3 = await startOriginCheck(sharedOrigin);
  await setCachedOrigin(sharedOrigin, false, check3);
  assert.equal(await getCachedOrigin(sharedOrigin), false, "Negative cache entry preserved");

  // Cleanup
  await db.collection("oauthClient").deleteMany({ clientId: { $in: [client1Id, client2Id] } });
  await invalidateOrigins([sharedOrigin]);
});

// =============================================================================
// TEST 18: Old lookup -> invalidation -> fresh write -> delayed old write
// Proves an older lookup cannot overwrite a newer cache decision even after
// a fresh write has completed.
// =============================================================================
await runTest("CORS-18: Old lookup -> invalidation -> fresh write -> delayed old write", async () => {
  const origin = "https://cors18-ordering.example.com";
  await invalidateOrigins([origin]);

  // 1. Old lookup begins at sequence v1
  const check1 = await startOriginCheck(origin);
  const v1 = check1.startVersion;
  assert.ok(v1 > 0);

  // 2. Client is modified / invalidated at sequence v2
  await invalidateOrigins([origin]);
  assert.equal(await getCachedOrigin(origin), null, "Invalidated origin is cache miss");

  // 3. Fresh lookup begins at sequence v3
  const check2 = await startOriginCheck(origin);
  const v3 = check2.startVersion;
  assert.ok(v3 > v1);

  // Fresh lookup determines origin is disallowed and caches 'false'
  await setCachedOrigin(origin, false, check2);
  assert.equal(await getCachedOrigin(origin), false, "Fresh write caches decision false");

  // 4. Delayed old write from lookup 1 arrives now with stale allowed=true and version v1
  await setCachedOrigin(origin, true, check1);

  // 5. Verification: Cache MUST NOT be overwritten with true!
  assert.equal(await getCachedOrigin(origin), false, "Delayed old write must NOT overwrite newer fresh decision");

  // Verify MongoDB document state directly
  const doc = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
  assert.ok(doc, "Origin document must exist");
  assert.equal(doc.allowed, false, "Origin document must remain allowed: false");
  assert.equal(doc.cachedVersion, v3, "Origin document cachedVersion must reflect fresh write v3");

  // Verify direct putOriginCache with v1 is explicitly rejected
  const putResult = await putOriginCache(origin, true, v1);
  assert.equal(putResult, false, "putOriginCache must reject write with version < cachedVersion");

  // Cleanup
  await invalidateOrigins([origin]);
});

// =============================================================================
// TEST 19: Old lookup -> global invalidation interleaved with cache write
// Proves global invalidation tombstone prevents in-flight reads from repopulating
// stale data, and interleaved writes are rejected/invalidated.
// =============================================================================
await runTest("CORS-19: Old lookup -> global invalidation interleaved with cache write", async () => {
  const origin = "https://cors19-global-interleave.example.com";

  // 1. Old lookup begins before global invalidation
  const check1 = await startOriginCheck(origin);
  const v1 = check1.startVersion;

  // 2. Global invalidation occurs (e.g. system-wide client re-sync / flush)
  await clearOriginCache();

  // 3. Delayed write arrives with check1 context (v1)
  await setCachedOrigin(origin, true, check1);

  // 4. Verification: origin must be a cache miss (null), not true
  assert.equal(await getCachedOrigin(origin), null, "Lookup after global invalidation must return null");

  // 5. Direct test: putOriginCache with v1 must be rejected by global tombstone
  const putResult = await putOriginCache(origin, true, v1);
  assert.equal(putResult, false, "putOriginCache must return false when version <= global tombstone");

  // 6. Test interleaved race: even if a stale document was inserted with v1,
  // getOriginCache verifies against global tombstone and returns null
  await db.collection("origin_cache").insertOne({
    _id: `ORIGIN#${origin}` as any,
    allowed: true,
    cachedAt: new Date(),
    cachedVersion: v1,
  });
  assert.equal(await getCachedOrigin(origin), null, "getOriginCache must return null because cachedVersion <= global tombstone");

  // Cleanup
  await invalidateOrigins([origin]);
});

// =============================================================================
// TEST 20: Two processes performing concurrent lookups and client changes
// Stress test verifying that concurrent multi-process lookups, client mutations,
// and delayed writes never produce a stale cache state.
// =============================================================================
await runTest("CORS-20: Two processes performing lookups and client changes concurrently", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const workerPath = path.resolve(__dirname, "../fixtures/cors-multi-process-worker.ts");
  const child = fork(workerPath, [], {
    execPath: process.execPath,
    execArgv: process.execArgv,
    env: {
      ...process.env,
      MONGO_URI: mongoUri,
      NODE_ENV: "test",
    },
    stdio: ["ignore", "inherit", "inherit", "ipc"],
  });

  const sendToChild = (msg: any): Promise<any> => {
    return new Promise((resolve, reject) => {
      const handler = (res: any) => {
        if (res.type === "ERROR") {
          child.off("message", handler);
          reject(new Error(res.error));
        } else {
          child.off("message", handler);
          resolve(res);
        }
      };
      child.on("message", handler);
      child.send(msg);
    });
  };

  try {
    await sendToChild({
      type: "INIT",
      redisUrl: mockRedis.url,
      redisToken: mockRedis.token,
    });

    const testOrigin = "https://two-process-concurrent.example.com";

    // 1. Worker initiates lookup at v1 (reading active state)
    const check1 = await sendToChild({ type: "START_CHECK", origin: testOrigin });
    assert.equal(check1.type, "CHECK_STARTED");

    // 2. Parent performs client mutation and invalidation
    await invalidateOrigins([testOrigin]);

    // 3. Parent performs fresh lookup at v2 and caches allowed=false
    const check2 = await startOriginCheck(testOrigin);
    await setCachedOrigin(testOrigin, false, check2);
    assert.equal(await getCachedOrigin(testOrigin), false);

    // 4. Worker finishes its delayed old write with v1 (trying to set allowed=true)
    const writeRes = await sendToChild({
      type: "COMPLETE_WRITE",
      origin: testOrigin,
      allowed: true,
      startTime: check1.startTime,
    });
    assert.equal(writeRes.type, "WRITE_COMPLETED");

    // 5. Parent verifies cache: must still be false, never overwritten by worker's stale write
    assert.equal(await getCachedOrigin(testOrigin), false, "Parent cache must preserve false decision");

    // 6. Worker verifies cache: must also see false (or null), never stale true
    const workerCacheRes = await sendToChild({ type: "CHECK_CACHE", origin: testOrigin });
    assert.notEqual(workerCacheRes.value, true, "Worker cache must not return stale true");
  } finally {
    try {
      child.send({ type: "EXIT" });
      await new Promise<void>((r) => {
        const timer = setTimeout(() => { child.kill(); r(); }, 1000);
        child.on("exit", () => { clearTimeout(timer); r(); });
      });
    } catch {}
    setRedisClientForTesting(null);
    await mockRedis.close();
  }
});

// =============================================================================
// TEST 21: Out of order per origin invalidations: delayed older v1 cannot reduce marker after v2
// Deterministic test proving:
// 1. A lookup starts between invalidation versions v1 and v2.
// 2. Invalidation v2 completes before delayed invalidation v1.
// 3. The older v1 operation cannot reduce the marker in Redis or MongoDB.
// 4. The delayed lookup cannot restore stale data.
// =============================================================================
await runTest("CORS-21: Out of order per origin invalidations: delayed older v1 cannot reduce marker after v2", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://out-of-order-origin.example.com";

  try {
    // 1. Invalidation v1 sequence is acquired (e.g. from an in-flight operation that gets delayed)
    const v1 = await getNextAuthoritativeVersion();
    assert.ok(v1 > 0);

    // 2. An in flight lookup begins between v1 and v2, getting v_lookup
    const lookupCheck = await startOriginCheck(origin);
    const vLookup = lookupCheck.startVersion;
    assert.ok(vLookup > v1, "Lookup sequence must be strictly greater than v1");

    // 3. Invalidation v2 starts and completes first
    const v2 = await getNextAuthoritativeVersion();
    assert.ok(v2 > vLookup, "v2 sequence must be strictly greater than lookup sequence");

    // Execute invalidation v2 across Redis and MongoDB
    await invalidateCachedOriginRedis([origin], v2);
    await invalidateOriginCache([origin], v2);

    // Verify initial marker state at v2
    const redisInvV2 = Number(mockRedis.get(`swyra:origin:inv:${origin}`));
    assert.equal(redisInvV2, v2, "Redis invalidation marker must initially be set to v2");

    const mongoDocV2 = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
    assert.equal(mongoDocV2?.invalidatedVersion, v2, "MongoDB invalidation version must be v2");

    // 4. Delayed invalidation v1 arrives late and attempts to run
    await invalidateCachedOriginRedis([origin], v1);
    await invalidateOriginCache([origin], v1);

    // 5. Verification: Older v1 operation CANNOT reduce the marker in Redis or MongoDB
    const redisInvAfterV1 = Number(mockRedis.get(`swyra:origin:inv:${origin}`));
    assert.equal(redisInvAfterV1, v2, "Older invalidation v1 must NOT reduce Redis marker; must remain v2");

    const mongoDocAfterV1 = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
    assert.equal(mongoDocAfterV1?.invalidatedVersion, v2, "Older invalidation v1 must NOT reduce MongoDB marker; must remain v2");

    // 6. Verification: Delayed in flight lookup (vLookup < v2) attempts to write stale data
    await setCachedOrigin(origin, true, lookupCheck);

    // Write must be rejected across both layers
    assert.equal(await getCachedOrigin(origin), null, "Delayed lookup must be rejected as cache miss, never allowed");
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Stale origin key must not exist in Redis");

    const finalMongoDoc = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
    assert.notEqual(finalMongoDoc?.allowed, true, "Delayed write must not set allowed: true in MongoDB");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 22: Out of order global invalidations: delayed older v1 cannot reduce global marker
// Deterministic test proving:
// 1. A lookup starts between global invalidation versions v1 and v2.
// 2. Global invalidation v2 completes before delayed global invalidation v1.
// 3. The older v1 operation cannot reduce the global marker in Redis or MongoDB.
// 4. The delayed lookup cannot restore stale data.
// =============================================================================
await runTest("CORS-22: Out of order global invalidations: delayed older v1 cannot reduce global marker", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://out-of-order-global.example.com";

  try {
    // 1. Global invalidation v1 sequence is acquired
    const v1 = await getNextAuthoritativeVersion();
    assert.ok(v1 > 0);

    // 2. An in flight lookup begins between v1 and v2
    const lookupCheck = await startOriginCheck(origin);
    const vLookup = lookupCheck.startVersion;
    assert.ok(vLookup > v1, "Lookup sequence must be strictly greater than v1");

    // 3. Global invalidation v2 starts and completes first
    const v2 = await getNextAuthoritativeVersion();
    assert.ok(v2 > vLookup, "v2 sequence must be strictly greater than lookup sequence");

    await invalidateCachedOriginRedis(undefined, v2);
    await invalidateOriginCache(undefined, v2);

    const redisGlobalV2 = Number(mockRedis.get("swyra:inv:global"));
    assert.equal(redisGlobalV2, v2, "Redis global marker must initially be set to v2");

    const mongoGlobalV2 = await db.collection("origin_cache").findOne({ _id: "ORIGIN#__GLOBAL_TOMBSTONE__" });
    assert.equal(mongoGlobalV2?.invalidatedVersion, v2, "MongoDB global tombstone must be v2");

    // 4. Delayed global invalidation v1 arrives late
    await invalidateCachedOriginRedis(undefined, v1);
    await invalidateOriginCache(undefined, v1);

    // 5. Verification: Older v1 operation CANNOT reduce the global marker
    const redisGlobalAfterV1 = Number(mockRedis.get("swyra:inv:global"));
    assert.equal(redisGlobalAfterV1, v2, "Older global invalidation v1 must NOT reduce Redis marker; must remain v2");

    const mongoGlobalAfterV1 = await db.collection("origin_cache").findOne({ _id: "ORIGIN#__GLOBAL_TOMBSTONE__" });
    assert.equal(mongoGlobalAfterV1?.invalidatedVersion, v2, "Older global invalidation v1 must NOT reduce MongoDB tombstone; must remain v2");

    // 6. Verification: Delayed in flight lookup attempts to write stale data
    await setCachedOrigin(origin, true, lookupCheck);

    assert.equal(await getCachedOrigin(origin), null, "Delayed lookup must be rejected by global marker");
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Stale origin key must not exist in Redis");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await clearOriginCache();
  }
});

// =============================================================================
// TEST 23: Marker expiry, Redis outage, recovery, and valid fresh lookup
// Verifies:
// 1. Invalidation sets monotonic markers.
// 2. Redis outage falls back safely to MongoDB.
// 3. Redis recovery purges stale keys and resets outage state.
// 4. Marker expiry or newer sequence allows a valid fresh lookup to populate cache.
// =============================================================================
await runTest("CORS-23: Marker expiry, Redis outage, recovery, and valid fresh lookup", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://marker-expiry-fresh.example.com";

  try {
    // 1. Invalidation runs for origin
    await invalidateOrigins([origin]);
    assert.equal(await getCachedOrigin(origin), null, "Origin is a cache miss after invalidation");

    // 2. Outage occurs
    mockRedis.simulateOutage();

    // Outage read safely falls through to MongoDB (cache miss)
    const outageRead = await getCachedOrigin(origin);
    assert.equal(outageRead, null, "Read during Redis outage falls back safely to MongoDB");

    // Write during outage succeeds in MongoDB
    const checkDuringOutage = await startOriginCheck(origin);
    await setCachedOrigin(origin, true, checkDuringOutage);
    assert.equal(await getCachedOrigin(origin), true, "Write during outage succeeds in MongoDB cache");

    // 3. Redis recovery
    mockRedis.simulateRecovery();

    // Recovery lookup triggers recovery flush
    await getCachedOrigin(origin);
    assert.equal(getRedisOutageDetected(), false, "Redis outage flag cleared after recovery");

    // 4. Marker expiry simulation: clear Redis invalidation marker
    mockRedis.set(`swyra:origin:inv:${origin}`, null, 0);

    // 5. Valid fresh lookup with sequence strictly greater than invalidation
    const freshCheck = await startOriginCheck(origin);
    await setCachedOrigin(origin, true, freshCheck);

    assert.equal(await getCachedOrigin(origin), true, "Fresh lookup succeeds after recovery and marker expiry");
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), true, "Redis is successfully repopulated by fresh lookup");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await markSharedRedisOutage(db, false);
    setRedisOutageDetectedForTesting(false);
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 24: Shared origin used by another active client remains allowed
// Verifies that multi client shared origins remain accessible when one client
// is updated or disabled out of order.
// =============================================================================
await runTest("CORS-24: Shared origin used by another active client remains allowed across mutations", async () => {
  const sharedOrigin = "https://shared-resilient.example.com";
  const clientAId = "client_a_" + crypto.randomBytes(4).toString("hex");
  const clientBId = "client_b_" + crypto.randomBytes(4).toString("hex");

  // Create Client A and Client B with shared origin
  await db.collection("oauthClient").insertMany([
    {
      clientId: clientAId,
      name: "Client A",
      allowedOrigins: [sharedOrigin],
      redirectUris: [`${sharedOrigin}/callback-a`],
      disabled: false,
      createdAt: new Date(),
    },
    {
      clientId: clientBId,
      name: "Client B",
      allowedOrigins: [sharedOrigin],
      redirectUris: [`${sharedOrigin}/callback-b`],
      disabled: false,
      createdAt: new Date(),
    },
  ]);

  try {
    // Both active: origin is allowed
    assert.equal(await isOriginAllowed(sharedOrigin), true, "Shared origin allowed with both clients active");

    const check1 = await startOriginCheck(sharedOrigin);
    await setCachedOrigin(sharedOrigin, true, check1);
    assert.equal(await getCachedOrigin(sharedOrigin), true, "Shared origin cached as allowed");

    // Disable Client A
    await db.collection("oauthClient").updateOne({ clientId: clientAId }, { $set: { disabled: true } });
    await invalidateOrigins([sharedOrigin]);

    // Origin MUST STILL BE ALLOWED because Client B is active
    assert.equal(await isOriginAllowed(sharedOrigin), true, "Shared origin remains allowed because Client B is active");

    // Fresh write caches allowed: true
    const check2 = await startOriginCheck(sharedOrigin);
    await setCachedOrigin(sharedOrigin, true, check2);
    assert.equal(await getCachedOrigin(sharedOrigin), true, "Shared origin re-cached as allowed");

    // Disable Client B
    await db.collection("oauthClient").updateOne({ clientId: clientBId }, { $set: { disabled: true } });
    await invalidateOrigins([sharedOrigin]);

    // Now origin must be disallowed
    assert.equal(await isOriginAllowed(sharedOrigin), false, "Shared origin disallowed when all clients are disabled");

    const check3 = await startOriginCheck(sharedOrigin);
    await setCachedOrigin(sharedOrigin, false, check3);
    assert.equal(await getCachedOrigin(sharedOrigin), false, "Negative cache entry preserved");
  } finally {
    await db.collection("oauthClient").deleteMany({ clientId: { $in: [clientAId, clientBId] } });
    await invalidateOrigins([sharedOrigin]);
  }
});

// =============================================================================
// TEST 25: Per origin invalidation with marker expired or removed
// Proves that when an old lookup pauses before cache write, origin is revoked,
// and the Redis invalidation marker expires or is removed, the resumed old
// lookup CANNOT restore a stale allow to Redis or MongoDB.
// =============================================================================
await runTest("CORS-25: Per origin invalidation with expired or removed marker prevents stale allow", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://stale-per-origin-expiry.example.com";
  const clientId = "client_expiry_" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    name: "Client Expiry Test",
    allowedOrigins: [origin],
    redirectUris: [`${origin}/callback`],
    disabled: false,
    createdAt: new Date(),
  });

  try {
    // 1. Initial verification: origin is allowed
    assert.equal(await isOriginAllowed(origin), true, "Origin is initially allowed");

    // 2. Old lookup starts: captures start version when origin was active
    const oldLookupCheck = await startOriginCheck(origin);
    assert.ok(oldLookupCheck.startVersion > 0, "Lookup check has valid sequence version");

    // Old lookup pauses here before setCachedOrigin!

    // 3. Client is disabled and origin is invalidated
    await db.collection("oauthClient").updateOne({ clientId }, { $set: { disabled: true } });
    await invalidateOrigins([origin]);

    // Verify invalidation marker exists in Redis
    assert.equal(mockRedis.has(`swyra:origin:inv:${origin}`), true, "Redis invalidation marker was written");

    // 4. Expire or remove the relevant marker from Redis
    mockRedis.delete(`swyra:origin:inv:${origin}`);
    assert.equal(mockRedis.has(`swyra:origin:inv:${origin}`), false, "Redis invalidation marker is removed or expired");

    // 5. Old lookup resumes and attempts to cache allowed=true with its old sequence version
    await setCachedOrigin(origin, true, oldLookupCheck);

    // 6. Assertions: stale allow MUST NOT be restored
    const cachedResult = await getCachedOrigin(origin);
    assert.notEqual(cachedResult, true, "Old lookup must not restore stale true in cache");

    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis must not hold stale allow key");

    const mongoDoc = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
    assert.notEqual(mongoDoc?.allowed, true, "MongoDB cache must not store allowed=true from old lookup");

    // 7. Authoritative isOriginAllowed check proves origin is rejected
    assert.equal(await isOriginAllowed(origin), false, "Origin is correctly disallowed");

    // 8. Fresh check stores allowed=false cleanly
    const freshCheck = await startOriginCheck(origin);
    await setCachedOrigin(origin, false, freshCheck);
    assert.equal(await getCachedOrigin(origin), false, "Fresh lookup caches negative result");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await db.collection("oauthClient").deleteOne({ clientId });
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 26: Global invalidation with global marker expired or removed
// Proves that when an old lookup pauses before cache write, global invalidation
// runs, and the Redis global marker expires or is removed, the resumed old
// lookup CANNOT restore a stale allow.
// =============================================================================
await runTest("CORS-26: Global invalidation with expired or removed marker prevents stale allow", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://stale-global-expiry.example.com";
  const clientId = "client_global_" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    name: "Client Global Expiry Test",
    allowedOrigins: [origin],
    redirectUris: [`${origin}/callback`],
    disabled: false,
    createdAt: new Date(),
  });

  try {
    assert.equal(await isOriginAllowed(origin), true, "Origin is initially allowed");

    // 1. Old lookup starts: captures start version
    const oldLookupCheck = await startOriginCheck(origin);

    // 2. Revoke client and run global invalidation
    await db.collection("oauthClient").updateOne({ clientId }, { $set: { disabled: true } });
    await invalidateOrigins();

    // Verify global marker was written
    assert.equal(mockRedis.has("swyra:inv:global"), true, "Redis global marker was written");

    // 3. Expire or remove the global marker from Redis
    mockRedis.delete("swyra:inv:global");
    assert.equal(mockRedis.has("swyra:inv:global"), false, "Redis global marker is removed or expired");

    // 4. Old lookup resumes and attempts to cache allowed=true
    await setCachedOrigin(origin, true, oldLookupCheck);

    // 5. Assertions: stale allow MUST NOT be restored
    const cachedResult = await getCachedOrigin(origin);
    assert.notEqual(cachedResult, true, "Old lookup must not restore stale true after global invalidation");

    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis must not hold stale allow key after global invalidation");

    const mongoDoc = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
    assert.notEqual(mongoDoc?.allowed, true, "MongoDB cache must not store allowed=true");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await db.collection("oauthClient").deleteOne({ clientId });
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 27: Concurrent writers with expired or removed markers
// Proves that multiple paused lookups attempting to write after client revocation
// and marker removal cannot populate the cache with stale data.
// =============================================================================
await runTest("CORS-27: Concurrent writers with expired or removed markers rejected", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://stale-concurrent-writers.example.com";
  const clientId = "client_concurrent_" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    name: "Client Concurrent Writers Test",
    allowedOrigins: [origin],
    redirectUris: [`${origin}/callback`],
    disabled: false,
    createdAt: new Date(),
  });

  try {
    // 1. Two separate lookups start before mutation
    const checkWorker1 = await startOriginCheck(origin);
    const checkWorker2 = await startOriginCheck(origin);

    // 2. Client is revoked and invalidation runs
    await db.collection("oauthClient").updateOne({ clientId }, { $set: { disabled: true } });
    await invalidateOrigins([origin]);

    // 3. Expire or remove the invalidation marker from Redis
    mockRedis.delete(`swyra:origin:inv:${origin}`);

    // 4. Both paused workers resume concurrently and attempt to write stale allowed=true
    await Promise.all([
      setCachedOrigin(origin, true, checkWorker1),
      setCachedOrigin(origin, true, checkWorker2),
    ]);

    // 5. Verification: neither worker restored stale true
    assert.notEqual(await getCachedOrigin(origin), true, "Neither concurrent worker can restore stale allow");
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis does not hold stale key");

    const mongoDoc = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
    assert.notEqual(mongoDoc?.allowed, true, "MongoDB does not hold stale allow");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await db.collection("oauthClient").deleteOne({ clientId });
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 28: Out of order invalidations with expired or removed markers
// Proves that out of order invalidation sequences followed by marker removal
// still protect against delayed stale lookups.
// =============================================================================
await runTest("CORS-28: Out of order invalidations with expired or removed markers prevent stale allow", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://stale-out-of-order.example.com";

  try {
    // 1. Old lookup starts at v0
    const lookupCheck = await startOriginCheck(origin);

    // 2. Invalidation v1 and v2 sequence
    const v1 = await getNextAuthoritativeVersion();
    const v2 = await getNextAuthoritativeVersion();
    assert.ok(v2 > v1 && v1 > lookupCheck.startVersion);

    // Invalidation v2 completes first
    await invalidateCachedOriginRedis([origin], v2);
    await invalidateOriginCache([origin], v2);

    // Delayed invalidation v1 arrives out of order
    await invalidateCachedOriginRedis([origin], v1);
    await invalidateOriginCache([origin], v1);

    // 3. Remove the marker from Redis
    mockRedis.delete(`swyra:origin:inv:${origin}`);

    // 4. Old lookup from v0 resumes and tries to write allowed=true
    await setCachedOrigin(origin, true, lookupCheck);

    // 5. Verification: stale write rejected
    assert.notEqual(await getCachedOrigin(origin), true, "Old lookup cannot write after out of order invalidations");
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis does not hold stale key");

    const mongoDoc = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
    assert.notEqual(mongoDoc?.allowed, true, "MongoDB does not hold stale allow");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 29: Multi process stale write prevention with expired or removed marker
// Proves that when a separate worker process initiates a lookup, client is revoked,
// and Redis marker is removed, the child process write CANNOT restore a stale allow.
// =============================================================================
await runTest("CORS-29: Multi process stale write prevention with expired or removed marker", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const workerPath = path.resolve(__dirname, "../fixtures/cors-multi-process-worker.ts");
  const child = fork(workerPath, [], {
    execPath: process.execPath,
    execArgv: process.execArgv,
    env: {
      ...process.env,
      MONGO_URI: mongoUri,
      NODE_ENV: "test",
    },
    stdio: ["ignore", "inherit", "inherit", "ipc"],
  });

  const sendToChild = (msg: any): Promise<any> => {
    return new Promise((resolve, reject) => {
      const handler = (res: any) => {
        if (res.type === "ERROR") {
          child.off("message", handler);
          reject(new Error(res.error));
        } else {
          child.off("message", handler);
          resolve(res);
        }
      };
      child.on("message", handler);
      child.send(msg);
    });
  };

  const origin = "https://cross-process-stale-expiry.example.com";
  const clientId = "client_proc_expiry_" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    name: "Client Process Expiry Test",
    allowedOrigins: [origin],
    redirectUris: [`${origin}/callback`],
    disabled: false,
    createdAt: new Date(),
  });

  try {
    await sendToChild({
      type: "INIT",
      redisUrl: mockRedis.url,
      redisToken: mockRedis.token,
    });

    // 1. Worker process initiates lookup reading active client state
    const check1 = await sendToChild({ type: "START_CHECK", origin });
    assert.equal(check1.type, "CHECK_STARTED");

    // 2. Parent disables client and performs invalidation
    await db.collection("oauthClient").updateOne({ clientId }, { $set: { disabled: true } });
    await invalidateOrigins([origin]);

    // 3. Parent explicitly clears the Redis invalidation marker
    mockRedis.delete(`swyra:origin:inv:${origin}`);
    assert.equal(mockRedis.has(`swyra:origin:inv:${origin}`), false, "Redis marker cleared");

    // 4. Worker process resumes and executes delayed old write with startVersion
    const writeRes = await sendToChild({
      type: "COMPLETE_WRITE",
      origin,
      allowed: true,
      startTime: check1.startTime,
    });
    assert.equal(writeRes.type, "WRITE_COMPLETED");

    // 5. Parent verifies cache: must NOT be true
    const parentCache = await getCachedOrigin(origin);
    assert.notEqual(parentCache, true, "Parent cache must not return stale true");
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis must not hold stale key");

    // 6. Worker verifies cache: must NOT be true
    const workerCacheRes = await sendToChild({ type: "CHECK_CACHE", origin });
    assert.notEqual(workerCacheRes.value, true, "Worker cache must not return stale true");
  } finally {
    try {
      child.send({ type: "EXIT" });
      await new Promise<void>((r) => {
        const timer = setTimeout(() => { child.kill(); r(); }, 1000);
        child.on("exit", () => { clearTimeout(timer); r(); });
      });
    } catch {}
    setRedisClientForTesting(null);
    await mockRedis.close();
    await db.collection("oauthClient").deleteOne({ clientId });
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 30: Per-origin invalidation: durable tombstone prevents stale allow
// after fresh write, TTL eviction, and Redis marker loss
// =============================================================================
await runTest("CORS-30: Per origin durable tombstone blocks stale write after fresh write, TTL eviction, and marker loss", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://durable-tombstone-ttl.example.com";
  const clientId = "client_ttl_tombstone_" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    name: "Client TTL Tombstone Test",
    allowedOrigins: [origin],
    redirectUris: [`${origin}/callback`],
    disabled: false,
    createdAt: new Date(),
  });

  try {
    // 1. Initial lookup starts at v0 while origin is allowed
    const lookupCheck = await startOriginCheck(origin);
    assert.ok(lookupCheck.startVersion > 0, "Lookup has valid sequence version");

    // 2. Old lookup pauses here!

    // 3. Client is disabled and origin is invalidated at v1
    await db.collection("oauthClient").updateOne({ clientId }, { $set: { disabled: true } });
    await invalidateOrigins([origin]);

    // Verify durable tombstone was recorded in MongoDB
    const tombstoneDoc = await db.collection("origin_cache").findOne({ _id: `ORIGIN_INV#${origin}` });
    assert.ok(tombstoneDoc, "Durable origin tombstone exists in MongoDB");
    assert.ok(
      typeof tombstoneDoc.invalidatedVersion === "number" && tombstoneDoc.invalidatedVersion >= lookupCheck.startVersion,
      "Durable tombstone records higher invalidation version",
    );
    assert.equal(tombstoneDoc.cachedAt, undefined, "Durable tombstone has no cachedAt field");

    // 4. A fresh cache decision is written at v2 (e.g. temporary re-enabling or shared client write)
    const freshVersion = await getNextAuthoritativeVersion();
    const freshAccepted = await putOriginCache(origin, true, freshVersion);
    assert.equal(freshAccepted, true, "Fresh write with higher version accepted");

    const freshDoc = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
    assert.ok(freshDoc?.cachedAt, "Fresh cache decision has cachedAt for TTL");

    // 5. MongoDB TTL mechanism removes the expiring cache entry
    await db.collection("origin_cache").deleteOne({ _id: `ORIGIN#${origin}` });
    assert.equal(await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` }), null, "Cache doc deleted by TTL");

    // 6. Redis loses its invalidation marker (e.g. restart or eviction)
    mockRedis.delete(`swyra:origin:inv:${origin}`);
    assert.equal(mockRedis.has(`swyra:origin:inv:${origin}`), false, "Redis marker removed");

    // 7. Old lookup resumes and attempts to write with startVersion
    await setCachedOrigin(origin, true, lookupCheck);

    // 8. Verification: stale write strictly rejected
    assert.notEqual(await getCachedOrigin(origin), true, "Old lookup cannot write stale allow after TTL eviction");
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis does not hold stale key");

    const mongoDocAfter = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
    assert.notEqual(mongoDocAfter?.allowed, true, "MongoDB does not hold stale allow");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await db.collection("oauthClient").deleteOne({ clientId });
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 31: Global invalidation: durable global tombstone blocks stale write
// after fresh write, TTL eviction, and Redis global marker loss
// =============================================================================
await runTest("CORS-31: Global durable tombstone blocks stale write after fresh write, TTL eviction, and marker loss", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://global-durable-ttl.example.com";

  try {
    // 1. Old lookup starts at v0
    const lookupCheck = await startOriginCheck(origin);

    // 2. Global invalidation occurs at v1
    await clearOriginCache();

    // Verify global tombstone in MongoDB has no cachedAt
    const globalTombstone = await db.collection("origin_cache").findOne({ _id: "ORIGIN#__GLOBAL_TOMBSTONE__" });
    assert.ok(globalTombstone, "Global tombstone exists");
    assert.equal(globalTombstone.cachedAt, undefined, "Global tombstone has no cachedAt");

    // 3. Fresh cache decision written at v2
    const freshVersion = await getNextAuthoritativeVersion();
    await putOriginCache(origin, true, freshVersion);

    // 4. MongoDB TTL removes expiring cache entry
    await db.collection("origin_cache").deleteOne({ _id: `ORIGIN#${origin}` });

    // 5. Redis loses global invalidation marker
    mockRedis.delete("swyra:inv:global");
    assert.equal(mockRedis.has("swyra:inv:global"), false, "Redis global marker removed");

    // 6. Old lookup resumes and attempts to write
    await setCachedOrigin(origin, true, lookupCheck);

    // 7. Verification: stale write rejected
    assert.notEqual(await getCachedOrigin(origin), true, "Old lookup cannot write stale allow after global TTL eviction");
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis does not hold stale key");

    const mongoDocAfter = await db.collection("origin_cache").findOne({ _id: `ORIGIN#${origin}` });
    assert.notEqual(mongoDocAfter?.allowed, true, "MongoDB does not hold stale allow");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 32: Pause after MongoDB acceptance before Redis write: per-origin
// invalidation and Redis marker loss
// =============================================================================
await runTest("CORS-32: Pause between MongoDB acceptance and Redis write rejected on per-origin invalidation", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://pause-mongo-redis-origin.example.com";
  const clientId = "client_pause_origin_" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    name: "Client Pause Origin Test",
    allowedOrigins: [origin],
    redirectUris: [`${origin}/callback`],
    disabled: false,
    createdAt: new Date(),
  });

  try {
    // 1. Old lookup starts at v0
    const lookupCheck = await startOriginCheck(origin);

    // 2. Set hook to simulate pause right after MongoDB accepts, but before Redis write
    let hookFired = false;
    setPreRedisWriteHookForTesting(async (hookOrigin) => {
      if (hookOrigin === origin) {
        hookFired = true;
        // While paused between MongoDB acceptance and Redis write:
        // Invalidation occurs! Client is disabled.
        await db.collection("oauthClient").updateOne({ clientId }, { $set: { disabled: true } });
        await invalidateOrigins([origin]);

        // Redis loses its invalidation marker (simulating eviction or restart)
        mockRedis.delete(`swyra:origin:inv:${origin}`);
      }
    });

    // 3. Old lookup executes setCachedOrigin
    await setCachedOrigin(origin, true, lookupCheck);
    assert.equal(hookFired, true, "Pre-Redis write hook fired");

    // 4. Verification: Pre-Redis Write Guard aborted write to Redis
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis does not hold stale key");
    assert.notEqual(await getCachedOrigin(origin), true, "Cache does not return stale allow");
  } finally {
    setPreRedisWriteHookForTesting(null);
    setRedisClientForTesting(null);
    await mockRedis.close();
    await db.collection("oauthClient").deleteOne({ clientId });
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 33: Pause after MongoDB acceptance before Redis write: global invalidation
// and Redis marker loss
// =============================================================================
await runTest("CORS-33: Pause between MongoDB acceptance and Redis write rejected on global invalidation", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://pause-mongo-redis-global.example.com";

  try {
    // 1. Old lookup starts at v0
    const lookupCheck = await startOriginCheck(origin);

    // 2. Set hook to simulate pause right after MongoDB accepts, but before Redis write
    let hookFired = false;
    setPreRedisWriteHookForTesting(async (hookOrigin) => {
      if (hookOrigin === origin) {
        hookFired = true;
        // Global invalidation occurs while paused
        await clearOriginCache();

        // Redis loses global marker
        mockRedis.delete("swyra:inv:global");
      }
    });

    // 3. Old lookup executes setCachedOrigin
    await setCachedOrigin(origin, true, lookupCheck);
    assert.equal(hookFired, true, "Pre-Redis write hook fired");

    // 4. Verification: Pre-Redis Write Guard aborted write to Redis
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis does not hold stale key");
    assert.notEqual(await getCachedOrigin(origin), true, "Cache does not return stale allow");
  } finally {
    setPreRedisWriteHookForTesting(null);
    setRedisClientForTesting(null);
    await mockRedis.close();
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 34: Multi-process stale write prevention with TTL removal and marker loss
// =============================================================================
await runTest("CORS-34: Multi process stale write prevention with TTL removal and marker loss", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const workerPath = path.resolve(__dirname, "../fixtures/cors-multi-process-worker.ts");
  const child = fork(workerPath, [], {
    execPath: process.execPath,
    execArgv: process.execArgv,
    env: {
      ...process.env,
      MONGO_URI: mongoUri,
      NODE_ENV: "test",
    },
    stdio: ["ignore", "inherit", "inherit", "ipc"],
  });

  const sendToChild = (msg: any): Promise<any> => {
    return new Promise((resolve, reject) => {
      const handler = (res: any) => {
        if (res.type === "ERROR") {
          child.off("message", handler);
          reject(new Error(res.error));
        } else {
          child.off("message", handler);
          resolve(res);
        }
      };
      child.on("message", handler);
      child.send(msg);
    });
  };

  const origin = "https://multi-proc-ttl-marker-loss.example.com";
  const clientId = "client_proc_ttl_" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    name: "Client Process TTL Test",
    allowedOrigins: [origin],
    redirectUris: [`${origin}/callback`],
    disabled: false,
    createdAt: new Date(),
  });

  try {
    await sendToChild({
      type: "INIT",
      redisUrl: mockRedis.url,
      redisToken: mockRedis.token,
    });

    // 1. Worker process initiates lookup reading active client state
    const check1 = await sendToChild({ type: "START_CHECK", origin });
    assert.equal(check1.type, "CHECK_STARTED");

    // 2. Parent disables client and performs invalidation
    await db.collection("oauthClient").updateOne({ clientId }, { $set: { disabled: true } });
    await invalidateOrigins([origin]);

    // 3. Parent writes a fresh decision at higher version with cachedAt
    const freshVersion = await getNextAuthoritativeVersion();
    await putOriginCache(origin, true, freshVersion);

    // 4. Parent simulates MongoDB TTL removal of expiring document
    await db.collection("origin_cache").deleteOne({ _id: `ORIGIN#${origin}` });

    // 5. Parent explicitly clears the Redis invalidation marker
    mockRedis.delete(`swyra:origin:inv:${origin}`);
    assert.equal(mockRedis.has(`swyra:origin:inv:${origin}`), false, "Redis marker cleared");

    // 6. Worker process resumes and executes delayed old write with startVersion
    const writeRes = await sendToChild({
      type: "COMPLETE_WRITE",
      origin,
      allowed: true,
      startTime: check1.startTime,
    });
    assert.equal(writeRes.type, "WRITE_COMPLETED");

    // 7. Parent verifies cache: must NOT be true
    const parentCache = await getCachedOrigin(origin);
    assert.notEqual(parentCache, true, "Parent cache must not return stale true");
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis must not hold stale key");

    // 8. Worker verifies cache: must NOT be true
    const workerCacheRes = await sendToChild({ type: "CHECK_CACHE", origin });
    assert.notEqual(workerCacheRes.value, true, "Worker cache must not return stale true");
  } finally {
    try {
      child.send({ type: "EXIT" });
      await new Promise<void>((r) => {
        const timer = setTimeout(() => { child.kill(); r(); }, 1000);
        child.on("exit", () => { clearTimeout(timer); r(); });
      });
    } catch {}
    setRedisClientForTesting(null);
    await mockRedis.close();
    await db.collection("oauthClient").deleteOne({ clientId });
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 35: Pause after final MongoDB check before Redis write: per-origin
// invalidation followed by Redis marker loss
// =============================================================================
await runTest("CORS-35: Pause after final MongoDB check, per-origin invalidation, and marker loss strictly blocks stale write", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://pause-postcheck-per-origin.example.com";
  const clientId = "client_postcheck_origin_" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    name: "Client Post-Check Origin Test",
    allowedOrigins: [origin],
    redirectUris: [`${origin}/callback`],
    disabled: false,
    createdAt: new Date(),
  });

  try {
    // 1. Old lookup begins
    const lookupCheck = await startOriginCheck(origin);

    // 2. Configure hook to pause AFTER final MongoDB check passes, immediately before Redis write
    let hookFired = false;
    setPostMongoCheckHookForTesting(async (hookOrigin) => {
      if (hookOrigin === origin) {
        hookFired = true;
        // Invalidation occurs while paused
        await db.collection("oauthClient").updateOne({ clientId }, { $set: { disabled: true } });
        await invalidateOrigins([origin]);

        // Redis loses its invalidation marker (simulating marker loss, eviction, or restart)
        mockRedis.delete(`swyra:origin:inv:${origin}`);
        assert.equal(mockRedis.has(`swyra:origin:inv:${origin}`), false, "Redis marker was cleared");
      }
    });

    // 3. Old lookup resumes and attempts to write allowed = true to Redis
    await setCachedOrigin(origin, true, lookupCheck);
    assert.equal(hookFired, true, "Post-Mongo check hook fired");

    // 4. Verification: The stale write MUST be rejected
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis must not store stale allow decision");
    assert.equal(await getCachedOriginRedis(origin), null, "Redis getCachedOriginRedis must return null");
    assert.notEqual(await getCachedOrigin(origin), true, "Overall cache must not return stale true");
  } finally {
    setPostMongoCheckHookForTesting(null);
    setRedisClientForTesting(null);
    await mockRedis.close();
    await db.collection("oauthClient").deleteOne({ clientId });
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 36: Pause after final MongoDB check before Redis write: global invalidation
// followed by Redis marker loss
// =============================================================================
await runTest("CORS-36: Pause after final MongoDB check, global invalidation, and marker loss strictly blocks stale write", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://pause-postcheck-global.example.com";

  try {
    // 1. Old lookup begins
    const lookupCheck = await startOriginCheck(origin);

    // 2. Configure hook to pause AFTER final MongoDB check passes, immediately before Redis write
    let hookFired = false;
    setPostMongoCheckHookForTesting(async (hookOrigin) => {
      if (hookOrigin === origin) {
        hookFired = true;
        // Global invalidation occurs while paused
        await clearOriginCache();

        // Redis loses its global invalidation marker (simulating marker loss, eviction, or restart)
        mockRedis.delete("swyra:inv:global");
        assert.equal(mockRedis.has("swyra:inv:global"), false, "Redis global marker was cleared");
      }
    });

    // 3. Old lookup resumes and attempts to write allowed = true to Redis
    await setCachedOrigin(origin, true, lookupCheck);
    assert.equal(hookFired, true, "Post-Mongo check hook fired");

    // 4. Verification: The stale write MUST be rejected
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis must not store stale allow decision");
    assert.equal(await getCachedOriginRedis(origin), null, "Redis getCachedOriginRedis must return null");
    assert.notEqual(await getCachedOrigin(origin), true, "Overall cache must not return stale true");
  } finally {
    setPostMongoCheckHookForTesting(null);
    setRedisClientForTesting(null);
    await mockRedis.close();
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 37: Non-atomic Redis reads race prevention via atomic Lua script
// =============================================================================
await runTest("CORS-37: Atomic Redis Lua read prevents pairing old cached value with new version", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://atomic-read-race.example.com";

  try {
    // 1. Initial cached entry in Redis: allowed = true at v10
    mockRedis.set(`swyra:origin:${origin}`, "1");
    mockRedis.set(`swyra:origin:ver:${origin}`, 10);

    // Initial read confirms true
    const initial = await getCachedOriginRedis(origin);
    assert.equal(initial, true, "Initial cache hit is true");

    // 2. Demonstrate what a non-atomic multi-get would do if interleaved:
    // Reader fetches originKey ('1')
    const simulatedOldValue = mockRedis.get(`swyra:origin:${origin}`);
    assert.equal(simulatedOldValue, "1");

    // Invalidation occurs: wipes originKey, sets invKey = 20
    await invalidateCachedOriginRedis([origin], 20);

    // Fresh write occurs for different decision: allowed = false at v30
    mockRedis.set(`swyra:origin:lease:${origin}`, 30);
    await setCachedOriginRedis(origin, false, 30);

    // Under non-atomic read, reader would fetch verKey (30), see 30 > 20, and pair with old true!
    // But under atomic getCachedOriginRedis, it evaluates the exact atomic snapshot:
    const atomicRead = await getCachedOriginRedis(origin);
    assert.equal(atomicRead, false, "Atomic read returns current decision (false), never pairing old true with new version");

    // 3. Also verify that when an invalidation marker exceeds verKey, atomic read returns null:
    await invalidateCachedOriginRedis([origin], 40);
    const afterInv = await getCachedOriginRedis(origin);
    assert.equal(afterInv, null, "Atomic read returns null when invalidated, never stale data");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 38: Multi-process race: worker pauses after final MongoDB check, parent
// invalidates and flushes Redis marker, worker cannot write stale allow
// =============================================================================
await runTest("CORS-38: Multi-process race: worker pauses after MongoDB check, parent invalidates and flushes marker, worker cannot write stale allow", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const workerPath = path.resolve(__dirname, "../fixtures/cors-multi-process-worker.ts");
  const child = fork(workerPath, [], {
    execPath: process.execPath,
    execArgv: process.execArgv,
    env: {
      ...process.env,
      MONGO_URI: mongoUri,
      NODE_ENV: "test",
    },
    stdio: ["ignore", "inherit", "inherit", "ipc"],
  });

  const sendToChild = (msg: any): Promise<any> => {
    return new Promise((resolve, reject) => {
      const handler = (res: any) => {
        if (res.type === "ERROR") {
          child.off("message", handler);
          reject(new Error(res.error));
        } else {
          child.off("message", handler);
          resolve(res);
        }
      };
      child.on("message", handler);
      child.send(msg);
    });
  };

  const origin = "https://multiprocess-postcheck.example.com";
  const clientId = "client_proc_postcheck_" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    name: "Client Multi-Process Post-Check Test",
    allowedOrigins: [origin],
    redirectUris: [`${origin}/callback`],
    disabled: false,
    createdAt: new Date(),
  });

  try {
    await sendToChild({
      type: "INIT",
      redisUrl: mockRedis.url,
      redisToken: mockRedis.token,
    });

    // Configure worker to pause after the final MongoDB check passes
    await sendToChild({ type: "SET_POST_MONGO_CHECK_HOOK" });

    // Worker starts lookup check at v0
    const checkPromise = sendToChild({ type: "START_CHECK", origin });
    const check1 = await checkPromise;
    assert.equal(check1.type, "CHECK_STARTED");

    // Worker begins write, which will pause at the post-Mongo-check hook
    let workerPaused = false;
    let writeCompleted = false;

    const pausedPromise = new Promise<void>((resolve) => {
      const handler = (msg: any) => {
        if (msg?.type === "POST_MONGO_CHECK_PAUSED") {
          workerPaused = true;
          child.off("message", handler);
          resolve();
        }
      };
      child.on("message", handler);
    });

    const writePromise = new Promise<void>((resolve) => {
      const handler = (msg: any) => {
        if (msg?.type === "WRITE_COMPLETED") {
          writeCompleted = true;
          child.off("message", handler);
          resolve();
        }
      };
      child.on("message", handler);
    });

    child.send({
      type: "COMPLETE_WRITE",
      origin,
      allowed: true,
      startTime: check1.startTime,
    });

    // Wait until worker is confirmed paused after MongoDB check
    await pausedPromise;
    assert.equal(workerPaused, true, "Worker confirmed paused after MongoDB check");

    // While worker is paused:
    // 1. Parent disables client and runs invalidation
    await db.collection("oauthClient").updateOne({ clientId }, { $set: { disabled: true } });
    await invalidateOrigins([origin]);

    // 2. Redis marker is deleted (simulating marker loss / eviction / restart)
    mockRedis.delete(`swyra:origin:inv:${origin}`);
    assert.equal(mockRedis.has(`swyra:origin:inv:${origin}`), false, "Redis marker deleted");

    // Resume worker
    child.send({ type: "RESUME_POST_MONGO_CHECK" });

    // Wait for worker write to finish
    await writePromise;
    assert.equal(writeCompleted, true, "Worker completed write attempt");

    // Verification: Stale allow MUST NOT be in Redis
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis must not contain stale key from worker");
    assert.equal(await getCachedOriginRedis(origin), null, "Redis getCachedOriginRedis must return null");

    // Worker cache check also returns not allowed
    const workerCheck = await sendToChild({ type: "CHECK_CACHE", origin });
    assert.notEqual(workerCheck.value, true, "Worker cache check must not return true");
  } finally {
    try {
      child.send({ type: "EXIT" });
      await new Promise<void>((r) => {
        const timer = setTimeout(() => { child.kill(); r(); }, 1000);
        child.on("exit", () => { clearTimeout(timer); r(); });
      });
    } catch {}
    setRedisClientForTesting(null);
    await mockRedis.close();
    await db.collection("oauthClient").deleteOne({ clientId });
    await invalidateOrigins([origin]);
  }
});

// =============================================================================
// TEST 39: Outage recovery and Redis restart with lease loss strictly blocks old writes
// =============================================================================
await runTest("CORS-39: Outage recovery and Redis restart with lease loss strictly blocks delayed write", async () => {
  const mockRedis = await createMockRedisServer();
  const testRedis = new Redis({
    url: mockRedis.url,
    token: mockRedis.token,
    retry: false,
    signal: () => AbortSignal.timeout(2000),
  });
  setRedisClientForTesting(testRedis);

  const origin = "https://outage-restart-lease.example.com";

  try {
    // 1. Lookup starts, registering lease at v10
    const lookupCheck = await startOriginCheck(origin);

    // 2. Redis experiences outage and restart (clearing all volatile keys, leases, and state)
    mockRedis.simulateOutage();
    mockRedis.clear(); // Wipes all state (simulating restart)
    mockRedis.simulateRecovery();

    // 3. Invalidation occurs in MongoDB
    await invalidateOrigins([origin]);

    // 4. Delayed lookup resumes and attempts to write to Redis
    await setCachedOrigin(origin, true, lookupCheck);

    // 5. Verification: Write was rejected because lease was wiped during restart
    assert.equal(mockRedis.has(`swyra:origin:${origin}`), false, "Redis does not have origin cached after restart");
    assert.equal(await getCachedOriginRedis(origin), null, "Redis getCachedOriginRedis returns null");
  } finally {
    setRedisClientForTesting(null);
    await mockRedis.close();
    await invalidateOrigins([origin]);
  }
});

await closeDb();
await mongod.stop();

console.log("\n================================================================");
console.log(`  CORS CACHE CORRECTNESS RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================\n");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
