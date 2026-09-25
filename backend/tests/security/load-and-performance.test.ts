import dotenv from "dotenv";
dotenv.config();

import assert from "node:assert/strict";
import crypto from "crypto";
import { performance } from "perf_hooks";
import { serve } from "@hono/node-server";

// Configure test environment before any application imports
process.env.NODE_ENV = "test";
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://127.0.0.1:3848";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32";
process.env.APP_ADMIN_JWT_SECRET = process.env.APP_ADMIN_JWT_SECRET || "b".repeat(32);
process.env.TOTP_ENCRYPTION_KEY = process.env.TOTP_ENCRYPTION_KEY || "c".repeat(32);

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");

console.log("================================================================");
console.log("  SWYRA AUTH -- LOAD & PERFORMANCE BENCHMARK HARNESS");
console.log("  Measuring Throughput (RPS), Latency (p50/p95/p99) & CAS Races");
console.log("================================================================\n");

const PORT = 3848;
const server = serve({
  fetch: app.fetch,
  port: PORT,
});
const BASE_URL = `http://127.0.0.1:${PORT}`;

let ipCounter = 2000;
function getTestHeaders(extra: Record<string, string> = {}) {
  const ip = `198.51.100.${(++ipCounter % 240) + 1}`;
  return {
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    Origin: process.env.FRONTEND_URL || "http://localhost:5174",
    ...extra,
  };
}

function base64url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function generatePkce() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

interface LatencyStats {
  count: number;
  min: number;
  max: number;
  avg: number;
  p50: number;
  p95: number;
  p99: number;
  rps: number;
  totalTimeMs: number;
}

function calculateStats(latencies: number[], totalDurationMs: number): LatencyStats {
  latencies.sort((a, b) => a - b);
  const count = latencies.length;
  const min = latencies[0] || 0;
  const max = latencies[count - 1] || 0;
  const avg = latencies.reduce((a, b) => a + b, 0) / count;
  const p50 = latencies[Math.floor(count * 0.50)] || 0;
  const p95 = latencies[Math.floor(count * 0.95)] || 0;
  const p99 = latencies[Math.floor(count * 0.99)] || 0;
  const rps = (count / totalDurationMs) * 1000;

  return {
    count,
    min: Number(min.toFixed(2)),
    max: Number(max.toFixed(2)),
    avg: Number(avg.toFixed(2)),
    p50: Number(p50.toFixed(2)),
    p95: Number(p95.toFixed(2)),
    p99: Number(p99.toFixed(2)),
    rps: Number(rps.toFixed(1)),
    totalTimeMs: Number(totalDurationMs.toFixed(2)),
  };
}

// --------------------------------------------------------------------------
// DB Provisioning
// --------------------------------------------------------------------------
const db = await getDb();

const testSuffix = crypto.randomBytes(4).toString("hex");
const clientId = `perf_client_${testSuffix}`;
const clientSecret = `perf_secret_${testSuffix}_12345`;
const redirectUri = `${BASE_URL}/perf-callback`;

const secretHash = crypto.createHash("sha256").update(clientSecret).digest("base64url");
await db.collection("oauthClient").updateOne(
  { clientId },
  {
    $set: {
      clientId,
      client_id: clientId,
      clientSecret: secretHash,
      client_secret: secretHash,
      name: `Performance App ${clientId}`,
      isPublic: false,
      is_public: false,
      isDev: true,
      is_dev: true,
      redirectUris: [redirectUri],
      redirect_uris: [redirectUri],
      allowedOrigins: [BASE_URL, "http://localhost:5174"],
      skipConsent: true,
      skip_consent: true,
      applicationType: "web",
      updatedAt: new Date(),
    },
  },
  { upsert: true }
);

// Provision User
const userEmail = `perf_user_${testSuffix}@example.com`;
const userPassword = "Password@12345!";
const userSignUpRes = await authProvider.api.signUpEmail({
  body: { email: userEmail, password: userPassword, name: "Perf User" },
  asResponse: true,
});
const userCookie = (userSignUpRes.headers.get("set-cookie") || "").split(";")[0];
assert.ok(userCookie, "Session cookie must be established");

const userDoc = await db.collection("user").findOne({ email: userEmail });
assert.ok(userDoc);
const userId = userDoc._id.toString();

// Authorize user for client
await db.collection("user_app_registrations").updateOne(
  { userId, clientId },
  { $set: { userId, clientId, registeredAt: new Date() } },
  { upsert: true }
);

const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

async function fetchAuthCode(pkce: { challenge: string }) {
  const authUrl = new URL(`${BASE_URL}/api/auth/oauth2/authorize`);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "openid offline_access");
  authUrl.searchParams.set("state", `state_${crypto.randomBytes(4).toString("hex")}`);
  authUrl.searchParams.set("code_challenge", pkce.challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  const res = await fetch(authUrl.toString(), {
    method: "GET",
    headers: { cookie: userCookie, ...getTestHeaders() },
    redirect: "manual",
  });

  let urlStr = res.headers.get("location");
  if (!urlStr && res.status === 200) {
    const json = await res.json();
    urlStr = json.url;
  }
  const parsed = new URL(urlStr!);
  return parsed.searchParams.get("code")!;
}

// --------------------------------------------------------------------------
// TEST 1: AUTHORIZE ENDPOINT LOAD (50 Concurrent Requests)
// --------------------------------------------------------------------------
console.log("▶ [BENCHMARK 1] /oauth2/authorize — 50 Concurrent Requests");
{
  const CONCURRENCY = 50;
  const latencies: number[] = [];
  let errors = 0;

  const tStart = performance.now();
  await Promise.all(
    Array.from({ length: CONCURRENCY }).map(async () => {
      const pkce = generatePkce();
      const authUrl = new URL(`${BASE_URL}/api/auth/oauth2/authorize`);
      authUrl.searchParams.set("client_id", clientId);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", "openid offline_access");
      authUrl.searchParams.set("state", `state_${crypto.randomBytes(4).toString("hex")}`);
      authUrl.searchParams.set("code_challenge", pkce.challenge);
      authUrl.searchParams.set("code_challenge_method", "S256");

      const reqStart = performance.now();
      try {
        const res = await fetch(authUrl.toString(), {
          method: "GET",
          headers: { cookie: userCookie, ...getTestHeaders() },
          redirect: "manual",
        });
        latencies.push(performance.now() - reqStart);
        if (res.status !== 302 && res.status !== 200) {
          errors++;
        }
      } catch {
        errors++;
      }
    })
  );
  const totalDuration = performance.now() - tStart;
  const stats = calculateStats(latencies, totalDuration);

  console.log(`    Total Requests: ${stats.count} | Errors: ${errors} (${((errors / stats.count) * 100).toFixed(1)}%)`);
  console.log(`    Throughput:     ${stats.rps} RPS`);
  console.log(`    Latency:        min=${stats.min}ms | p50=${stats.p50}ms | p95=${stats.p95}ms | p99=${stats.p99}ms | max=${stats.max}ms`);
  assert.equal(errors, 0, "All 50 concurrent authorize requests must succeed");
}

// --------------------------------------------------------------------------
// TEST 2: TOKEN EXCHANGE LOAD (50 Concurrent Exchanges)
// --------------------------------------------------------------------------
console.log("\n▶ [BENCHMARK 2] /oauth2/token — 50 Concurrent Authorization Code Exchanges");
{
  const CONCURRENCY = 50;
  // Pre-generate 50 codes
  const pkceList = Array.from({ length: CONCURRENCY }).map(() => generatePkce());
  const codes: string[] = [];
  for (const pkce of pkceList) {
    const code = await fetchAuthCode(pkce);
    codes.push(code);
  }

  const latencies: number[] = [];
  let errors = 0;
  const tokens: any[] = [];

  const tStart = performance.now();
  await Promise.all(
    codes.map(async (code, idx) => {
      const pkce = pkceList[idx];
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: pkce.verifier,
      });

      const reqStart = performance.now();
      try {
        const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Basic ${basicAuth}`,
            ...getTestHeaders(),
          },
          body: body.toString(),
        });
        latencies.push(performance.now() - reqStart);
        if (res.status === 200) {
          tokens.push(await res.json());
        } else {
          errors++;
        }
      } catch {
        errors++;
      }
    })
  );
  const totalDuration = performance.now() - tStart;
  const stats = calculateStats(latencies, totalDuration);

  console.log(`    Total Requests: ${stats.count} | Errors: ${errors} (${((errors / stats.count) * 100).toFixed(1)}%)`);
  console.log(`    Throughput:     ${stats.rps} RPS`);
  console.log(`    Latency:        min=${stats.min}ms | p50=${stats.p50}ms | p95=${stats.p95}ms | p99=${stats.p99}ms | max=${stats.max}ms`);
  assert.equal(errors, 0, "All 50 concurrent token exchange requests must succeed");
}

// --------------------------------------------------------------------------
// TEST 3: REFRESH CONCURRENCY RACE & CAS (20 Concurrent Refreshes on Same R0)
// --------------------------------------------------------------------------
console.log("\n▶ [BENCHMARK 3] /oauth2/token — F-08 Concurrency Race: 20 Simultaneous Refreshes on Single R0");
{
  const pkce = generatePkce();
  const code = await fetchAuthCode(pkce);
  const tokenRes = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: pkce.verifier,
    }).toString(),
  });
  const { refresh_token: r0Token } = await tokenRes.json();

  const CONCURRENCY = 20;
  const responses: { status: number; data?: any }[] = [];

  const tStart = performance.now();
  await Promise.all(
    Array.from({ length: CONCURRENCY }).map(async () => {
      try {
        const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Basic ${basicAuth}`,
            ...getTestHeaders(),
          },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: r0Token,
          }).toString(),
        });
        const data = await res.json().catch(() => null);
        responses.push({ status: res.status, data });
      } catch (err: any) {
        responses.push({ status: 500, data: { error: err.message } });
      }
    })
  );
  const raceDuration = performance.now() - tStart;

  const successfulRotations = responses.filter((r) => r.status === 200);
  const failedRequests = responses.filter((r) => r.status !== 200);

  console.log(`    Race Duration:        ${raceDuration.toFixed(2)}ms across ${CONCURRENCY} concurrent attempts`);
  console.log(`    Successful Rotations: ${successfulRotations.length} (Expected: 1)`);
  console.log(`    Rejected Competitors: ${failedRequests.length} (Expected: 19)`);

  assert.equal(successfulRotations.length, 1, "Exactly ONE concurrent refresh request must succeed (F-08 invariant)");
  assert.equal(failedRequests.length, 19, "All 19 competing requests must be rejected");

  // Invariant check on DB state: exactly 1 active token family state
  const rotatedSuccessor = successfulRotations[0].data.refresh_token;
  const activeHash = crypto.createHash("sha256").update(rotatedSuccessor).digest("hex");
  const family = await db.collection("oauth_token_families").findOne({ activeTokenHash: activeHash });
  assert.ok(family, "Active token hash in database must match the winning rotated successor");
  console.log("    ✅ Invariant I1/F-08 holds: Token family state is atomically consistent.");
}

// --------------------------------------------------------------------------
// TEST 4: USERINFO ENDPOINT LOAD (100 Concurrent Requests)
// --------------------------------------------------------------------------
console.log("\n▶ [BENCHMARK 4] /oauth2/userinfo — 100 Concurrent Requests");
{
  const pkce = generatePkce();
  const code = await fetchAuthCode(pkce);
  const tokenRes = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: pkce.verifier,
    }).toString(),
  });
  const { access_token } = await tokenRes.json();

  const CONCURRENCY = 100;
  const latencies: number[] = [];
  let errors = 0;

  const tStart = performance.now();
  await Promise.all(
    Array.from({ length: CONCURRENCY }).map(async () => {
      const reqStart = performance.now();
      try {
        const res = await fetch(`${BASE_URL}/api/auth/oauth2/userinfo`, {
          headers: {
            Authorization: `Bearer ${access_token}`,
            ...getTestHeaders(),
          },
        });
        latencies.push(performance.now() - reqStart);
        if (res.status !== 200) {
          errors++;
        }
      } catch {
        errors++;
      }
    })
  );
  const totalDuration = performance.now() - tStart;
  const stats = calculateStats(latencies, totalDuration);

  console.log(`    Total Requests: ${stats.count} | Errors: ${errors} (${((errors / stats.count) * 100).toFixed(1)}%)`);
  console.log(`    Throughput:     ${stats.rps} RPS`);
  console.log(`    Latency:        min=${stats.min}ms | p50=${stats.p50}ms | p95=${stats.p95}ms | p99=${stats.p99}ms | max=${stats.max}ms`);
  assert.equal(errors, 0, "All 100 concurrent UserInfo requests must succeed");
}

// --------------------------------------------------------------------------
// TEST 5: MIXED WORKLOAD (100 Requests: 50% UserInfo, 25% Exchange, 15% Refresh, 10% Authorize)
// --------------------------------------------------------------------------
console.log("\n▶ [BENCHMARK 5] Mixed Workload (50% UserInfo, 25% Token Exchange, 15% Refresh, 10% Authorize)");
{
  // Setup baseline tokens
  const pkce = generatePkce();
  const code = await fetchAuthCode(pkce);
  const baseTokenRes = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: pkce.verifier,
    }).toString(),
  });
  const baseTokens = await baseTokenRes.json();
  let currentRefreshToken = baseTokens.refresh_token;

  // Pre-generate 25 codes for exchange
  const exchangeCodes: { code: string; verifier: string }[] = [];
  for (let i = 0; i < 25; i++) {
    const p = generatePkce();
    const c = await fetchAuthCode(p);
    exchangeCodes.push({ code: c, verifier: p.verifier });
  }

  const tasks: (() => Promise<number>)[] = [];

  // 50 UserInfo requests
  for (let i = 0; i < 50; i++) {
    tasks.push(async () => {
      const s = performance.now();
      const res = await fetch(`${BASE_URL}/api/auth/oauth2/userinfo`, {
        headers: { Authorization: `Bearer ${baseTokens.access_token}`, ...getTestHeaders() },
      });
      assert.equal(res.status, 200);
      return performance.now() - s;
    });
  }

  // 25 Token exchanges
  for (let i = 0; i < 25; i++) {
    const { code, verifier } = exchangeCodes[i];
    tasks.push(async () => {
      const s = performance.now();
      const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${basicAuth}`,
          ...getTestHeaders(),
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }).toString(),
      });
      assert.equal(res.status, 200);
      return performance.now() - s;
    });
  }

  // 10 Authorize requests
  for (let i = 0; i < 10; i++) {
    tasks.push(async () => {
      const p = generatePkce();
      const s = performance.now();
      const authUrl = new URL(`${BASE_URL}/api/auth/oauth2/authorize`);
      authUrl.searchParams.set("client_id", clientId);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", "openid offline_access");
      authUrl.searchParams.set("code_challenge", p.challenge);
      authUrl.searchParams.set("code_challenge_method", "S256");

      const res = await fetch(authUrl.toString(), {
        method: "GET",
        headers: { cookie: userCookie, ...getTestHeaders() },
        redirect: "manual",
      });
      assert.ok(res.status === 302 || res.status === 200);
      return performance.now() - s;
    });
  }

  // Shuffle tasks to simulate real mixed traffic
  tasks.sort(() => Math.random() - 0.5);

  const latencies: number[] = [];
  const tStart = performance.now();
  await Promise.all(
    tasks.map(async (task) => {
      const dur = await task();
      latencies.push(dur);
    })
  );

  // 15 Sequential refreshes
  for (let i = 0; i < 15; i++) {
    const s = performance.now();
    const res = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
        ...getTestHeaders(),
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: currentRefreshToken,
      }).toString(),
    });
    assert.equal(res.status, 200);
    const refreshed = await res.json();
    currentRefreshToken = refreshed.refresh_token;
    latencies.push(performance.now() - s);
  }

  const totalDuration = performance.now() - tStart;
  const stats = calculateStats(latencies, totalDuration);

  console.log(`    Total Mixed Requests: ${stats.count} | Errors: 0`);
  console.log(`    Aggregate RPS:        ${stats.rps} RPS`);
  console.log(`    Latency:              min=${stats.min}ms | p50=${stats.p50}ms | p95=${stats.p95}ms | p99=${stats.p99}ms | max=${stats.max}ms`);
}

// --------------------------------------------------------------------------
// TEST 6: MEMORY USAGE & HEAP LEAK CHECK (1,000 Iterations)
// --------------------------------------------------------------------------
console.log("\n▶ [BENCHMARK 6] Memory Usage & Leak Check — 1,000 Rapid Iterations");
{
  if (global.gc) {
    global.gc();
  }
  const initialHeap = process.memoryUsage().heapUsed;

  const pkce = generatePkce();
  const code = await fetchAuthCode(pkce);
  const tokenRes = await fetch(`${BASE_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      ...getTestHeaders(),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: pkce.verifier,
    }).toString(),
  });
  const { access_token } = await tokenRes.json();

  // Run 1000 fast calls to UserInfo in batches of 50
  const BATCH_SIZE = 50;
  const TOTAL = 1000;
  for (let b = 0; b < TOTAL / BATCH_SIZE; b++) {
    await Promise.all(
      Array.from({ length: BATCH_SIZE }).map(async () => {
        const res = await fetch(`${BASE_URL}/api/auth/oauth2/userinfo`, {
          headers: { Authorization: `Bearer ${access_token}`, ...getTestHeaders() },
        });
        assert.equal(res.status, 200);
      })
    );
  }

  // Allow event loop to drain pending microtasks
  await new Promise((r) => setTimeout(r, 600));
  if (global.gc) {
    global.gc();
  }
  const finalHeap = process.memoryUsage().heapUsed;
  const heapDiffMb = (finalHeap - initialHeap) / (1024 * 1024);

  console.log(`    Initial Heap: ${(initialHeap / (1024 * 1024)).toFixed(2)} MB`);
  console.log(`    Final Heap:   ${(finalHeap / (1024 * 1024)).toFixed(2)} MB`);
  console.log(`    Heap Delta:   ${heapDiffMb >= 0 ? "+" : ""}${heapDiffMb.toFixed(2)} MB over 1,000 requests`);

  // Growth must be bounded under 120MB across 1,000 rapid requests
  assert.ok(heapDiffMb < 120, `Heap growth over 1000 requests (${heapDiffMb.toFixed(2)} MB) must be bounded`);
  console.log("    ✅ Memory check passed: No unbounded heap accumulation detected.");
}

server.close();
console.log("\n================================================================");
console.log("  ALL PERFORMANCE AND LOAD BENCHMARKS PASSED SUCCESSFULLY");
console.log("================================================================\n");
process.exit(0);
