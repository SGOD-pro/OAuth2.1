import { performance } from "node:perf_hooks";

process.env.NODE_ENV = "test";
process.env.MONGO_URI = "mongodb+srv://testing938212:Jarvis123@cluster0.df3gouo.mongodb.net/oauthservice";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.TRUSTED_PROXY_CIDRS = "10.0.0.0/8";

const { authProvider } = await import("../src/utils/auth");
const { getDb } = await import("../src/db/mongo");

interface TimingStats {
  samples: number;
  meanMs: number;
  medianMs: number;
  stdDevMs: number;
  minMs: number;
  maxMs: number;
  p25Ms: number;
  p75Ms: number;
  iqrMs: number;
}

function calculateStats(latencies: number[]): TimingStats {
  const sorted = [...latencies].sort((a, b) => a - b);
  const n = sorted.length;
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const mean = sum / n;
  const median = n % 2 === 0 ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2 : sorted[Math.floor(n / 2)];
  const variance = sorted.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / n;
  const stdDev = Math.sqrt(variance);
  const p25 = sorted[Math.floor(n * 0.25)];
  const p75 = sorted[Math.floor(n * 0.75)];

  return {
    samples: n,
    meanMs: Number(mean.toFixed(2)),
    medianMs: Number(median.toFixed(2)),
    stdDevMs: Number(stdDev.toFixed(2)),
    minMs: Number(sorted[0].toFixed(2)),
    maxMs: Number(sorted[n - 1].toFixed(2)),
    p25Ms: Number(p25.toFixed(2)),
    p75Ms: Number(p75.toFixed(2)),
    iqrMs: Number((p75 - p25).toFixed(2)),
  };
}

async function runTimingTrial(
  name: string,
  fn: () => Promise<unknown>,
  count = 50
): Promise<TimingStats> {
  const latencies: number[] = [];

  // Warmup
  for (let i = 0; i < 3; i++) {
    try { await fn(); } catch {}
  }

  for (let i = 0; i < count; i++) {
    const start = performance.now();
    try {
      await fn();
    } catch {}
    const elapsed = performance.now() - start;
    latencies.push(elapsed);
    await new Promise((r) => setTimeout(r, 10));
  }

  return calculateStats(latencies);
}

async function main() {
  console.log("==================================================================");
  console.log(" SWYRA AUTH -- DIRECT CORE TIMING & ORACLE BENCHMARK (50 trials)");
  console.log(` Timestamp: ${new Date().toISOString()}`);
  console.log("==================================================================\n");

  const db = await getDb();
  // Ensure we know what users exist
  const existingUser = await db.collection("user").findOne({ email: "admin@swyra.com" });
  const appUser = await db.collection("user").findOne({ email: "app1@gmail.com" });

  console.log("Test Context:");
  console.log("  - Admin user exists:", !!existingUser);
  console.log("  - App1 user exists:", !!appUser);

  // -------------------------------------------------------------
  // B7: Password Reset Timing
  // -------------------------------------------------------------
  console.log("\n--- [B7] PASSWORD RESET REQUEST TIMING (50 samples) ---");
  const b7Registered = await runTimingTrial("B7 Registered", async () => {
    return authProvider.api.forgetPassword({
      body: { email: "admin@swyra.com", redirectTo: "/reset-password" },
    });
  });
  console.log("Registered Email (admin@swyra.com):\n", JSON.stringify(b7Registered, null, 2));

  const b7Unregistered = await runTimingTrial("B7 Unregistered", async () => {
    return authProvider.api.forgetPassword({
      body: { email: "ghost_user_992@nonexistent-domain.invalid", redirectTo: "/reset-password" },
    });
  });
  console.log("Unregistered Email:\n", JSON.stringify(b7Unregistered, null, 2));

  // -------------------------------------------------------------
  // B10: Admin Login Timing (4 States)
  // -------------------------------------------------------------
  console.log("\n--- [B10] LOGIN ATTEMPT TIMING (50 samples each across 4 states) ---");

  // State 1: Valid admin email + wrong password
  const b10State1 = await runTimingTrial("State 1: Admin + Wrong Pass", async () => {
    return authProvider.api.signInEmail({
      body: { email: "admin@swyra.com", password: "WrongPassword@123!" },
    });
  });
  console.log("State 1 (Valid Admin + Wrong Password):\n", JSON.stringify(b10State1, null, 2));

  // State 2: Valid non-admin email + wrong password
  const b10State2 = await runTimingTrial("State 2: Non-Admin + Wrong Pass", async () => {
    return authProvider.api.signInEmail({
      body: { email: "app1@gmail.com", password: "WrongPassword@123!" },
    });
  });
  console.log("State 2 (Valid Non-Admin + Wrong Password):\n", JSON.stringify(b10State2, null, 2));

  // State 3: Nonexistent email + wrong password
  const b10State3 = await runTimingTrial("State 3: Ghost Email + Wrong Pass", async () => {
    return authProvider.api.signInEmail({
      body: { email: "ghost_nonexistent_882@fake.invalid", password: "WrongPassword@123!" },
    });
  });
  console.log("State 3 (Nonexistent Email + Wrong Password):\n", JSON.stringify(b10State3, null, 2));

  // State 4: Valid admin email + correct password
  const b10State4 = await runTimingTrial("State 4: Admin + Correct Pass (or probe)", async () => {
    return authProvider.api.signInEmail({
      body: { email: "admin@swyra.com", password: "AdminPassword@123!" },
    });
  });
  console.log("State 4 (Valid Admin + Probe/Attempt):\n", JSON.stringify(b10State4, null, 2));

  console.log("\n==================================================================");
  console.log(" BENCHMARK COMPLETED SUCCESSFULLY");
  console.log("==================================================================");
  process.exit(0);
}

main().catch(console.error);
