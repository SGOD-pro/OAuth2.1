import { performance } from "node:perf_hooks";

const BASE_URL = "http://localhost:3000";

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

async function benchmark(
  name: string,
  url: string,
  options: RequestInit,
  count = 50
): Promise<{ stats: TimingStats; statusCodes: Record<number, number> }> {
  const latencies: number[] = [];
  const statusCodes: Record<number, number> = {};

  // Warmup 3 requests
  for (let i = 0; i < 3; i++) {
    try {
      await fetch(url, options);
    } catch {}
  }

  for (let i = 0; i < count; i++) {
    const start = performance.now();
    let status = 0;
    try {
      const res = await fetch(url, options);
      status = res.status;
    } catch {
      status = -1;
    }
    const elapsed = performance.now() - start;
    latencies.push(elapsed);
    statusCodes[status] = (statusCodes[status] || 0) + 1;
    // Tiny delay between sequential requests to prevent socket congestion
    await new Promise((r) => setTimeout(r, 25));
  }

  const stats = calculateStats(latencies);
  return { stats, statusCodes };
}

async function main() {
  console.log("==================================================================");
  console.log(" SWYRA AUTH -- TIMING ORACLE & LATENCY DISTRIBUTION BENCHMARK");
  console.log(` Timestamp: ${new Date().toISOString()}`);
  console.log(" 50 samples per condition, sequential execution");
  console.log("==================================================================\n");

  // -------------------------------------------------------------
  // B7: Password Reset Timing
  // -------------------------------------------------------------
  console.log("--- [B7] PASSWORD RESET REQUEST TIMING (50 samples) ---");
  const b7Registered = await benchmark(
    "B7.1 Registered Email",
    `${BASE_URL}/api/auth/request-password-reset`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: "admin@swyra.com", redirectTo: "/reset-password" }),
    },
    50
  );
  console.log("Registered Email (admin@swyra.com):", JSON.stringify(b7Registered, null, 2));

  const b7Unregistered = await benchmark(
    "B7.2 Unregistered Email",
    `${BASE_URL}/api/auth/request-password-reset`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: "nonexistent_user_9921@unregistered.invalid", redirectTo: "/reset-password" }),
    },
    50
  );
  console.log("Unregistered Email:", JSON.stringify(b7Unregistered, null, 2));

  // -------------------------------------------------------------
  // B10: Admin Login Timing & Enumeration (4 States)
  // -------------------------------------------------------------
  console.log("\n--- [B10] ADMIN LOGIN TIMING (50 samples each across 4 states) ---");

  const b10State1 = await benchmark(
    "B10.1 Valid Admin + Wrong Password",
    `${BASE_URL}/api/auth/sign-in/email`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: "admin@swyra.com", password: "WrongPassword@999!" }),
    },
    50
  );
  console.log("State 1 (Valid Admin + Wrong Password):", JSON.stringify(b10State1, null, 2));

  const b10State2 = await benchmark(
    "B10.2 Valid Non-Admin + Wrong Password",
    `${BASE_URL}/api/auth/sign-in/email`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: "app1@gmail.com", password: "WrongPassword@999!" }),
    },
    50
  );
  console.log("State 2 (Valid Non-Admin + Wrong Password):", JSON.stringify(b10State2, null, 2));

  const b10State3 = await benchmark(
    "B10.3 Nonexistent Email + Wrong Password",
    `${BASE_URL}/api/auth/sign-in/email`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: "definitely_not_a_user_8832@ghost.invalid", password: "WrongPassword@999!" }),
    },
    50
  );
  console.log("State 3 (Nonexistent Email + Wrong Password):", JSON.stringify(b10State3, null, 2));

  // State 4: Check if account exists with 2FA vs without 2FA
  const b10State4 = await benchmark(
    "B10.4 2FA-Enabled Account Wrong Password Probe",
    `${BASE_URL}/api/auth/sign-in/email`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:5174" },
      body: JSON.stringify({ email: "admin@swyra.com", password: "IncorrectPass@123!" }),
    },
    50
  );
  console.log("State 4 (2FA Account with Wrong Password):", JSON.stringify(b10State4, null, 2));
}

main().catch(console.error);
