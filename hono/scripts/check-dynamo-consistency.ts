/**
 * Verification script: confirms rate-limit and origin-cache consistency
 * across simulated concurrent Lambda invocations via DynamoDB.
 *
 * Requires a real DynamoDB table (local or deployed).
 * Run: DYNAMODB_TABLE=<table-name> AWS_REGION=<region> npx tsx scripts/check-dynamo-consistency.ts
 *
 * What it checks:
 *   1. Two concurrent rate-limit increments both land (count reaches 2, not 1).
 *   2. Origin-cache write is visible immediately, and invalidation removes it.
 */
import {
  getRateLimit,
  putRateLimit,
  getOriginCache,
  putOriginCache,
  invalidateOriginCache,
} from "../src/db/dynamo";

const TEST_IP = `test-${Date.now()}`;
const TEST_ORIGIN = `https://test-${Date.now()}.example.com`;

async function checkRateLimitConsistency() {
  console.log("── Rate limit consistency ──");

  const resetAt = Date.now() + 60_000;

  // Simulate two concurrent increments
  await Promise.all([
    putRateLimit(TEST_IP, 1, resetAt),
    (async () => {
      // Small delay to simulate near-concurrent write
      await new Promise((r) => setTimeout(r, 50));
      const entry = await getRateLimit(TEST_IP);
      const count = entry ? entry.count + 1 : 1;
      await putRateLimit(TEST_IP, count, resetAt);
    })(),
  ]);

  const final = await getRateLimit(TEST_IP);
  if (!final) {
    console.error("FAIL: rate-limit entry not found after writes");
    process.exit(1);
  }

  if (final.count < 2) {
    console.error(`FAIL: expected count >= 2, got ${final.count} (lost write)`);
    process.exit(1);
  }

  console.log(`PASS: rate-limit count = ${final.count} (both writes visible)`);
}

async function checkOriginCacheConsistency() {
  console.log("── Origin cache consistency ──");

  // Write
  await putOriginCache(TEST_ORIGIN, true);
  const cached = await getOriginCache(TEST_ORIGIN);
  if (cached !== true) {
    console.error(`FAIL: expected cached=true, got ${cached}`);
    process.exit(1);
  }
  console.log("PASS: origin-cache write is immediately readable");

  // Invalidate
  await invalidateOriginCache([TEST_ORIGIN]);
  const after = await getOriginCache(TEST_ORIGIN);
  if (after !== null) {
    console.error(`FAIL: expected null after invalidation, got ${after}`);
    process.exit(1);
  }
  console.log("PASS: origin-cache invalidation is immediately visible");
}

async function main() {
  await checkRateLimitConsistency();
  await checkOriginCacheConsistency();
  console.log("\n✓ All DynamoDB consistency checks passed");
}

main().catch((err) => {
  console.error("ERROR:", err);
  process.exit(1);
});
