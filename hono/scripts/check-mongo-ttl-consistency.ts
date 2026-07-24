/**
 * Verification script: confirms rate-limit and origin-cache consistency
 * across simulated concurrent Lambda invocations via MongoDB TTL collections.
 *
 * Requires MONGO_URI to point at a disposable local or remote database.
 * Run: MONGO_URI=<uri> npx tsx scripts/check-mongo-ttl-consistency.ts
 *
 * What it checks:
 *   1. Two concurrent rate-limit increments both land (count reaches 2, not 1).
 *   2. Origin-cache write is visible immediately, and invalidation removes it.
 */
import {
  incrementRateLimit,
  getOriginCache,
  putOriginCache,
  invalidateOriginCache,
} from "../src/db/state";
import { closeDb } from "../src/db/mongo";

const TEST_IP = `test-${Date.now()}`;
const TEST_ORIGIN = `https://test-${Date.now()}.example.com`;

async function checkRateLimitConsistency() {
  console.log("── Rate limit consistency ──");

  const [, final] = await Promise.all([
    incrementRateLimit(TEST_IP, Date.now(), 60_000),
    incrementRateLimit(TEST_IP, Date.now(), 60_000),
  ]);

  if (final.count < 2) {
    console.error(`FAIL: expected count >= 2, got ${final.count} (lost write)`);
    process.exit(1);
  }

  console.log(`PASS: rate-limit count = ${final.count} (both increments visible)`);
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
  console.log("\nAll MongoDB TTL consistency checks passed");
  await closeDb();
}

main().catch((err) => {
  console.error("ERROR:", err);
  void closeDb();
  process.exit(1);
});
