import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { Hono } from "hono";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { checkUsernameAvailability, UsernameBloomFilter } from "../../src/identity/username-bloom-filter";

function p95(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95));
  return sorted[idx] ?? 0;
}

describe("P6b/P8 Username Availability with Bloom Prefilter (Real Docker MongoDB)", { timeout: 60_000 }, () => {
  let suiteCtx: SuiteDatabaseContext;
  let db: any;

  before(async () => {
    process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
    process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
    process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
    process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
    process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
    isolateTestEnvironment();
    process.env.NODE_ENV = "test";
    process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
    process.env.IDENTITY_REGISTRATION_MODE = "verified";

    suiteCtx = await setupSuiteDatabase("p6b_username_bloom");
    const mongoMod = await import("../../src/db/mongo");
    db = await mongoMod.getDb();
    const { ensureIdentityCollectionIndexes } = await import("../../src/db/indexes");
    await ensureIdentityCollectionIndexes(db);
  });

  after(async () => {
    const { closeDb } = await import("../../src/db/mongo");
    await closeDb();
    await suiteCtx?.cleanup();
  });

  it("confirms false positives against MongoDB and falls back to exact lookup when filter is stale or unavailable", async () => {
    const { computeUsernameLookup } = await import("../../src/identity/registration-crypto");

    // Seed one taken username in MongoDB
    await db.collection("identity_lookup").insertOne({
      kind: "username",
      keyVersion: 1,
      keyedLookup: computeUsernameLookup("taken_real"),
      userId: "user-taken-1",
      createdAt: new Date(),
    });

    // 1. Force false positive with a saturated 1-byte / 8-bit filter
    const tinyFilter = new UsernameBloomFilter({ expectedItems: 1, falsePositiveRate: 0.9, maxAgeMs: 60_000 });
    tinyFilter.markFresh(Date.now());
    for (let i = 0; i < 30; i++) tinyFilter.add(`filler_${i}`);
    assert.equal(tinyFilter.mightContain("available_fp_user"), true, "Precondition: tiny filter must false-positive");

    const fpRes = await checkUsernameAvailability({
      database: db,
      normalizedUsername: "available_fp_user",
      keyedLookup: computeUsernameLookup("available_fp_user"),
      bloomFilter: tinyFilter,
    });
    assert.equal(fpRes.available, true);
    assert.equal(fpRes.path, "mongo_confirm_available");
    assert.equal(fpRes.mongoQueries, 1);

    // 2. Stale filter (expired maxAgeMs) must fall back to MongoDB and catch taken_real
    const staleFilter = new UsernameBloomFilter({ expectedItems: 100, falsePositiveRate: 0.01, maxAgeMs: 1000 });
    staleFilter.markFresh(Date.now() - 10_000);
    const staleRes = await checkUsernameAvailability({
      database: db,
      normalizedUsername: "taken_real",
      keyedLookup: computeUsernameLookup("taken_real"),
      bloomFilter: staleFilter,
    });
    assert.equal(staleRes.available, false);
    assert.equal(staleRes.path, "mongo_fallback_stale");
    assert.equal(staleRes.mongoQueries, 1);

    // 3. Unavailable filter (undefined) falls back to exact lookup
    const noFilterRes = await checkUsernameAvailability({
      database: db,
      normalizedUsername: "taken_real",
      keyedLookup: computeUsernameLookup("taken_real"),
    });
    assert.equal(noFilterRes.available, false);
    assert.equal(noFilterRes.path, "mongo_fallback_stale");
    assert.equal(noFilterRes.mongoQueries, 1);
  });

  it("reflects newly claimed usernames and enforces transactional uniqueness on concurrent signups even if filter says absent", async () => {
    const {
      computeBrowserBindingHash,
      computeEmailLookup,
      computeUsernameLookup,
      digestToken,
      encryptContactEmail,
    } = await import("../../src/identity/registration-crypto");
    const { completeVerifiedRegistration } = await import("../../src/identity/registration-complete");
    const { createUsernameCheckHandler } = await import("../../src/routes/identity-registration-complete");

    const bloom = new UsernameBloomFilter({ expectedItems: 500, falsePositiveRate: 0.01, maxAgeMs: 60_000 });
    bloom.markFresh(Date.now());

    const seedIntent = async (id: string, email: string) => {
      const rawBrowser = `b-${id}`;
      const rawProof = `p-${id}`;
      const emailLookup = computeEmailLookup(email);
      await db.collection("registration_intents").insertOne({
        intentId: id,
        browserBindingHash: computeBrowserBindingHash(rawBrowser),
        proofDigest: digestToken(rawProof, "proof"),
        status: "verified",
        emailLookup,
        encryptedEmail: encryptContactEmail(email, { intentId: id, emailLookup }),
        termsVersion: "v1",
        expiresAt: new Date(Date.now() + 600_000),
        proofExpiresAt: new Date(Date.now() + 600_000),
      });
      return { rawBrowser, rawProof };
    };

    // Route-level check before claim uses negative fast path
    const i0 = await seedIntent("bloom-check-0", "bloom0@example.com");
    const app = new Hono();
    app.post("/username/check", createUsernameCheckHandler({ getDb: async () => db, bloomFilter: bloom }));

    const beforeClaim = await app.request("/username/check", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `swyra_reg_browser=${i0.rawBrowser}; swyra_reg_proof=${i0.rawProof}`,
      },
      body: JSON.stringify({ username: "FreshClaimUser" }),
    });
    assert.equal(beforeClaim.status, 200);
    assert.equal((await beforeClaim.json()).available, true);

    // Concurrent signups for same normalized username ("RaceUser" vs "raceuser") while bloom says absent
    const i1 = await seedIntent("bloom-race-1", "race1@example.com");
    const i2 = await seedIntent("bloom-race-2", "race2@example.com");
    const [r1, r2] = await Promise.all([
      completeVerifiedRegistration(
        {
          rawBrowser: i1.rawBrowser,
          rawProof: i1.rawProof,
          username: "RaceUser",
          password: "Strong!Password#2026",
          acceptedTermsVersion: "v1",
          clientIp: "198.51.100.1",
          userAgent: "bloom-test",
          requestHeaders: new Headers(),
          requestId: "race-1",
        },
        { getDb: async () => db, signInEmail: async () => null, bloomFilter: bloom }
      ),
      completeVerifiedRegistration(
        {
          rawBrowser: i2.rawBrowser,
          rawProof: i2.rawProof,
          username: "raceuser",
          password: "Strong!Password#2026",
          acceptedTermsVersion: "v1",
          clientIp: "198.51.100.1",
          userAgent: "bloom-test",
          requestHeaders: new Headers(),
          requestId: "race-2",
        },
        { getDb: async () => db, signInEmail: async () => null, bloomFilter: bloom }
      ),
    ]);

    const statuses = [r1.status, r2.status].sort();
    assert.deepEqual(statuses, [201, 409], "One concurrent signup must succeed (201) and one must fail (409)");
    assert.equal(
      await db.collection("identity_lookup").countDocuments({ kind: "username", keyedLookup: computeUsernameLookup("raceuser") }),
      1
    );

    // Newly claimed username now reports available: false via route handler
    const afterClaim = await app.request("/username/check", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `swyra_reg_browser=${i0.rawBrowser}; swyra_reg_proof=${i0.rawProof}`,
      },
      body: JSON.stringify({ username: "RaceUser" }),
    });
    assert.equal(afterClaim.status, 200);
    assert.equal((await afterClaim.json()).available, false);
  });

  it("benchmarks indexed MongoDB alone versus Bloom prefilter path", async () => {
    const { computeUsernameLookup } = await import("../../src/identity/registration-crypto");
    const bloom = new UsernameBloomFilter({ expectedItems: 1000, falsePositiveRate: 0.01, maxAgeMs: 60_000 });
    bloom.markFresh(Date.now());

    const seedDocs = [];
    for (let i = 0; i < 500; i++) {
      const uname = `seeded_user_${i}`;
      bloom.add(uname);
      seedDocs.push({
        kind: "username",
        keyVersion: 1,
        keyedLookup: computeUsernameLookup(uname),
        userId: `seed-${i}`,
        createdAt: new Date(),
      });
    }
    await db.collection("identity_lookup").insertMany(seedDocs);

    const probes = Array.from({ length: 200 }, (_, i) =>
      i % 5 === 0 ? `seeded_user_${i % 500}` : `fresh_candidate_${i}`
    );

    const mongoLatencies: number[] = [];
    let mongoOnlyQueries = 0;
    for (const u of probes) {
      const t0 = performance.now();
      const res = await checkUsernameAvailability({
        database: db,
        normalizedUsername: u,
        keyedLookup: computeUsernameLookup(u),
      });
      mongoLatencies.push(performance.now() - t0);
      mongoOnlyQueries += res.mongoQueries;
    }

    const bloomLatencies: number[] = [];
    let bloomMongoQueries = 0;
    for (const u of probes) {
      const t0 = performance.now();
      const res = await checkUsernameAvailability({
        database: db,
        normalizedUsername: u,
        keyedLookup: computeUsernameLookup(u),
        bloomFilter: bloom,
      });
      bloomLatencies.push(performance.now() - t0);
      bloomMongoQueries += res.mongoQueries;
    }

    const mongoP95 = Number(p95(mongoLatencies).toFixed(3));
    const bloomP95 = Number(p95(bloomLatencies).toFixed(3));
    const memBytes = bloom.memoryBytes();
    console.log(
      JSON.stringify({
        benchmark: "username_availability_200_probes_80pct_available",
        mongoOnly: { p95Ms: mongoP95, mongoQueries: mongoOnlyQueries },
        bloomPath: { p95Ms: bloomP95, mongoQueries: bloomMongoQueries, filterMemoryBytes: memBytes },
      })
    );
    assert.ok(bloomMongoQueries < mongoOnlyQueries, "Bloom path must reduce MongoDB queries on available usernames");
  });
});
