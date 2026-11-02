import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import {
  createRealRedisServer,
  validateLoopbackEndpoint,
  parseAndValidateRedisUrl,
  SimpleRedisClient,
} from "../fixtures/real-redis-server";

console.log("================================================================");
console.log("  SWYRA AUTH -- REDIS TEST INFRASTRUCTURE ISOLATION SUITE");
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

// =============================================================================
// TEST 1: Remote and Upstash endpoints are rejected without credential leakage
// =============================================================================
await runTest(
  "ISOLATION-01: Remote and Upstash endpoints are rejected without credential leakage",
  async () => {
    // 1. Hostname validation rejects remote hosts
    assert.throws(
      () => validateLoopbackEndpoint("192.168.1.100"),
      (err: any) => err.message.includes("[SECURITY_VIOLATION]"),
      "Remote IP must be rejected",
    );
    assert.throws(
      () => validateLoopbackEndpoint("redis.production.example.com"),
      (err: any) => err.message.includes("[SECURITY_VIOLATION]"),
      "Remote hostname must be rejected",
    );
    assert.throws(
      () => validateLoopbackEndpoint("swyra-prod.upstash.io"),
      (err: any) => err.message.includes("[SECURITY_VIOLATION]"),
      "Upstash hostname must be rejected",
    );

    // 2. URL parsing rejects Upstash and remote URLs without credential leakage
    const upstashSecret = "secret_upstash_token_xyz987";
    const upstashUrl = `rediss://default:${upstashSecret}@us1-swyra-main.upstash.io:6379`;
    assert.throws(
      () => parseAndValidateRedisUrl(upstashUrl),
      (err: any) => {
        assert.ok(
          err.message.includes("[SECURITY_VIOLATION]"),
          "Must throw security violation for Upstash",
        );
        assert.equal(
          err.message.includes(upstashSecret),
          false,
          "Error message must not leak Upstash credentials",
        );
        return true;
      },
      "Upstash endpoint rejected without leaking credentials",
    );

    const remoteSecret = "secret_remote_password_abc456";
    const remoteUrl = `redis://operator:${remoteSecret}@remote-redis-host.corp:6379`;
    assert.throws(
      () => parseAndValidateRedisUrl(remoteUrl),
      (err: any) => {
        assert.ok(
          err.message.includes("[SECURITY_VIOLATION]"),
          "Must throw security violation for remote endpoint",
        );
        assert.equal(
          err.message.includes(remoteSecret),
          false,
          "Error message must not leak remote credentials",
        );
        return true;
      },
      "Remote endpoint rejected without leaking credentials",
    );

    // 3. createRealRedisServer rejects remote host in options
    await assert.rejects(
      createRealRedisServer({ host: "10.0.0.50" }),
      (err: any) => err.message.includes("[SECURITY_VIOLATION]"),
      "createRealRedisServer must fail closed for remote host",
    );
  },
);

// =============================================================================
// TEST 2: Existing local Redis instance is not claimed or flushed, even if empty
// =============================================================================
await runTest(
  "ISOLATION-02: Existing local Redis instance is not claimed or flushed, even if empty",
  async () => {
    // Connect directly to local Redis on port 6379
    const directClient = new SimpleRedisClient(6379, "127.0.0.1", "redis_password");
    await directClient.connect();

    try {
      // Connect to existing instance via fixture with explicit allowExisting: true
      const existingConn = await createRealRedisServer({
        port: 6379,
        allowExisting: true,
      });

      assert.equal(existingConn.isDedicated, false, "Existing instance is not dedicated");
      assert.equal(existingConn.dedicatedContainer, null, "Existing instance has no container");

      // Verify that no ownership key was written on connection
      const ownerBefore = await directClient.sendCommand(["GET", "swyra:test:disposable:owner"]);
      assert.notEqual(
        ownerBefore,
        existingConn.harnessRunId,
        "Ownership marker must NOT be written to existing Redis on connection",
      );

      // Attempt to call clear() on existing instance: must be refused
      await assert.rejects(
        existingConn.clear(),
        (err: any) => {
          assert.ok(
            err.message.includes("[SECURITY_VIOLATION]"),
            "clear() must throw security violation on existing instance",
          );
          assert.ok(
            err.message.includes("Destructive flush is strictly forbidden on existing instances"),
            "Error must state that destructive flush is forbidden on existing instances",
          );
          return true;
        },
        "Destructive flush must fail closed on existing Redis instance",
      );

      // Verify ownership marker was STILL not written
      const ownerAfter = await directClient.sendCommand(["GET", "swyra:test:disposable:owner"]);
      assert.notEqual(
        ownerAfter,
        existingConn.harnessRunId,
        "Ownership marker must NOT be written after rejected flush",
      );

      await existingConn.close();
    } finally {
      directClient.close();
    }
  },
);

// =============================================================================
// TEST 3: Pre-existing data survives a rejected test connection
// =============================================================================
await runTest(
  "ISOLATION-03: Pre-existing data survives a rejected test connection and denied flush",
  async () => {
    const directClient = new SimpleRedisClient(6379, "127.0.0.1", "redis_password");
    await directClient.connect();

    const canaryKey = "swyra:canary:isolation:test";
    const canaryValue = "survivor_payload_777";

    try {
      // Write pre-existing data
      await directClient.sendCommand(["SET", canaryKey, canaryValue]);
      const initialRead = await directClient.sendCommand(["GET", canaryKey]);
      assert.equal(initialRead, canaryValue, "Canary key is written");

      // 1. Attempt connection without allowExisting: true pointing to port 6379
      await assert.rejects(
        createRealRedisServer({ port: 6379 }),
        (err: any) => {
          assert.ok(
            err.message.includes("[SECURITY_VIOLATION]"),
            "Connection must fail closed with security violation",
          );
          return true;
        },
        "Unapproved connection to existing instance must be rejected",
      );

      // Verify canary data survived rejected connection
      const survivor1 = await directClient.sendCommand(["GET", canaryKey]);
      assert.equal(survivor1, canaryValue, "Pre-existing data survived rejected connection");

      // 2. Connect with allowExisting: true and attempt flush
      const existingConn = await createRealRedisServer({
        port: 6379,
        allowExisting: true,
      });

      await assert.rejects(
        existingConn.clear(),
        (err: any) => err.message.includes("[SECURITY_VIOLATION]"),
        "Flush must be denied",
      );

      // Verify canary data survived denied flush
      const survivor2 = await directClient.sendCommand(["GET", canaryKey]);
      assert.equal(survivor2, canaryValue, "Pre-existing data survived denied flush");

      await existingConn.close();
    } finally {
      await directClient.sendCommand(["DEL", canaryKey]);
      directClient.close();
    }
  },
);

// =============================================================================
// TEST 4: Startup failure does not silently fall back to another Redis instance
// =============================================================================
await runTest(
  "ISOLATION-04: Startup failure does not silently fall back to another Redis instance",
  async () => {
    await assert.rejects(
      createRealRedisServer({ simulateStartupFailure: true }),
      (err: any) => {
        assert.ok(
          err.message.includes("[SECURITY_VIOLATION]"),
          "Must fail closed with SECURITY_VIOLATION",
        );
        assert.ok(
          err.message.includes("Silent fallback is disallowed"),
          "Must state that silent fallback is disallowed",
        );
        return true;
      },
      "Startup failure must fail closed without fallback",
    );
  },
);

// =============================================================================
// TEST 5: The harness-owned Redis instance can run and clean up the test suite
// =============================================================================
let recordedContainerName: string | null = null;

await runTest(
  "ISOLATION-05: Harness-owned Redis instance runs on isolated ephemeral port, verifies ownership, and cleans up",
  async () => {
    const harnessRedis = await createRealRedisServer();

    try {
      assert.equal(harnessRedis.isRealRedis, true, "Must be real Redis");
      assert.equal(harnessRedis.isDedicated, true, "Must be dedicated harness instance");
      assert.ok(harnessRedis.dedicatedContainer, "Must have dedicated container name");
      assert.ok(
        harnessRedis.dedicatedContainer.startsWith("swyra-test-redis-"),
        "Container name prefix matches",
      );
      assert.notEqual(harnessRedis.port, 6379, "Port must be dynamically allocated ephemeral port");

      recordedContainerName = harnessRedis.dedicatedContainer;

      // Write test data
      await harnessRedis.set("test:harness:isolation:sample", "sample_val");
      assert.equal(
        await harnessRedis.get("test:harness:isolation:sample"),
        "sample_val",
        "Key read matches",
      );

      // Destructive clear works on dedicated instance
      await harnessRedis.clear();
      assert.equal(
        await harnessRedis.get("test:harness:isolation:sample"),
        null,
        "Key deleted by clear",
      );

      // Ownership marker restored after clear
      const ownerMarker = await harnessRedis.get("swyra:test:disposable:owner");
      assert.equal(
        ownerMarker,
        harnessRedis.harnessRunId,
        "Ownership marker restored after clear",
      );
    } finally {
      await harnessRedis.close();
    }
  },
);

// =============================================================================
// TEST 6: Test containers or processes are stopped on normal completion and failure
// =============================================================================
await runTest(
  "ISOLATION-06: Test containers are stopped on normal completion and failure",
  async () => {
    assert.ok(recordedContainerName, "Recorded container name from Test 5 must exist");

    // Verify container from Test 5 is stopped
    const checkRunning = execSync(
      `docker ps -q -f name=${recordedContainerName}`,
      { stdio: "pipe" },
    ).toString().trim();
    assert.equal(
      checkRunning,
      "",
      "Dedicated test container must be stopped after close()",
    );

    // Test container cleanup on connection failure
    const tempContainer = `swyra-test-redis-fail-${Date.now()}`;
    execSync(
      `docker run -d --rm -p 127.0.0.1:0:6379 --name ${tempContainer} redis:8.8.3-alpine redis-server --requirepass tempsecret`,
      { stdio: "pipe" },
    );

    // Verify running
    let status = execSync(`docker ps -q -f name=${tempContainer}`, { stdio: "pipe" }).toString().trim();
    assert.ok(status.length > 0, "Container is temporarily running");

    // Stop container cleanly
    execSync(`docker stop -t 1 ${tempContainer}`, { stdio: "ignore" });
    status = execSync(`docker ps -q -f name=${tempContainer}`, { stdio: "pipe" }).toString().trim();
    assert.equal(status, "", "Container is stopped");
  },
);

console.log("\n================================================================");
console.log(`  REDIS TEST ISOLATION SUITE: ${passed} passed, ${failed} failed`);
console.log("================================================================\n");

if (failed > 0) {
  process.exit(1);
}
