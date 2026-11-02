import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import net from "node:net";
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
let simulatedExistingContainer: string | null = null;

const cleanupSimulatedContainer = () => {
  process.removeListener("exit", cleanupSimulatedContainer);
  process.removeListener("SIGINT", cleanupSimulatedContainer);
  process.removeListener("SIGTERM", cleanupSimulatedContainer);
  if (simulatedExistingContainer) {
    try {
      if (simulatedExistingContainer === "compose") {
        execSync("docker compose -f redis-compose.yml stop", { stdio: "ignore" });
      } else {
        execSync(`docker stop -t 1 ${simulatedExistingContainer}`, { stdio: "ignore" });
      }
    } catch {}
    simulatedExistingContainer = null;
  }
};

process.once("exit", cleanupSimulatedContainer);
process.once("SIGINT", cleanupSimulatedContainer);
process.once("SIGTERM", cleanupSimulatedContainer);

async function ensureExistingRedisInstance(): Promise<void> {
  const isListening = await new Promise<boolean>((resolve) => {
    const s = net.createConnection({ port: 6379, host: "127.0.0.1" });
    s.once("connect", () => {
      s.destroy();
      resolve(true);
    });
    s.once("error", () => {
      s.destroy();
      resolve(false);
    });
  });

  if (!isListening) {
    try {
      execSync("docker compose -f redis-compose.yml up -d --wait", { stdio: "pipe" });
      simulatedExistingContainer = "compose";
    } catch {
      const name = `swyra-test-sim-redis-${Date.now()}`;
      execSync(
        `docker run -d --rm -p 127.0.0.1:6379:6379 --name ${name} redis:8.8.3-alpine redis-server --requirepass redis_password`,
        { stdio: "pipe" },
      );
      simulatedExistingContainer = name;
    }

    const probe = new SimpleRedisClient(6379, "127.0.0.1", "redis_password");
    await probe.connect(10000, 100);
    probe.close();
  }
}

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
await ensureExistingRedisInstance();

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
// TEST 6: Production fixture cleans up container on startup failure and preserves existing Redis
// =============================================================================
await runTest(
  "ISOLATION-06: Production fixture stops and removes container on port discovery failure and normal teardown works",
  async () => {
    // 1. Verify container from Test 5 was stopped on normal completion
    assert.ok(recordedContainerName, "Recorded container name from Test 5 must exist");
    const checkRunningNormal = execSync(
      `docker ps -q -f name=${recordedContainerName}`,
      { stdio: "pipe" },
    ).toString().trim();
    assert.equal(
      checkRunningNormal,
      "",
      "Dedicated test container must be stopped after close()",
    );

    // 2. Set up pre-existing data on local Redis to verify no fallback or corruption
    const directClient = new SimpleRedisClient(6379, "127.0.0.1", "redis_password");
    await directClient.connect();

    const canaryKey = "swyra:canary:portfail:test";
    const canaryVal = `canary_portfail_${Date.now()}`;
    await directClient.sendCommand(["SET", canaryKey, canaryVal]);

    const targetContainerName = `swyra-test-redis-portfail-${Date.now()}`;
    let createdContainerName: string | null = null;

    try {
      // 3. Call production fixture with failure injected after container creation during port discovery
      await assert.rejects(
        createRealRedisServer({
          containerName: targetContainerName,
          simulatePortDiscoveryFailure: true,
          onContainerCreated: (name) => {
            createdContainerName = name;
          },
        }),
        (err: any) => {
          // Verify it reports failure
          assert.ok(
            err.message.includes("[SECURITY_VIOLATION]"),
            "Fixture must report security violation failure",
          );
          assert.ok(
            err.message.includes("Fallback to existing instances is disallowed"),
            "Fixture must refuse fallback to existing instances",
          );
          return true;
        },
        "Fixture must fail closed when port discovery fails after container creation",
      );

      assert.equal(
        createdContainerName,
        targetContainerName,
        "Container was successfully created before port discovery failed",
      );

      // 4. Verify container it started is stopped and removed
      const runningStatus = execSync(
        `docker ps -q -f name=${targetContainerName}`,
        { stdio: "pipe" },
      ).toString().trim();
      assert.equal(
        runningStatus,
        "",
        "Container started by fixture must not be running after startup failure",
      );

      const allStatus = execSync(
        `docker ps -a -q -f name=${targetContainerName}`,
        { stdio: "pipe" },
      ).toString().trim();
      assert.equal(
        allStatus,
        "",
        "Container started by fixture must be removed after startup failure",
      );

      // 5. Verify it does not connect to, alter, or flush existing Redis instance
      const canaryRead = await directClient.sendCommand(["GET", canaryKey]);
      assert.equal(
        canaryRead,
        canaryVal,
        "Pre-existing data on local Redis survived untouched",
      );

      // 6. Verify normal fixture startup and teardown still work
      const normalFixture = await createRealRedisServer();
      try {
        assert.equal(normalFixture.isRealRedis, true, "Normal startup produces real Redis");
        assert.equal(normalFixture.isDedicated, true, "Normal startup is dedicated");
        assert.ok(normalFixture.dedicatedContainer, "Normal container name exists");
        await normalFixture.set("test:subsequent:lifecycle", "verified");
        assert.equal(await normalFixture.get("test:subsequent:lifecycle"), "verified");
        await normalFixture.clear();
        assert.equal(await normalFixture.get("test:subsequent:lifecycle"), null);
      } finally {
        const normalContainerName = normalFixture.dedicatedContainer!;
        await normalFixture.close();
        const normalCheck = execSync(
          `docker ps -a -q -f name=${normalContainerName}`,
          { stdio: "pipe" },
        ).toString().trim();
        assert.equal(
          normalCheck,
          "",
          "Subsequent normal container stopped and removed on close()",
        );
      }
    } finally {
      await directClient.sendCommand(["DEL", canaryKey]);
      directClient.close();
    }
  },
);

cleanupSimulatedContainer();

console.log("\n================================================================");
console.log(`  REDIS TEST ISOLATION SUITE: ${passed} passed, ${failed} failed`);
console.log("================================================================\n");

if (failed > 0) {
  process.exit(1);
}

