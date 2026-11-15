import assert from "node:assert/strict";

console.log("================================================================");
console.log("  SWYRA AUTH -- ADMIN STORE CACHE RACE & CONCURRENCY UNIT SUITE");
console.log("================================================================\n");

// Import the actual store implementation from frontend
const { useAdminStore, _resetAdminLogsCacheForTesting } = await import("../../../frontend/lib/adminStore.ts");

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

function makeResponse(data: any, totalCount = 1, page = 1, limit = 10, totalPages = 1): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "X-Total-Count": String(totalCount),
      "X-Page": String(page),
      "X-Limit": String(limit),
      "X-Total-Pages": String(totalPages),
    },
  });
}

// --------------------------------------------------------------------------
// TEST 1: Cache Race - Returning to cached Query A ignores delayed Query B
// --------------------------------------------------------------------------
await runTest(
  "RACE-1: Returning to cached query A ignores delayed query B when B resolves later",
  async () => {
    _resetAdminLogsCacheForTesting();

    const originalFetch = globalThis.fetch;
    const queryA = { page: 1, limit: 10, action: "sign_in" };
    const queryB = { page: 1, limit: 10, action: "admin_login" };

    const dataA = [{ userId: "u1", action: "sign_in", createdAt: new Date().toISOString() }];
    const dataB = [{ userId: "u2", action: "admin_login", createdAt: new Date().toISOString() }];

    let resolveFetchB: ((res: Response) => void) | null = null;

    globalThis.fetch = (async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes("action=sign_in")) {
        return makeResponse(dataA, 1, 1, 10, 1);
      }
      if (urlStr.includes("action=admin_login")) {
        return new Promise<Response>((resolve) => {
          resolveFetchB = resolve;
        });
      }
      return makeResponse([]);
    }) as any;

    try {
      // 1. Load Query A successfully
      await useAdminStore.getState().fetchLogs(queryA);
      const stateAfterA = useAdminStore.getState().logs;
      assert.equal(stateAfterA.loading, false);
      assert.deepEqual(stateAfterA.data, dataA);
      const keyA = stateAfterA.activeQueryKey;

      // 2. Start Query B (delayed response)
      const fetchBPromise = useAdminStore.getState().fetchLogs(queryB);
      assert.equal(useAdminStore.getState().logs.loading, true);

      // 3. Return to cached Query A while Query B is still pending
      await useAdminStore.getState().fetchLogs(queryA);
      const stateAfterReturnA = useAdminStore.getState().logs;
      assert.equal(stateAfterReturnA.loading, false, "Loading must be false upon returning to cached query");
      assert.deepEqual(stateAfterReturnA.data, dataA, "Must immediately display cached Query A data");
      assert.equal(stateAfterReturnA.activeQueryKey, keyA, "Active query key must be Query A");

      // 4. Resolve delayed Query B
      assert.ok(resolveFetchB, "Fetch B must have been initiated");
      resolveFetchB!(makeResponse(dataB, 1, 1, 10, 1));
      await fetchBPromise;

      // 5. Assert: Obsolete Query B response did NOT overwrite Query A
      const finalState = useAdminStore.getState().logs;
      assert.equal(finalState.loading, false, "Loading must remain false");
      assert.equal(finalState.error, null, "Error must remain null");
      assert.deepEqual(finalState.data, dataA, "Query A data must NOT be replaced by obsolete Query B response");
      assert.equal(finalState.activeQueryKey, keyA, "Active query must remain Query A");
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
);

// --------------------------------------------------------------------------
// TEST 2: Delayed Query Rejection does not corrupt active cached query
// --------------------------------------------------------------------------
await runTest(
  "RACE-2: Rejection of obsolete in-flight query B does not set error on active cached query A",
  async () => {
    _resetAdminLogsCacheForTesting();

    const originalFetch = globalThis.fetch;
    const queryA = { page: 1, limit: 10, search: "alice" };
    const queryB = { page: 1, limit: 10, search: "bob" };

    const dataA = [{ userId: "u1", action: "sign_in", createdAt: new Date().toISOString() }];
    let rejectFetchB: ((err: Error) => void) | null = null;

    globalThis.fetch = (async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes("search=alice")) {
        return makeResponse(dataA, 1, 1, 10, 1);
      }
      if (urlStr.includes("search=bob")) {
        return new Promise<Response>((_, reject) => {
          rejectFetchB = reject;
        });
      }
      return makeResponse([]);
    }) as any;

    try {
      // 1. Load Query A
      await useAdminStore.getState().fetchLogs(queryA);
      assert.deepEqual(useAdminStore.getState().logs.data, dataA);

      // 2. Start Query B (delayed)
      const fetchBPromise = useAdminStore.getState().fetchLogs(queryB);

      // 3. Return to cached Query A
      await useAdminStore.getState().fetchLogs(queryA);

      // 4. Reject delayed Query B with network error
      assert.ok(rejectFetchB, "Fetch B must have been initiated");
      rejectFetchB!(new Error("Network connection lost"));
      await fetchBPromise;

      // 5. Assert: Query A state remains intact and error is not set
      const state = useAdminStore.getState().logs;
      assert.equal(state.error, null, "Error from obsolete query must NOT be applied to active state");
      assert.equal(state.loading, false, "Loading must remain false");
      assert.deepEqual(state.data, dataA, "Data must remain Query A");
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
);

// --------------------------------------------------------------------------
// TEST 3: In-flight Request Deduplication without sleeps
// --------------------------------------------------------------------------
await runTest(
  "RACE-3: Identical concurrent in-flight queries are deduplicated to a single HTTP request",
  async () => {
    _resetAdminLogsCacheForTesting();

    const originalFetch = globalThis.fetch;
    const query = { page: 1, limit: 20, outcome: "failure" };
    const mockData = [{ userId: "u3", action: "sign_in", outcome: "failure", createdAt: new Date().toISOString() }];

    let fetchCount = 0;
    let resolveControlledFetch: ((res: Response) => void) | null = null;

    globalThis.fetch = (async () => {
      fetchCount++;
      return new Promise<Response>((resolve) => {
        resolveControlledFetch = resolve;
      });
    }) as any;

    try {
      // Dispatch 3 concurrent calls for the exact same query
      const p1 = useAdminStore.getState().fetchLogs(query);
      const p2 = useAdminStore.getState().fetchLogs(query);
      const p3 = useAdminStore.getState().fetchLogs(query);

      // Verify that fetch was invoked exactly once before resolution
      assert.equal(fetchCount, 1, "Only 1 HTTP network request must be made for concurrent identical queries");
      assert.ok(resolveControlledFetch, "Controlled fetch resolver must be assigned");

      // Resolve the single controlled request
      resolveControlledFetch!(makeResponse(mockData, 1, 1, 20, 1));
      await Promise.all([p1, p2, p3]);

      const state = useAdminStore.getState().logs;
      assert.deepEqual(state.data, mockData, "Store must be populated with result");
      assert.equal(state.loading, false);
      assert.equal(fetchCount, 1, "Fetch count must remain 1 after completion");
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
);

// --------------------------------------------------------------------------
// TEST 4: Rapid Overlapping Queries with Out-of-Order Resolution
// --------------------------------------------------------------------------
await runTest(
  "RACE-4: Out-of-order resolution of rapid sequential queries only applies the latest requested query",
  async () => {
    _resetAdminLogsCacheForTesting();

    const originalFetch = globalThis.fetch;
    const query1 = { page: 1, limit: 10, search: "q1" };
    const query2 = { page: 1, limit: 10, search: "q2" };
    const query3 = { page: 1, limit: 10, search: "q3" };

    const data1 = [{ userId: "1", action: "q1", createdAt: new Date().toISOString() }];
    const data2 = [{ userId: "2", action: "q2", createdAt: new Date().toISOString() }];
    const data3 = [{ userId: "3", action: "q3", createdAt: new Date().toISOString() }];

    const resolvers: Record<string, (res: Response) => void> = {};

    globalThis.fetch = (async (url: any) => {
      const urlStr = String(url);
      const match = urlStr.match(/search=(q\d)/);
      const qKey = match ? match[1] : "default";
      return new Promise<Response>((resolve) => {
        resolvers[qKey] = resolve;
      });
    }) as any;

    try {
      // Fire Q1, Q2, Q3 sequentially before any resolve
      const p1 = useAdminStore.getState().fetchLogs(query1);
      const p2 = useAdminStore.getState().fetchLogs(query2);
      const p3 = useAdminStore.getState().fetchLogs(query3);

      // Resolve in out-of-order sequence: Q3 first, then Q1, then Q2
      resolvers["q3"](makeResponse(data3, 3, 1, 10, 1));
      await p3;
      assert.deepEqual(useAdminStore.getState().logs.data, data3, "Store must display Q3 data");

      resolvers["q1"](makeResponse(data1, 1, 1, 10, 1));
      await p1;
      assert.deepEqual(useAdminStore.getState().logs.data, data3, "Q1 resolution must not overwrite Q3");

      resolvers["q2"](makeResponse(data2, 2, 1, 10, 1));
      await p2;
      assert.deepEqual(useAdminStore.getState().logs.data, data3, "Q2 resolution must not overwrite Q3");

      const finalState = useAdminStore.getState().logs;
      assert.deepEqual(finalState.data, data3);
      assert.equal(finalState.totalCount, 3);
      assert.equal(finalState.loading, false);
      assert.equal(finalState.error, null);
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
);

// --------------------------------------------------------------------------
// TEST 5: Force Refresh Bypasses Cache
// --------------------------------------------------------------------------
await runTest(
  "RACE-5: Force refresh (force=true) bypasses cache and updates with fresh data",
  async () => {
    _resetAdminLogsCacheForTesting();

    const originalFetch = globalThis.fetch;
    const query = { page: 1, limit: 10, search: "refresh_test" };

    const initialData = [{ userId: "init", action: "sign_in", createdAt: new Date().toISOString() }];
    const updatedData = [
      { userId: "init", action: "sign_in", createdAt: new Date().toISOString() },
      { userId: "new", action: "sign_in", createdAt: new Date().toISOString() },
    ];

    let fetchCount = 0;
    globalThis.fetch = (async () => {
      fetchCount++;
      const currentData = fetchCount === 1 ? initialData : updatedData;
      return makeResponse(currentData, currentData.length, 1, 10, 1);
    }) as any;

    try {
      // 1. Initial fetch
      await useAdminStore.getState().fetchLogs(query);
      assert.equal(fetchCount, 1);
      assert.equal(useAdminStore.getState().logs.totalCount, 1);

      // 2. Fetch without force (cache hit)
      await useAdminStore.getState().fetchLogs(query, false);
      assert.equal(fetchCount, 1, "Unforced call must hit cache and avoid network");

      // 3. Fetch with force=true (cache bypass)
      await useAdminStore.getState().fetchLogs(query, true);
      assert.equal(fetchCount, 2, "Forced call must hit network");
      assert.equal(useAdminStore.getState().logs.totalCount, 2, "Store must reflect fresh data");
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
);

// --------------------------------------------------------------------------
// TEST 6: Old request finishes after a successful forced refresh
// Next cache hit must still return fresh data
// --------------------------------------------------------------------------
await runTest(
  "RACE-6: Old request finishes after successful forced refresh; next cache hit returns fresh data",
  async () => {
    _resetAdminLogsCacheForTesting();

    const originalFetch = globalThis.fetch;
    const query = { page: 1, limit: 10, search: "forced_race_test" };

    const oldData = [{ userId: "old", action: "sign_in", createdAt: new Date().toISOString() }];
    const freshData = [{ userId: "fresh", action: "sign_in", createdAt: new Date().toISOString() }];

    let resolveReqA: ((res: Response) => void) | null = null;
    let resolveReqB: ((res: Response) => void) | null = null;
    let fetchCount = 0;

    globalThis.fetch = (async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return new Promise<Response>((resolve) => {
          resolveReqA = resolve;
        });
      }
      if (fetchCount === 2) {
        return new Promise<Response>((resolve) => {
          resolveReqB = resolve;
        });
      }
      return makeResponse([]);
    }) as any;

    try {
      // 1. Start unforced request A (delayed)
      const promiseA = useAdminStore.getState().fetchLogs(query, false);

      // 2. Start forced refresh request B for the same query (delayed)
      const promiseB = useAdminStore.getState().fetchLogs(query, true);
      assert.equal(fetchCount, 2, "Forced refresh must initiate a second network request");

      // 3. Resolve forced refresh B with fresh data
      assert.ok(resolveReqB, "Resolver for request B must exist");
      resolveReqB!(makeResponse(freshData, 1, 1, 10, 1));
      await promiseB;

      // Assert store displays fresh data
      assert.deepEqual(useAdminStore.getState().logs.data, freshData, "Store must display fresh data from refresh");

      // 4. Resolve older request A with stale data
      assert.ok(resolveReqA, "Resolver for request A must exist");
      resolveReqA!(makeResponse(oldData, 1, 1, 10, 1));
      await promiseA;

      // Assert visible store was NOT replaced by stale data
      assert.deepEqual(useAdminStore.getState().logs.data, freshData, "Store must remain on fresh data");

      // 5. Run a third unforced call for the same query (should hit cache)
      await useAdminStore.getState().fetchLogs(query, false);
      assert.equal(fetchCount, 2, "Third unforced call must hit cache and make no new network request");
      assert.deepEqual(
        useAdminStore.getState().logs.data,
        freshData,
        "Subsequent cache hit must still return fresh data, not stale data from old request"
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
);

// --------------------------------------------------------------------------
// TEST 7: Old request finishes while a newer request remains pending
// A third identical unforced call must reuse the pending newer request
// --------------------------------------------------------------------------
await runTest(
  "RACE-7: Old request finishes while newer request is pending; third unforced call reuses pending newer request",
  async () => {
    _resetAdminLogsCacheForTesting();

    const originalFetch = globalThis.fetch;
    const query = { page: 1, limit: 10, search: "reuse_pending_newer" };

    const oldData = [{ userId: "reqA", action: "sign_in", createdAt: new Date().toISOString() }];
    const newerData = [{ userId: "reqB", action: "sign_in", createdAt: new Date().toISOString() }];

    let resolveReqA: ((res: Response) => void) | null = null;
    let resolveReqB: ((res: Response) => void) | null = null;
    let fetchCount = 0;

    globalThis.fetch = (async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return new Promise<Response>((resolve) => {
          resolveReqA = resolve;
        });
      }
      if (fetchCount === 2) {
        return new Promise<Response>((resolve) => {
          resolveReqB = resolve;
        });
      }
      return makeResponse([]);
    }) as any;

    try {
      // 1. Start unforced request A (delayed)
      const promiseA = useAdminStore.getState().fetchLogs(query, false);

      // 2. Start forced refresh request B for the same query (delayed)
      const promiseB = useAdminStore.getState().fetchLogs(query, true);
      assert.equal(fetchCount, 2, "Forced refresh must initiate request B");

      // 3. Resolve request A while request B is STILL pending
      assert.ok(resolveReqA, "Resolver for request A must exist");
      resolveReqA!(makeResponse(oldData, 1, 1, 10, 1));
      await promiseA;

      // 4. Request C is started without force while request B is still in-flight
      const promiseC = useAdminStore.getState().fetchLogs(query, false);
      assert.equal(fetchCount, 2, "Request C must reuse pending request B and not spawn a 3rd network call");

      // 5. Now resolve request B
      assert.ok(resolveReqB, "Resolver for request B must exist");
      resolveReqB!(makeResponse(newerData, 1, 1, 10, 1));
      await Promise.all([promiseB, promiseC]);

      // 6. Assert store shows newerData
      const finalState = useAdminStore.getState().logs;
      assert.deepEqual(finalState.data, newerData, "Store must display newer data");
      assert.equal(fetchCount, 2, "Total network requests must remain 2");
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
);

// --------------------------------------------------------------------------
// TEST 8: Multiple forced refreshes resolve out of order
// Only the latest generation may update that query's cache
// --------------------------------------------------------------------------
await runTest(
  "RACE-8: Multiple forced refreshes resolve out of order; only latest generation updates query cache",
  async () => {
    _resetAdminLogsCacheForTesting();

    const originalFetch = globalThis.fetch;
    const query = { page: 1, limit: 10, search: "multi_gen" };

    const data1 = [{ userId: "gen1", action: "sign_in", createdAt: new Date().toISOString() }];
    const data2 = [{ userId: "gen2", action: "sign_in", createdAt: new Date().toISOString() }];
    const data3 = [{ userId: "gen3", action: "sign_in", createdAt: new Date().toISOString() }];

    const resolvers: Record<number, (res: Response) => void> = {};
    let fetchCount = 0;

    globalThis.fetch = (async () => {
      fetchCount++;
      const currentGen = fetchCount;
      return new Promise<Response>((resolve) => {
        resolvers[currentGen] = resolve;
      });
    }) as any;

    try {
      // 1. Fire generation 1 (unforced)
      const p1 = useAdminStore.getState().fetchLogs(query, false);

      // 2. Fire generation 2 (forced)
      const p2 = useAdminStore.getState().fetchLogs(query, true);

      // 3. Fire generation 3 (forced)
      const p3 = useAdminStore.getState().fetchLogs(query, true);

      assert.equal(fetchCount, 3, "Three network requests must have been initiated");

      // 4. Resolve Generation 3 FIRST
      resolvers[3](makeResponse(data3, 1, 1, 10, 1));
      await p3;
      assert.deepEqual(useAdminStore.getState().logs.data, data3, "Store must reflect generation 3");

      // 5. Resolve Generation 1 SECOND
      resolvers[1](makeResponse(data1, 1, 1, 10, 1));
      await p1;
      assert.deepEqual(useAdminStore.getState().logs.data, data3, "Store must still reflect generation 3");

      // 6. Resolve Generation 2 THIRD
      resolvers[2](makeResponse(data2, 1, 1, 10, 1));
      await p2;
      assert.deepEqual(useAdminStore.getState().logs.data, data3, "Store must still reflect generation 3");

      // 7. Verify subsequent cache hit returns generation 3 data
      await useAdminStore.getState().fetchLogs(query, false);
      assert.equal(fetchCount, 3, "Unforced call must hit cache");
      assert.deepEqual(
        useAdminStore.getState().logs.data,
        data3,
        "Query cache must hold generation 3 data, never overwritten by delayed earlier generations"
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
);

// --------------------------------------------------------------------------
// TEST 9: Obsolete request rejection does not alter current data or error state
// --------------------------------------------------------------------------
await runTest(
  "RACE-9: Obsolete request rejection does not alter current data or error state",
  async () => {
    _resetAdminLogsCacheForTesting();

    const originalFetch = globalThis.fetch;
    const query = { page: 1, limit: 10, search: "reject_race" };

    const freshData = [{ userId: "fresh_ok", action: "sign_in", createdAt: new Date().toISOString() }];

    let rejectReqA: ((err: Error) => void) | null = null;
    let resolveReqB: ((res: Response) => void) | null = null;
    let fetchCount = 0;

    globalThis.fetch = (async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return new Promise<Response>((_, reject) => {
          rejectReqA = reject;
        });
      }
      if (fetchCount === 2) {
        return new Promise<Response>((resolve) => {
          resolveReqB = resolve;
        });
      }
      return makeResponse([]);
    }) as any;

    try {
      // 1. Request A starts (delayed)
      const promiseA = useAdminStore.getState().fetchLogs(query, false);

      // 2. Forced Request B starts (delayed)
      const promiseB = useAdminStore.getState().fetchLogs(query, true);

      // 3. Resolve Request B successfully
      assert.ok(resolveReqB, "Resolver for request B must exist");
      resolveReqB!(makeResponse(freshData, 1, 1, 10, 1));
      await promiseB;

      assert.deepEqual(useAdminStore.getState().logs.data, freshData);
      assert.equal(useAdminStore.getState().logs.error, null);

      // 4. Reject older Request A
      assert.ok(rejectReqA, "Rejector for request A must exist");
      rejectReqA!(new Error("Stale network timeout"));
      await promiseA;

      // 5. Assert: error is NOT set on the active store, and data is still freshData
      const finalState = useAdminStore.getState().logs;
      assert.equal(finalState.error, null, "Error from obsolete request must not be applied to store");
      assert.deepEqual(finalState.data, freshData, "Data must remain intact");
      assert.equal(finalState.loading, false, "Loading must remain false");
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
);

console.log("\n================================================================");
console.log(`  ADMIN STORE RACE SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
