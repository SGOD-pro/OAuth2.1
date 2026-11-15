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
        return new Response(JSON.stringify(dataA), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-Total-Count": "1",
            "X-Page": "1",
            "X-Limit": "10",
            "X-Total-Pages": "1",
          },
        });
      }
      if (urlStr.includes("action=admin_login")) {
        return new Promise<Response>((resolve) => {
          resolveFetchB = resolve;
        });
      }
      return new Response("[]", { status: 200 });
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
      resolveFetchB!(
        new Response(JSON.stringify(dataB), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-Total-Count": "1",
            "X-Page": "1",
            "X-Limit": "10",
            "X-Total-Pages": "1",
          },
        })
      );
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
        return new Response(JSON.stringify(dataA), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-Total-Count": "1",
            "X-Page": "1",
            "X-Limit": "10",
            "X-Total-Pages": "1",
          },
        });
      }
      if (urlStr.includes("search=bob")) {
        return new Promise<Response>((_, reject) => {
          rejectFetchB = reject;
        });
      }
      return new Response("[]", { status: 200 });
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
// TEST 3: In-flight Request Deduplication
// --------------------------------------------------------------------------
await runTest(
  "RACE-3: Identical concurrent in-flight queries are deduplicated to a single HTTP request",
  async () => {
    _resetAdminLogsCacheForTesting();

    const originalFetch = globalThis.fetch;
    const query = { page: 1, limit: 20, outcome: "failure" };
    const mockData = [{ userId: "u3", action: "sign_in", outcome: "failure", createdAt: new Date().toISOString() }];

    let fetchCount = 0;
    globalThis.fetch = (async (url: any) => {
      fetchCount++;
      await new Promise((r) => setTimeout(r, 20));
      return new Response(JSON.stringify(mockData), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "X-Total-Count": "1",
          "X-Page": "1",
          "X-Limit": "20",
          "X-Total-Pages": "1",
        },
      });
    }) as any;

    try {
      // Dispatch 3 concurrent calls for the exact same query
      await Promise.all([
        useAdminStore.getState().fetchLogs(query),
        useAdminStore.getState().fetchLogs(query),
        useAdminStore.getState().fetchLogs(query),
      ]);

      assert.equal(fetchCount, 1, "Only 1 HTTP network request must be made for concurrent identical queries");
      const state = useAdminStore.getState().logs;
      assert.deepEqual(state.data, mockData, "Store must be populated with result");
      assert.equal(state.loading, false);
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

      const makeRes = (data: any, total: string) =>
        new Response(JSON.stringify(data), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-Total-Count": total,
            "X-Page": "1",
            "X-Limit": "10",
            "X-Total-Pages": "1",
          },
        });

      // Resolve in out-of-order sequence: Q3 first, then Q1, then Q2
      resolvers["q3"](makeRes(data3, "3"));
      await p3;
      assert.deepEqual(useAdminStore.getState().logs.data, data3, "Store must display Q3 data");

      resolvers["q1"](makeRes(data1, "1"));
      await p1;
      assert.deepEqual(useAdminStore.getState().logs.data, data3, "Q1 resolution must not overwrite Q3");

      resolvers["q2"](makeRes(data2, "2"));
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
      return new Response(JSON.stringify(currentData), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "X-Total-Count": String(currentData.length),
          "X-Page": "1",
          "X-Limit": "10",
          "X-Total-Pages": "1",
        },
      });
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

console.log("\n================================================================");
console.log(`  ADMIN STORE RACE SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
