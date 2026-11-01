import http from "node:http";

export interface MockRedisServerInstance {
  server: http.Server;
  url: string;
  port: number;
  token: string;
  simulateOutage: () => void;
  simulateRecovery: () => void;
  get: (key: string) => any;
  set: (key: string, value: any, ttlSeconds?: number) => void;
  delete: (key: string) => boolean;
  has: (key: string) => boolean;
  clear: () => void;
  close: () => Promise<void>;
}

export function createMockRedisServer(): Promise<MockRedisServerInstance> {
  return new Promise((resolve, reject) => {
    const store = new Map<string, { value: any; expiresAt?: number }>();
    let isOutage = false;

    function isExpired(entry: { value: any; expiresAt?: number }): boolean {
      if (!entry.expiresAt) return false;
      return Date.now() > entry.expiresAt;
    }

    const server = http.createServer((req, res) => {
      if (isOutage) {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Service Unavailable (Simulated Redis Outage)" }));
        return;
      }

      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        try {
          let commands: any[][] = [];
          if (req.url === "/pipeline") {
            commands = JSON.parse(body);
          } else {
            // Single command endpoint: POST / with body ["OP", ...args]
            commands = [JSON.parse(body)];
          }

          const results = commands.map((cmd) => {
            const [op, ...args] = cmd;
            const lower = String(op).toLowerCase();

            if (lower === "set") {
              const [key, value, ...optArgs] = args;
              let ttlSeconds: number | undefined;
              for (let i = 0; i < optArgs.length; i++) {
                if (String(optArgs[i]).toLowerCase() === "ex" && optArgs[i + 1] !== undefined) {
                  ttlSeconds = Number(optArgs[i + 1]);
                  break;
                }
              }
              store.set(key, {
                value,
                expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined,
              });
              return { result: "OK" };
            }

            if (lower === "get") {
              const [key] = args;
              const entry = store.get(key);
              if (!entry || isExpired(entry)) {
                if (entry) store.delete(key);
                return { result: null };
              }
              return { result: entry.value };
            }

            if (lower === "del") {
              let deletedCount = 0;
              for (const k of args) {
                if (store.delete(k)) deletedCount++;
              }
              return { result: deletedCount };
            }

            if (lower === "hset") {
              const [key, ...rest] = args;
              let entry = store.get(key);
              if (!entry || isExpired(entry) || !(entry.value instanceof Map)) {
                entry = { value: new Map<string, any>() };
                store.set(key, entry);
              }
              const map = entry.value as Map<string, any>;
              if (rest.length === 1 && typeof rest[0] === "object" && rest[0] !== null) {
                for (const [f, v] of Object.entries(rest[0])) {
                  map.set(f, v);
                }
              } else {
                for (let i = 0; i < rest.length; i += 2) {
                  if (rest[i] !== undefined && rest[i + 1] !== undefined) {
                    map.set(String(rest[i]), rest[i + 1]);
                  }
                }
              }
              return { result: 1 };
            }

            if (lower === "hget") {
              const [key, field] = args;
              const entry = store.get(key);
              if (!entry || isExpired(entry) || !(entry.value instanceof Map)) {
                return { result: null };
              }
              const val = (entry.value as Map<string, any>).get(field);
              return { result: val !== undefined ? String(val) : null };
            }

            if (lower === "hdel") {
              const [key, ...fields] = args;
              const entry = store.get(key);
              if (!entry || isExpired(entry) || !(entry.value instanceof Map)) {
                return { result: 0 };
              }
              const map = entry.value as Map<string, any>;
              let deletedCount = 0;
              for (const f of fields) {
                if (map.delete(f)) deletedCount++;
              }
              return { result: deletedCount };
            }

            if (lower === "eval") {
              const [_script, numKeysRaw, ...rest] = args;
              const scriptStr = String(_script);
              const numKeys = Number(numKeysRaw) || 0;
              const keys = rest.slice(0, numKeys);
              const scriptArgs = rest.slice(numKeys);

              // 0. Atomic Lua Read Script
              if (scriptStr.includes("LUA_GET_ORIGIN_CACHE")) {
                const originKey = keys[0];
                const verKey = keys[1];
                const invKey = keys[2];
                const globalInvKey = keys[3];

                const originEntry = store.get(originKey);
                if (!originEntry || isExpired(originEntry)) {
                  if (originEntry) store.delete(originKey);
                  return { result: null };
                }

                const verEntry = store.get(verKey);
                const ver = verEntry && !isExpired(verEntry) ? Number(verEntry.value) : 0;

                const invEntry = store.get(invKey);
                const inv = invEntry && !isExpired(invEntry) ? Number(invEntry.value) : 0;

                const globalInvEntry = store.get(globalInvKey);
                const globalInv = globalInvEntry && !isExpired(globalInvEntry) ? Number(globalInvEntry.value) : 0;

                if (globalInv > 0 && ver <= globalInv) {
                  return { result: null };
                }
                if (inv > 0 && ver <= inv) {
                  return { result: null };
                }

                const rawVal = originEntry.value;
                const resultVal =
                  rawVal === true || rawVal === "1" || rawVal === 1 || rawVal === "true"
                    ? "1"
                    : rawVal === false || rawVal === "0" || rawVal === 0 || rawVal === "false"
                    ? "0"
                    : String(rawVal);
                return { result: resultVal };
              }

              // 0a. Atomic Lua Set Lease Script
              if (scriptStr.includes("LUA_SET_ORIGIN_LEASE")) {
                const leaseKey = keys[0];
                const leasesKey = keys[1] || "swyra:origin:leases";
                const origin = scriptArgs[0];
                const version = Number(scriptArgs[1]);
                const ttlSeconds = Number(scriptArgs[2]) || 60;
                const containerTtl = Number(scriptArgs[3]) || 3600;

                store.set(leaseKey, {
                  value: version,
                  expiresAt: Date.now() + ttlSeconds * 1000,
                });

                let entry = store.get(leasesKey);
                if (!entry || isExpired(entry) || !(entry.value instanceof Map)) {
                  entry = { value: new Map<string, any>() };
                  store.set(leasesKey, entry);
                }
                (entry.value as Map<string, any>).set(origin, version);
                entry.expiresAt = Date.now() + containerTtl * 1000;
                return { result: 1 };
              }

              // 0b. Atomic Lua Cleanup Abandoned Leases Script
              if (scriptStr.includes("LUA_CLEANUP_ABANDONED_LEASES")) {
                const leasesKey = keys[0] || "swyra:origin:leases";
                const count = Number(scriptArgs[1]) || 50;

                const entry = store.get(leasesKey);
                if (!entry || isExpired(entry) || !(entry.value instanceof Map)) {
                  return { result: ["0", 0] };
                }

                const map = entry.value as Map<string, any>;
                let cleaned = 0;
                let checked = 0;
                for (const [origin, version] of Array.from(map.entries())) {
                  if (checked >= count) break;
                  checked++;

                  const leaseKey = `swyra:origin:lease:${origin}`;
                  const leaseEntry = store.get(leaseKey);
                  const active = leaseEntry && !isExpired(leaseEntry);
                  const activeVer = active ? Number(leaseEntry.value) : undefined;

                  if (!active || activeVer !== Number(version)) {
                    if (map.get(origin) === version) {
                      map.delete(origin);
                      cleaned++;
                    }
                  }
                }
                return { result: ["0", cleaned] };
              }

              // 1. Atomic Lua Invalidation Script (Per-Origin)
              if (scriptStr.includes("LUA_INVALIDATE_ORIGIN_CACHE") || scriptStr.includes("swyra:origin:inv:\" .. origin")) {
                const newVersion = Number(scriptArgs[0]) || 0;
                const ttlSeconds = Number(scriptArgs[1]) || 0;
                for (const origin of keys) {
                  const invKey = `swyra:origin:inv:${origin}`;
                  const currentInv = store.get(invKey);
                  const curNum = currentInv && !isExpired(currentInv) ? Number(currentInv.value) : 0;
                  if (newVersion > curNum || !currentInv || isExpired(currentInv)) {
                    store.set(invKey, {
                      value: newVersion,
                      expiresAt: ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : undefined,
                    });
                  } else if (newVersion === curNum && currentInv && ttlSeconds > 0) {
                    const currentExpires = currentInv.expiresAt || 0;
                    const newExpires = Date.now() + ttlSeconds * 1000;
                    if (newExpires > currentExpires) {
                      currentInv.expiresAt = newExpires;
                    }
                  }
                  store.delete(`swyra:origin:${origin}`);
                  store.delete(`swyra:origin:ver:${origin}`);
                  store.delete(`swyra:origin:lease:${origin}`);
                  const leasesEntry = store.get("swyra:origin:leases");
                  if (leasesEntry && leasesEntry.value instanceof Map) {
                    leasesEntry.value.delete(origin);
                  }
                }
                return { result: 1 };
              }

              // 1b. Atomic Lua Global Invalidation Script
              if (scriptStr.includes("LUA_INVALIDATE_GLOBAL_ORIGIN_CACHE")) {
                const globalKey = keys[0] || "swyra:inv:global";
                const leasesKey = keys[1] || "swyra:origin:leases";
                const newVersion = Number(scriptArgs[0]) || 0;
                const ttlSeconds = Number(scriptArgs[1]) || 0;
                const currentGlobal = store.get(globalKey);
                const curNum = currentGlobal && !isExpired(currentGlobal) ? Number(currentGlobal.value) : 0;
                if (newVersion > curNum || !currentGlobal || isExpired(currentGlobal)) {
                  store.set(globalKey, {
                    value: newVersion,
                    expiresAt: ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : undefined,
                  });
                } else if (newVersion === curNum && currentGlobal && ttlSeconds > 0) {
                  const currentExpires = currentGlobal.expiresAt || 0;
                  const newExpires = Date.now() + ttlSeconds * 1000;
                  if (newExpires > currentExpires) {
                    currentGlobal.expiresAt = newExpires;
                  }
                }
                store.delete(leasesKey);
                return { result: 1 };
              }

              // 2. Conditional Cache Write Script
              const originKey = keys[0];
              const invKey = keys[1];
              const globalInvKey = keys[2];
              const verKey = keys[3];
              const leaseKey = keys[4];
              const leasesKey = keys[5];
              const allowed = scriptArgs[0];
              const startTime = Number(scriptArgs[1]) || 0;
              const ttlSeconds = Number(scriptArgs[2]) || 300;
              const origin = scriptArgs[3];

              if (startTime > 0) {
                if (!leaseKey || !leasesKey || !origin) {
                  return { result: 0 };
                }
                const leaseEntry = store.get(leaseKey);
                if (!leaseEntry || isExpired(leaseEntry) || Number(leaseEntry.value) !== startTime) {
                  return { result: 0 };
                }
                const leasesEntry = store.get(leasesKey);
                if (!leasesEntry || isExpired(leasesEntry) || !(leasesEntry.value instanceof Map)) {
                  return { result: 0 };
                }
                const val = leasesEntry.value.get(origin);
                if (val === undefined || Number(val) !== startTime) {
                  return { result: 0 };
                }
                if (verKey) {
                  const verEntry = store.get(verKey);
                  if (verEntry && !isExpired(verEntry) && Number(verEntry.value) >= startTime) {
                    return { result: 0 };
                  }
                }
                const invEntry = store.get(invKey);
                if (invEntry && !isExpired(invEntry) && Number(invEntry.value) >= startTime) {
                  return { result: 0 };
                }
                const globalInvEntry = store.get(globalInvKey);
                if (globalInvEntry && !isExpired(globalInvEntry) && Number(globalInvEntry.value) >= startTime) {
                  return { result: 0 };
                }
              }

              store.set(originKey, {
                value: allowed === "1" || allowed === 1 || allowed === true,
                expiresAt: Date.now() + ttlSeconds * 1000,
              });
              if (verKey && startTime > 0) {
                store.set(verKey, {
                  value: startTime,
                  expiresAt: Date.now() + ttlSeconds * 1000,
                });
              }
              if (leaseKey) {
                store.delete(leaseKey);
              }
              if (leasesKey && origin) {
                const leasesEntry = store.get(leasesKey);
                if (leasesEntry && leasesEntry.value instanceof Map) {
                  leasesEntry.value.delete(origin);
                }
              }
              return { result: 1 };
            }

            if (lower === "scan") {
              const now = Date.now();
              let matchPattern: string | null = null;
              for (let i = 1; i < args.length; i++) {
                if (String(args[i]).toLowerCase() === "match" && args[i + 1]) {
                  matchPattern = String(args[i + 1]);
                  break;
                }
              }

              let regex: RegExp | null = null;
              if (matchPattern) {
                const escaped = matchPattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
                regex = new RegExp(`^${escaped}$`);
              }

              const validKeys: string[] = [];
              for (const [k, v] of store.entries()) {
                if (isExpired(v)) {
                  store.delete(k);
                } else if (!regex || regex.test(k)) {
                  validKeys.push(k);
                }
              }
              // Format: [nextCursor, keys]
              return { result: ["0", validKeys] };
            }

            if (lower === "incr") {
              const [key] = args;
              const entry = store.get(key);
              let currentVal = 0;
              if (entry && !isExpired(entry)) {
                currentVal = Number(entry.value) || 0;
              }
              const nextVal = currentVal + 1;
              store.set(key, { value: nextVal });
              return { result: nextVal };
            }

            return { result: null };
          });

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(req.url === "/pipeline" ? results : results[0]));
        } catch (err: any) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: err?.message || String(err) }));
        }
      });
    });

    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("Failed to get server address"));
        return;
      }
      const port = addr.port;
      const url = `http://127.0.0.1:${port}`;
      const token = "mock-redis-test-token";

      resolve({
        server,
        url,
        port,
        token,
        simulateOutage: () => {
          isOutage = true;
        },
        simulateRecovery: () => {
          isOutage = false;
        },
        get: (key: string) => {
          const entry = store.get(key);
          if (!entry || isExpired(entry)) return null;
          return entry.value;
        },
        set: (key: string, value: any, ttlSeconds?: number) => {
          if (value === null || value === undefined) {
            store.delete(key);
            return;
          }
          store.set(key, {
            value,
            expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined,
          });
        },
        delete: (key: string) => store.delete(key),
        has: (key: string) => {
          const entry = store.get(key);
          if (!entry || isExpired(entry)) return false;
          return true;
        },
        clear: () => store.clear(),
        close: () =>
          new Promise<void>((res) => {
            if (typeof (server as any).closeAllConnections === "function") {
              (server as any).closeAllConnections();
            }
            server.close(() => res());
          }),
      });
    });
  });
}
