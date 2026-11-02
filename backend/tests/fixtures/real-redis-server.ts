import http from "node:http";
import net from "node:net";
import crypto from "node:crypto";
import { execSync } from "node:child_process";

export interface RealRedisServerInstance {
  server: http.Server;
  url: string;
  port: number;
  token: string;
  isRealRedis: true;
  isDedicated: boolean;
  redisVersion: string;
  dedicatedContainer?: string | null;
  harnessRunId: string;
  simulateOutage: () => void;
  simulateRecovery: () => void;
  get: (key: string) => Promise<any>;
  set: (key: string, value: any, ttlSeconds?: number) => Promise<void>;
  delete: (key: string) => Promise<boolean>;
  has: (key: string) => Promise<boolean>;
  clear: () => Promise<void>;
  close: () => Promise<void>;
  sendCommand: (args: (string | number)[]) => Promise<any>;
}

export class SimpleRedisClient {
  port: number;
  host: string;
  password?: string;
  socket: net.Socket | null = null;
  buffer: Buffer = Buffer.alloc(0);
  pending: { resolve: (val: any) => void; reject: (err: any) => void }[] = [];

  constructor(port = 6379, host = "127.0.0.1", password: string | undefined = "redis_password") {
    this.port = port;
    this.host = host;
    this.password = password;
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = net.createConnection({ port: this.port, host: this.host }, async () => {
        if (this.password) {
          try {
            await this.sendCommand(["AUTH", this.password]);
          } catch (e) {
            return reject(e);
          }
        }
        resolve();
      });

      this.socket.on("data", (chunk) => this._onData(chunk));
      this.socket.on("error", (err) => {
        while (this.pending.length) {
          const p = this.pending.shift();
          if (p) p.reject(err);
        }
      });
    });
  }

  _encodeCommand(args: (string | number)[]): Buffer {
    let out = "*" + args.length + "\r\n";
    for (const arg of args) {
      const s = String(arg);
      out += "$" + Buffer.byteLength(s) + "\r\n" + s + "\r\n";
    }
    return Buffer.from(out);
  }

  sendCommand(args: (string | number)[]): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.socket || this.socket.destroyed) {
        return reject(new Error("Redis socket is closed"));
      }
      this.pending.push({ resolve, reject });
      this.socket.write(this._encodeCommand(args));
    });
  }

  _onData(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length > 0) {
      const res = this._parseResp(this.buffer);
      if (!res) break;
      this.buffer = this.buffer.subarray(res.bytesRead);
      const req = this.pending.shift();
      if (req) {
        if (res.isError) req.reject(new Error(res.value));
        else req.resolve(res.value);
      }
    }
  }

  _parseResp(buf: Buffer): { value: any; bytesRead: number; isError?: boolean } | null {
    if (buf.length === 0) return null;
    const type = String.fromCharCode(buf[0]);
    const idx = buf.indexOf("\r\n");
    if (idx === -1) return null;

    if (type === "+" || type === "-") {
      return {
        value: buf.subarray(1, idx).toString("utf8"),
        bytesRead: idx + 2,
        isError: type === "-",
      };
    } else if (type === ":") {
      return {
        value: Number(buf.subarray(1, idx).toString("utf8")),
        bytesRead: idx + 2,
      };
    } else if (type === "$") {
      const len = parseInt(buf.subarray(1, idx).toString("utf8"), 10);
      if (len === -1) {
        return { value: null, bytesRead: idx + 2 };
      }
      if (buf.length < idx + 2 + len + 2) return null;
      const val = buf.subarray(idx + 2, idx + 2 + len).toString("utf8");
      return { value: val, bytesRead: idx + 2 + len + 2 };
    } else if (type === "*") {
      const count = parseInt(buf.subarray(1, idx).toString("utf8"), 10);
      if (count === -1) return { value: null, bytesRead: idx + 2 };
      let offset = idx + 2;
      const arr: any[] = [];
      for (let i = 0; i < count; i++) {
        const item = this._parseResp(buf.subarray(offset));
        if (!item) return null;
        arr.push(item.value);
        offset += item.bytesRead;
      }
      return { value: arr, bytesRead: offset };
    }
    throw new Error("Unknown RESP type: " + type);
  }

  close(): void {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
  }
}

function encodeForUpstash(val: any, isBase64: boolean): any {
  if (val === null || val === undefined) return null;
  if (typeof val === "string") {
    return isBase64 ? Buffer.from(val, "utf8").toString("base64") : val;
  }
  if (Array.isArray(val)) {
    return val.map((v) => encodeForUpstash(v, isBase64));
  }
  return val;
}

export function validateLoopbackEndpoint(host: string): void {
  let hostname = host;
  try {
    if (host.includes("://")) {
      const u = new URL(host);
      hostname = u.hostname;
    }
  } catch {}
  const normalized = hostname.toLowerCase().trim();
  if (
    normalized !== "127.0.0.1" &&
    normalized !== "localhost" &&
    normalized !== "::1" &&
    normalized !== "[::1]"
  ) {
    throw new Error(
      "[SECURITY_VIOLATION] Remote or Upstash Redis endpoint is strictly forbidden in test harness. Tests must run against a local disposable instance.",
    );
  }
}

export function parseAndValidateRedisUrl(rawUrl: string): { protocol: string; host: string; port: number; password?: string } {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    throw new Error("[SECURITY_VIOLATION] Malformed Redis URL provided in environment.");
  }
  if (parsedUrl.protocol !== "redis:" && parsedUrl.protocol !== "rediss:") {
    throw new Error("[SECURITY_VIOLATION] Disallowed protocol in Redis URL. Only redis: is permitted.");
  }
  if (parsedUrl.hostname.toLowerCase().includes("upstash.io")) {
    throw new Error("[SECURITY_VIOLATION] Production Upstash endpoints are strictly forbidden in test harness.");
  }
  validateLoopbackEndpoint(parsedUrl.hostname);
  const host = parsedUrl.hostname === "localhost" ? "127.0.0.1" : parsedUrl.hostname;
  const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : 6379;
  const password = parsedUrl.password ? decodeURIComponent(parsedUrl.password) : undefined;
  return { protocol: parsedUrl.protocol, host, port, password };
}

export interface RealRedisOptions {
  host?: string;
  port?: number;
  password?: string;
  allowExisting?: boolean;
  simulateStartupFailure?: boolean;
}

export async function createRealRedisServer(
  options: RealRedisOptions = {},
): Promise<RealRedisServerInstance> {
  const envUrl = process.env.TEST_REDIS_URL || process.env.LOCAL_REDIS_URL;
  if (envUrl) {
    parseAndValidateRedisUrl(envUrl);
  }

  if (options.simulateStartupFailure) {
    throw new Error(
      "[SECURITY_VIOLATION] Simulated startup failure: could not start dedicated Redis instance. Silent fallback is disallowed.",
    );
  }

  const targetingExisting = Boolean(options.port || options.host || envUrl);
  if (targetingExisting && !options.allowExisting) {
    throw new Error(
      "[SECURITY_VIOLATION] Existing Redis instances cannot be used for destructive tests. Tests require a dedicated Redis container or process started and owned by the test harness on an isolated loopback port.",
    );
  }

  let host = "127.0.0.1";
  let port = 0;
  let password: string | undefined;
  let dedicatedContainerName: string | null = null;
  const harnessRunId = `swyra:test:disposable:${crypto.randomBytes(8).toString("hex")}`;
  let isDedicated = false;

  if (options.allowExisting) {
    host = options.host || "127.0.0.1";
    port = options.port || 6379;
    password =
      options.password !== undefined
        ? options.password
        : process.env.LOCAL_REDIS_PASSWORD || "redis_password";
    if (envUrl) {
      const parsed = parseAndValidateRedisUrl(envUrl);
      host = parsed.host;
      port = parsed.port;
      if (parsed.password !== undefined) password = parsed.password;
    }
    validateLoopbackEndpoint(host);
    isDedicated = false;
  } else {
    const containerName = `swyra-test-redis-${crypto.randomBytes(6).toString("hex")}`;
    const generatedPassword = crypto.randomBytes(16).toString("hex");
    try {
      execSync(
        `docker run -d --rm -p 127.0.0.1:0:6379 --name ${containerName} redis:8.8.3-alpine redis-server --requirepass ${generatedPassword}`,
        { stdio: "pipe" },
      );
      const portOut = execSync(`docker port ${containerName} 6379`, { stdio: "pipe" }).toString().trim();
      const portMatch = portOut.match(/:(\d+)$/m);
      if (!portMatch) {
        throw new Error("Unable to parse dynamically allocated port from docker container output");
      }
      port = parseInt(portMatch[1], 10);
      host = "127.0.0.1";
      password = generatedPassword;
      dedicatedContainerName = containerName;
      isDedicated = true;
    } catch (startErr: any) {
      if (dedicatedContainerName) {
        try {
          execSync(`docker stop -t 1 ${dedicatedContainerName}`, { stdio: "ignore" });
        } catch {}
      }
      throw new Error(
        `[SECURITY_VIOLATION] Could not start a dedicated test Redis instance. Destructive tests strictly require a harness-owned Redis process or container on an isolated loopback port. Fallback to existing instances is disallowed: ${startErr?.message || String(startErr)}`,
      );
    }
  }

  validateLoopbackEndpoint(host);

  const cleanupContainer = () => {
    process.removeListener("exit", cleanupContainer);
    process.removeListener("SIGINT", cleanupContainer);
    process.removeListener("SIGTERM", cleanupContainer);
    if (dedicatedContainerName) {
      try {
        execSync(`docker stop -t 1 ${dedicatedContainerName}`, { stdio: "ignore" });
      } catch {}
      dedicatedContainerName = null;
    }
  };

  process.once("exit", cleanupContainer);
  process.once("SIGINT", cleanupContainer);
  process.once("SIGTERM", cleanupContainer);

  const client = new SimpleRedisClient(port, host, password);
  try {
    await client.connect();
  } catch (err: any) {
    client.close();
    cleanupContainer();
    throw new Error(
      `Failed to connect to real Redis on ${host}:${port}: ${err?.message || String(err)}. Real Redis is required for these tests. Fallback to mock is disallowed.`,
    );
  }

  let info: string;
  try {
    info = await client.sendCommand(["INFO", "server"]);
  } catch (err: any) {
    client.close();
    cleanupContainer();
    throw new Error(
      `Failed to query real Redis INFO on ${host}:${port}: ${err?.message || String(err)}. Fallback to mock is disallowed.`,
    );
  }

  const versionMatch = info.match(/redis_version:([^\r\n]+)/);
  const redisVersion = versionMatch ? versionMatch[1] : "unknown";

  // Establish and prove ownership of this Redis instance before permitting destructive operations
  if (isDedicated && dedicatedContainerName) {
    await client.sendCommand(["SET", "swyra:test:disposable:owner", harnessRunId]);
    await client.sendCommand(["SET", "swyra:test:disposable:container", dedicatedContainerName]);
  }

  let isOutage = false;

  const server = http.createServer(async (req, res) => {
    if (isOutage) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Service Unavailable (Simulated Redis Outage)" }));
      return;
    }

    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const isBase64 = req.headers["upstash-encoding"] === "base64";
        const isPipeline = req.url === "/pipeline";
        const commands = isPipeline ? JSON.parse(body) : [JSON.parse(body)];
        const results: any[] = [];

        for (const cmd of commands) {
          try {
            const raw = await client.sendCommand(cmd);
            results.push({ result: encodeForUpstash(raw, isBase64) });
          } catch (e: any) {
            results.push({ error: e?.message || String(e) });
          }
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(isPipeline ? results : results[0]));
      } catch (e: any) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: e?.message || String(e) }));
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => resolve());
    server.on("error", reject);
  });

  const addr = server.address();
  if (!addr || typeof addr === "string") {
    client.close();
    cleanupContainer();
    throw new Error("Failed to get bridge server address");
  }

  const serverPort = addr.port;
  const url = `http://127.0.0.1:${serverPort}`;
  const token = "real-redis-test-token";

  return {
    server,
    url,
    port: serverPort,
    token,
    isRealRedis: true,
    isDedicated,
    redisVersion,
    dedicatedContainer: dedicatedContainerName,
    harnessRunId,
    simulateOutage: () => {
      isOutage = true;
    },
    simulateRecovery: () => {
      isOutage = false;
    },
    has: async (key: string): Promise<boolean> => {
      const count = await client.sendCommand(["EXISTS", key]);
      return Number(count) > 0;
    },
    get: async (key: string): Promise<any> => {
      const type = await client.sendCommand(["TYPE", key]);
      if (type === "none") return null;
      if (type === "hash") {
        const raw = await client.sendCommand(["HGETALL", key]);
        const map = new Map<string, any>();
        if (Array.isArray(raw)) {
          for (let i = 0; i < raw.length; i += 2) {
            map.set(raw[i], raw[i + 1]);
          }
        }
        return map;
      }
      return client.sendCommand(["GET", key]);
    },
    set: async (key: string, value: any, ttlSeconds?: number): Promise<void> => {
      if (ttlSeconds) {
        await client.sendCommand(["SET", key, String(value), "EX", ttlSeconds]);
      } else {
        await client.sendCommand(["SET", key, String(value)]);
      }
    },
    delete: async (key: string): Promise<boolean> => {
      const count = await client.sendCommand(["DEL", key]);
      return Number(count) > 0;
    },
    clear: async (): Promise<void> => {
      // Destructive flush is strictly restricted to dedicated instances started and owned by the harness
      if (!isDedicated || !dedicatedContainerName) {
        throw new Error(
          "[SECURITY_VIOLATION] Refusing to flush Redis: instance was not started and owned by the test harness. Destructive flush is strictly forbidden on existing instances.",
        );
      }
      const currentOwner = await client.sendCommand(["GET", "swyra:test:disposable:owner"]);
      if (currentOwner !== harnessRunId) {
        throw new Error(
          "[SECURITY_VIOLATION] Refusing to flush Redis: instance ownership marker mismatch. Harness does not own this instance.",
        );
      }
      await client.sendCommand(["FLUSHDB"]);
      await client.sendCommand(["SET", "swyra:test:disposable:owner", harnessRunId]);
      await client.sendCommand(["SET", "swyra:test:disposable:container", dedicatedContainerName]);
    },
    close: async (): Promise<void> => {
      if (typeof (server as any).closeAllConnections === "function") {
        (server as any).closeAllConnections();
      }
      await new Promise<void>((r) => server.close(() => r()));
      client.close();
      cleanupContainer();
    },
    sendCommand: (args: (string | number)[]) => client.sendCommand(args),
  };
}
