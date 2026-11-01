import http from "node:http";
import net from "node:net";

export interface RealRedisServerInstance {
  server: http.Server;
  url: string;
  port: number;
  token: string;
  isRealRedis: true;
  redisVersion: string;
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

export interface RealRedisOptions {
  host?: string;
  port?: number;
  password?: string;
}

export async function createRealRedisServer(
  options: RealRedisOptions = {},
): Promise<RealRedisServerInstance> {
  const envUrl = process.env.TEST_REDIS_URL || process.env.LOCAL_REDIS_URL;
  let host = options.host || "127.0.0.1";
  let port = options.port || 6379;
  let password: string | undefined =
    options.password !== undefined
      ? options.password
      : process.env.LOCAL_REDIS_PASSWORD || "redis_password";

  if (envUrl) {
    try {
      const u = new URL(envUrl);
      if (u.hostname) {
        host = u.hostname === "localhost" ? "127.0.0.1" : u.hostname;
      }
      if (u.port) {
        port = parseInt(u.port, 10);
      }
      if (u.password) {
        password = decodeURIComponent(u.password);
      }
    } catch {
      // Keep defaults
    }
  }

  const client = new SimpleRedisClient(port, host, password);
  try {
    await client.connect();
  } catch (err: any) {
    throw new Error(
      `Failed to connect to real Redis on ${host}:${port}: ${err?.message || String(err)}. Real Redis is required for these tests. Fallback to mock is disallowed.`,
    );
  }

  let info: string;
  try {
    info = await client.sendCommand(["INFO", "server"]);
  } catch (err: any) {
    client.close();
    throw new Error(
      `Failed to query real Redis INFO on ${host}:${port}: ${err?.message || String(err)}. Fallback to mock is disallowed.`,
    );
  }

  const versionMatch = info.match(/redis_version:([^\r\n]+)/);
  const redisVersion = versionMatch ? versionMatch[1] : "unknown";

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
    redisVersion,
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
      await client.sendCommand(["FLUSHDB"]);
    },
    close: async (): Promise<void> => {
      if (typeof (server as any).closeAllConnections === "function") {
        (server as any).closeAllConnections();
      }
      await new Promise<void>((r) => server.close(() => r()));
      client.close();
    },
    sendCommand: (args: (string | number)[]) => client.sendCommand(args),
  };
}
