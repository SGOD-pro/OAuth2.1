import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { spawn, ChildProcess } from "node:child_process";
import { chromium, Browser } from "playwright";

export function getChromiumExecutable(): string | undefined {
  if (process.env.CHROMIUM_PATH && fs.existsSync(process.env.CHROMIUM_PATH)) {
    return process.env.CHROMIUM_PATH;
  }
  const defaultLocal = "/home/swyra/.local/bin/chromium";
  if (fs.existsSync(defaultLocal)) return defaultLocal;
  return undefined;
}

export async function getAvailablePort(usedPorts = new Set<number>()): Promise<number> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const candidate = 32000 + Math.floor(Math.random() * 25000);
    if (usedPorts.has(candidate)) continue;
    const isFree = await new Promise<boolean>((resolve) => {
      const client = net.createConnection({ port: candidate, host: "127.0.0.1" }, () => {
        client.destroy();
        resolve(false);
      });
      client.on("error", () => resolve(true));
      client.setTimeout(150, () => {
        client.destroy();
        resolve(true);
      });
    });
    if (isFree) {
      usedPorts.add(candidate);
      return candidate;
    }
  }
  const fallback = 36000 + Math.floor(Math.random() * 10000);
  usedPorts.add(fallback);
  return fallback;
}

export async function waitForHttp(url: string, timeoutMs = 25000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (res.status > 0) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Timeout waiting for ${url}`);
}

export interface BrowserTestEnvironment {
  idpUrl: string;
  frontendUrl: string;
  browser: Browser;
  cleanup: () => Promise<void>;
}

export async function startIdpAndFrontendHarness(options: {
  backendDir: string;
  frontendDir: string;
  mongoUri: string;
  gatewaySecret: string;
  betterAuthSecret: string;
}): Promise<BrowserTestEnvironment> {
  const usedPorts = new Set<number>();
  const idpPort = await getAvailablePort(usedPorts);
  const frontendPort = await getAvailablePort(usedPorts);
  const idpUrl = `http://127.0.0.1:${idpPort}`;
  const frontendUrl = `http://127.0.0.1:${frontendPort}`;

  const children: ChildProcess[] = [];
  const killChildren = () => {
    for (const child of children) {
      if (!child.killed && child.pid) {
        try { process.kill(-child.pid, "SIGKILL"); } catch {
          try { child.kill("SIGKILL"); } catch {}
        }
      }
    }
  };

  const idpChild = spawn(
    process.execPath,
    [path.join(options.backendDir, "node_modules/tsx/dist/cli.mjs"), "src/node-server.ts"],
    {
      cwd: options.backendDir,
      detached: true,
      env: {
        ...process.env,
        NODE_ENV: "test",
        PORT: String(idpPort),
        HOST: "127.0.0.1",
        MONGO_URI: options.mongoUri,
        BETTER_AUTH_SECRET: options.betterAuthSecret,
        BETTER_AUTH_URL: idpUrl,
        FRONTEND_URL: frontendUrl,
        AUTH_PUBLIC_SIGNUP_ENABLED: "true",
        GOOGLE_CLIENT_ID: "test-google-id",
        GOOGLE_CLIENT_SECRET: "test-google-secret",
        INTERNAL_GATEWAY_SECRET: options.gatewaySecret,
        TRUSTED_PROXY_CIDRS: "127.0.0.1/32,10.0.0.0/8",
      },
      stdio: "pipe",
    }
  );
  idpChild.stderr?.on("data", (d) => process.stderr.write(`[IdP ERR] ${d}`));
  children.push(idpChild);
  await waitForHttp(`${idpUrl}/health`);

  if (!fs.existsSync(path.join(options.frontendDir, "dist/index.html"))) {
    const { execSync } = await import("node:child_process");
    execSync("npm run build:ui", { cwd: options.frontendDir, stdio: "pipe" });
  }

  let frontendServer: http.Server | null = null;
  await new Promise<void>((resolve, reject) => {
    const srv = http.createServer(async (req, res) => {
      try {
        const reqPath = req.url?.split("?")[0] || "/";
        if (reqPath.startsWith("/api") || reqPath.startsWith("/.well-known")) {
          const headers = new Headers();
          for (const [k, v] of Object.entries(req.headers)) {
            if (v && k.toLowerCase() !== "host") {
              headers.set(k, Array.isArray(v) ? v.join(", ") : v);
            }
          }
          headers.set("x-gateway-secret", options.gatewaySecret);
          let bodyBuf: Buffer | undefined;
          if (req.method !== "GET" && req.method !== "HEAD") {
            const chunks: Buffer[] = [];
            for await (const chunk of req) chunks.push(Buffer.from(chunk));
            bodyBuf = Buffer.concat(chunks);
          }
          const upRes = await fetch(`${idpUrl}${req.url}`, {
            method: req.method,
            headers,
            body: bodyBuf,
            redirect: "manual",
          });
          res.statusCode = upRes.status;
          for (const [k, v] of upRes.headers) {
            if (k.toLowerCase() === "set-cookie") {
              const setCookies = typeof (upRes.headers as any).getSetCookie === "function"
                ? (upRes.headers as any).getSetCookie()
                : [v];
              res.setHeader("set-cookie", setCookies);
            } else {
              res.setHeader(k, v);
            }
          }
          res.end(Buffer.from(await upRes.arrayBuffer()));
          return;
        }

        let filePath = path.join(options.frontendDir, "dist", reqPath);
        if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
          filePath = path.join(options.frontendDir, "dist", "index.html");
        }
        const mimeTypes: Record<string, string> = {
          ".html": "text/html; charset=utf-8",
          ".js": "application/javascript; charset=utf-8",
          ".css": "text/css; charset=utf-8",
          ".json": "application/json; charset=utf-8",
          ".svg": "image/svg+xml",
          ".png": "image/png",
        };
        res.setHeader("Content-Type", mimeTypes[path.extname(filePath)] || "application/octet-stream");
        fs.createReadStream(filePath).pipe(res);
      } catch (err: any) {
        res.statusCode = 500;
        res.end(err?.message || "Internal error");
      }
    });
    srv.listen(frontendPort, "127.0.0.1", () => {
      frontendServer = srv;
      resolve();
    });
    srv.on("error", reject);
  });
  await waitForHttp(`${frontendUrl}/admin/login`);

  const browser = await chromium.launch({
    executablePath: getChromiumExecutable(),
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
  });

  return {
    idpUrl,
    frontendUrl,
    browser,
    cleanup: async () => {
      await browser.close().catch(() => {});
      if (frontendServer) {
        try { frontendServer.close(); } catch {}
      }
      killChildren();
    },
  };
}
