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

export async function killProcessGroupAndConfirm(pid: number, termTimeoutMs = 2000, killTimeoutMs = 1000): Promise<void> {
  const isGroupGone = (): boolean => {
    try {
      process.kill(-pid, 0);
      return false;
    } catch (err: any) {
      if (err?.code === "ESRCH") return true;
      throw err;
    }
  };

  if (isGroupGone()) return;

  try { process.kill(-pid, "SIGTERM"); } catch (err: any) {
    if (err?.code === "ESRCH") return;
  }

  const termDeadline = Date.now() + termTimeoutMs;
  while (Date.now() < termDeadline) {
    if (isGroupGone()) return;
    await new Promise((r) => setTimeout(r, 50));
  }

  try { process.kill(-pid, "SIGKILL"); } catch (err: any) {
    if (err?.code === "ESRCH") return;
  }

  const killDeadline = Date.now() + killTimeoutMs;
  while (Date.now() < killDeadline) {
    if (isGroupGone()) return;
    await new Promise((r) => setTimeout(r, 50));
  }

  if (!isGroupGone()) {
    throw new Error(`Process group -${pid} survived SIGKILL`);
  }
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
  extraEnv?: Record<string, string>;
  idpArgs?: string[];
  onResourcesAllocated?: (info: { frontendPort: number; idpPid: number }) => void;
}): Promise<BrowserTestEnvironment> {
  const children: ChildProcess[] = [];
  let frontendServer: http.Server | null = null;
  let browser: Browser | null = null;
  let stage = "init";

  const killAndAwaitChildren = async () => {
    await Promise.all(
      children.map((child) => (child.pid ? killProcessGroupAndConfirm(child.pid) : Promise.resolve()))
    );
  };

  const cleanup = async () => {
    await browser?.close().catch(() => {});
    if (frontendServer) {
      (frontendServer as any).closeAllConnections?.();
      await new Promise<void>((resolve) => frontendServer!.close(() => resolve()));
    }
    await killAndAwaitChildren();
  };

  try {
    stage = "frontend_listen";
    if (!fs.existsSync(path.join(options.frontendDir, "dist/index.html"))) {
      const { execSync } = await import("node:child_process");
      execSync("npm run build:ui", { cwd: options.frontendDir, stdio: "pipe" });
    }

    let idpUrl = "";

    // Bind frontend listener to port 0 first so its port is OS-assigned and reserved
    frontendServer = http.createServer(async (req, res) => {
      const urlPath = (req.url || "/").split("?")[0];
      if (urlPath.startsWith("/api/") || urlPath.startsWith("/.well-known/")) {
        const target = `${idpUrl}${req.url}`;
        const headers = new Headers();
        for (const [k, v] of Object.entries(req.headers)) {
          if (v !== undefined && k.toLowerCase() !== "host") {
            headers.set(k, Array.isArray(v) ? v.join(", ") : v);
          }
        }
        headers.set("x-gateway-secret", options.gatewaySecret);
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(Buffer.from(chunk));
        const body = chunks.length > 0 && req.method !== "GET" && req.method !== "HEAD" ? Buffer.concat(chunks) : undefined;
        try {
          const upstream = await fetch(target, { method: req.method, headers, body, redirect: "manual" });
          res.statusCode = upstream.status;
          upstream.headers.forEach((val, key) => {
            if (key.toLowerCase() !== "transfer-encoding") {
              res.setHeader(key, val);
            }
          });
          const getSetCookie = (upstream.headers as any).getSetCookie;
          if (typeof getSetCookie === "function") {
            const setCookies = getSetCookie.call(upstream.headers);
            if (Array.isArray(setCookies) && setCookies.length > 0) {
              res.setHeader("set-cookie", setCookies);
            }
          }
          const buf = Buffer.from(await upstream.arrayBuffer());
          res.end(buf);
        } catch (err: any) {
          res.statusCode = 502;
          res.end(String(err?.message || err));
        }
        return;
      }

      const distDir = path.join(options.frontendDir, "dist");
      const candidate = path.join(distDir, urlPath === "/" ? "index.html" : urlPath);
      const filePath = fs.existsSync(candidate) && fs.statSync(candidate).isFile() ? candidate : path.join(distDir, "index.html");
      const ext = path.extname(filePath);
      const mime =
        ext === ".html" ? "text/html; charset=utf-8"
        : ext === ".js" ? "application/javascript; charset=utf-8"
        : ext === ".css" ? "text/css; charset=utf-8"
        : ext === ".svg" ? "image/svg+xml"
        : "application/octet-stream";
      res.setHeader("Content-Type", mime);
      res.end(fs.readFileSync(filePath));
    });

    await new Promise<void>((resolve, reject) => {
      frontendServer!.once("error", reject);
      frontendServer!.listen(0, "127.0.0.1", () => resolve());
    });
    const frontendAddr = frontendServer.address();
    if (!frontendAddr || typeof frontendAddr === "string") {
      throw new Error("Failed to resolve bound frontend port");
    }
    const frontendUrl = `http://127.0.0.1:${frontendAddr.port}`;

    stage = "idp_spawn";
    const idpChild = spawn(
      process.execPath,
      options.idpArgs ?? [
        path.join(options.backendDir, "node_modules/tsx/dist/cli.mjs"),
        path.join(options.backendDir, "tests/fixtures/idp-test-launcher.ts"),
      ],
      {
        cwd: options.backendDir,
        detached: true,
        env: {
          ...process.env,
          NODE_ENV: "test",
          HOST: "127.0.0.1",
          MONGO_URI: options.mongoUri,
          BETTER_AUTH_SECRET: options.betterAuthSecret,
          FRONTEND_URL: frontendUrl,
          AUTH_PUBLIC_SIGNUP_ENABLED: "true",
          GOOGLE_CLIENT_ID: "test-google-id",
          GOOGLE_CLIENT_SECRET: "test-google-secret",
          INTERNAL_GATEWAY_SECRET: options.gatewaySecret,
          TRUSTED_PROXY_CIDRS: "127.0.0.1/32,10.0.0.0/8",
          ...(options.extraEnv || {}),
        },
        stdio: ["ignore", "pipe", "pipe", "ipc"],
      }
    );
    idpChild.stderr?.on("data", (d) => process.stderr.write(`[IdP ERR] ${d}`));
    children.push(idpChild);
    if (idpChild.pid) {
      options.onResourcesAllocated?.({ frontendPort: frontendAddr.port, idpPid: idpChild.pid });
    }

    idpUrl = await Promise.race([
      new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("Timeout waiting for IdP IPC ready")), 25000);
        idpChild.on("message", (msg: any) => {
          if (msg?.type === "ready" && typeof msg.idpUrl === "string") {
            clearTimeout(timer);
            resolve(msg.idpUrl);
          } else if (msg?.type === "error") {
            clearTimeout(timer);
            reject(new Error(String(msg.message || "IdP startup error")));
          }
        });
      }),
      new Promise<never>((_, reject) => {
        idpChild.once("error", (err) => reject(new Error(`IdP spawn error: ${err.message}`)));
        idpChild.once("exit", (code, sig) =>
          reject(new Error(`IdP exited early (code=${code}, signal=${sig})`))
        );
      }),
    ]);

    stage = "browser_launch";
    const executablePath = getChromiumExecutable();
    browser = await chromium.launch({
      headless: true,
      ...(executablePath ? { executablePath } : {}),
    });

    return {
      idpUrl,
      frontendUrl,
      browser,
      cleanup,
    };
  } catch (err: any) {
    await cleanup();
    throw new Error(`[browser-harness] Startup failed at stage "${stage}": ${err?.message || err}`);
  }
}
