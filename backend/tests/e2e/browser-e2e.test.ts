import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { spawn, ChildProcess } from "node:child_process";
import { MongoMemoryServer } from "mongodb-memory-server";
import { MongoClient } from "mongodb";
import { chromium, Browser, BrowserContext } from "playwright";

console.log("================================================================");
console.log("  SWYRA AUTH -- LIVE BROWSER E2E TEST SUITE (PLAYWRIGHT)");
console.log("  Real Browser Testing (IdP Frontend + Next.js + Express)");
console.log("================================================================\n");

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, "../../");
const repoRoot = path.resolve(backendDir, "../");
const frontendDir = path.resolve(repoRoot, "frontend");
const nextAppDir = path.resolve(repoRoot, "test/next-app");
const expressAppDir = path.resolve(repoRoot, "test/react-express-app/backend");

async function getAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

const IDP_PORT = await getAvailablePort();
const FRONTEND_PORT = await getAvailablePort();
const NEXT_PORT = await getAvailablePort();
const EXPRESS_PORT = await getAvailablePort();

const IDP_URL = `http://127.0.0.1:${IDP_PORT}`;
const FRONTEND_URL = `http://127.0.0.1:${FRONTEND_PORT}`;
const NEXT_URL = `http://127.0.0.1:${NEXT_PORT}`;
const EXPRESS_URL = `http://127.0.0.1:${EXPRESS_PORT}`;

console.log("Port Allocation:");
console.log(`  IdP Backend:  ${IDP_PORT}`);
console.log(`  IdP Frontend: ${FRONTEND_PORT}`);
console.log(`  Next.js:      ${NEXT_PORT}`);
console.log(`  Express:      ${EXPRESS_PORT}\n`);

const spawnedChildren: ChildProcess[] = [];
function trackChild(child: ChildProcess): ChildProcess {
  spawnedChildren.push(child);
  return child;
}

function killAllChildren() {
  for (const child of spawnedChildren) {
    if (!child.killed && child.pid) {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {}
      }
    }
  }
}

process.on("exit", killAllChildren);
process.on("SIGINT", () => { killAllChildren(); process.exit(1); });
process.on("SIGTERM", () => { killAllChildren(); process.exit(1); });

function getChromiumExecutable(): string | undefined {
  if (process.env.CHROMIUM_PATH && fs.existsSync(process.env.CHROMIUM_PATH)) {
    return process.env.CHROMIUM_PATH;
  }
  const defaultLocal = "/home/swyra/.local/bin/chromium";
  if (fs.existsSync(defaultLocal)) {
    return defaultLocal;
  }
  return undefined;
}

// 1. Start disposable in-memory MongoDB
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();
console.log(`Disposable MongoDB running at ${mongoUri}`);

const mongoClient = new MongoClient(mongoUri);
await mongoClient.connect();
const db = mongoClient.db();

// 2. Client Definitions
const NEXT_CLIENT_ID = "next-browser-client-live";
const NEXT_CLIENT_SECRET = "next-browser-secret-12345";
const NEXT_CLIENT_SECRET_HASH = crypto.createHash("sha256").update(NEXT_CLIENT_SECRET).digest("base64url");
const NEXT_CALLBACK_URL = `${NEXT_URL}/api/auth/callback`;

const EXPRESS_CLIENT_ID = "express-browser-client-live";
const EXPRESS_CLIENT_SECRET = "express-browser-secret-12345";
const EXPRESS_CLIENT_SECRET_HASH = crypto.createHash("sha256").update(EXPRESS_CLIENT_SECRET).digest("base64url");
const EXPRESS_CALLBACK_URL = `${EXPRESS_URL}/auth/callback`;

await db.collection("oauthClient").insertMany([
  {
    id: NEXT_CLIENT_ID,
    clientId: NEXT_CLIENT_ID,
    clientSecret: NEXT_CLIENT_SECRET_HASH,
    redirectUris: [NEXT_CALLBACK_URL],
    allowedOrigins: [NEXT_URL],
    isPublic: false,
    isDev: true,
    skipConsent: true,
    tokenEndpointAuthMethod: "client_secret_basic",
    createdAt: new Date(),
  },
  {
    id: EXPRESS_CLIENT_ID,
    clientId: EXPRESS_CLIENT_ID,
    clientSecret: EXPRESS_CLIENT_SECRET_HASH,
    redirectUris: [EXPRESS_CALLBACK_URL],
    allowedOrigins: [EXPRESS_URL],
    isPublic: false,
    isDev: true,
    skipConsent: true,
    tokenEndpointAuthMethod: "client_secret_basic",
    createdAt: new Date(),
  },
]);

// Helper to poll server ready
async function waitForHttp(url: string, timeoutMs = 25000): Promise<void> {
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

let browser: Browser | null = null;

try {
  // 3. Spawn IdP Backend
  console.log("Spawning IdP backend process...");
  const idpChild = trackChild(spawn(
    process.execPath,
    [path.join(backendDir, "node_modules/tsx/dist/cli.mjs"), "src/node-server.ts"],
    {
      cwd: backendDir,
      detached: true,
      env: {
        ...process.env,
        NODE_ENV: "test",
        PORT: String(IDP_PORT),
        MONGO_URI: mongoUri,
        BETTER_AUTH_SECRET: "a".repeat(32),
        BETTER_AUTH_URL: IDP_URL,
        FRONTEND_URL: FRONTEND_URL,
        AUTH_PUBLIC_SIGNUP_ENABLED: "true",
        GOOGLE_CLIENT_ID: "test-google-id",
        GOOGLE_CLIENT_SECRET: "test-google-secret",
        INTERNAL_GATEWAY_SECRET: "g".repeat(32),
        TRUSTED_PROXY_CIDRS: "127.0.0.1/32,10.0.0.0/8",
      },
      stdio: "pipe",
    }
  ));
  await waitForHttp(`${IDP_URL}/health`);
  console.log("[PASS] IdP backend ready at " + IDP_URL);

  // 4. Ensure Frontend UI is built & spawn IdP Frontend (Vite Preview)
  if (!fs.existsSync(path.join(frontendDir, "dist/index.html"))) {
    console.log("Building frontend production bundle for testing...");
    const { execSync } = await import("node:child_process");
    execSync("npm run build:ui", { cwd: frontendDir, stdio: "pipe" });
  }

  console.log("Spawning IdP frontend Vite preview process...");
  const frontendChild = trackChild(spawn(
    path.join(frontendDir, "node_modules/.bin/vite"),
    ["preview", "--port", String(FRONTEND_PORT), "--host", "127.0.0.1"],
    {
      cwd: frontendDir,
      detached: true,
      env: {
        ...process.env,
        BACKEND_URL: IDP_URL,
        INTERNAL_GATEWAY_SECRET: "g".repeat(32),
      },
      stdio: "pipe",
    }
  ));
  await waitForHttp(`${FRONTEND_URL}/auth`);
  console.log("[PASS] IdP frontend ready at " + FRONTEND_URL);

  // 5. Spawn Next.js Consumer
  console.log("Spawning Next.js consumer process...");
  const nextChild = trackChild(spawn(
    process.execPath,
    [path.join(nextAppDir, "node_modules/next/dist/bin/next"), "start", "-p", String(NEXT_PORT)],
    {
      cwd: nextAppDir,
      detached: true,
      env: {
        ...process.env,
        NODE_ENV: "production",
        AUTH_ISSUER: IDP_URL,
        CLIENT_ID: NEXT_CLIENT_ID,
        CLIENT_SECRET: NEXT_CLIENT_SECRET,
        AUTH_CALLBACK_URL: NEXT_CALLBACK_URL,
        SESSION_SECRET: "s".repeat(32),
      },
      stdio: "pipe",
    }
  ));
  await waitForHttp(`${NEXT_URL}/`);
  console.log("[PASS] Next.js consumer ready at " + NEXT_URL);

  // 6. Spawn Express Consumer
  console.log("Spawning Express consumer process...");
  const expressChild = trackChild(spawn(
    process.execPath,
    [path.join(expressAppDir, "dist/index.js")],
    {
      cwd: expressAppDir,
      detached: true,
      env: {
        ...process.env,
        NODE_ENV: "production",
        PORT: String(EXPRESS_PORT),
        AUTH_ISSUER: IDP_URL,
        CLIENT_ID: EXPRESS_CLIENT_ID,
        CLIENT_SECRET: EXPRESS_CLIENT_SECRET,
        AUTH_CALLBACK_URL: EXPRESS_CALLBACK_URL,
        CLIENT_ORIGIN: EXPRESS_URL,
      },
      stdio: "pipe",
    }
  ));
  await waitForHttp(`${EXPRESS_URL}/auth/login`);
  console.log("[PASS] Express consumer ready at " + EXPRESS_URL);

  // 7. Seed 2 User Accounts via IdP Sign-Up Endpoint
  console.log("\nSeeding user accounts via IdP sign-up...");
  const USER1_EMAIL = "pilot1@swyra.com";
  const USER1_PASS = "Password123!Secure";
  const USER1_NAME = "Pilot Alpha";

  const USER2_EMAIL = "pilot2@swyra.com";
  const USER2_PASS = "Password123!Secure";
  const USER2_NAME = "Pilot Bravo";

  const signup1Res = await fetch(`${IDP_URL}/api/auth/sign-up/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: IDP_URL, Referer: `${IDP_URL}/` },
    body: JSON.stringify({ email: USER1_EMAIL, password: USER1_PASS, name: USER1_NAME }),
  });
  assert.equal(signup1Res.status, 200, "Sign-up for User 1 must succeed");
  const user1Data = await signup1Res.json();
  const user1Id = user1Data.user.id;

  const signup2Res = await fetch(`${IDP_URL}/api/auth/sign-up/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: IDP_URL, Referer: `${IDP_URL}/` },
    body: JSON.stringify({ email: USER2_EMAIL, password: USER2_PASS, name: USER2_NAME }),
  });
  assert.equal(signup2Res.status, 200, "Sign-up for User 2 must succeed");
  const user2Data = await signup2Res.json();
  const user2Id = user2Data.user.id;

  // Register both users for both clients in user_app_registrations
  await db.collection("user_app_registrations").insertMany([
    { userId: user1Id, clientId: NEXT_CLIENT_ID, role: "user", registeredAt: new Date() },
    { userId: user1Id, clientId: EXPRESS_CLIENT_ID, role: "user", registeredAt: new Date() },
    { userId: user2Id, clientId: NEXT_CLIENT_ID, role: "user", registeredAt: new Date() },
    { userId: user2Id, clientId: EXPRESS_CLIENT_ID, role: "user", registeredAt: new Date() },
  ]);
  console.log("[PASS] Test users created and registered for client access.\n");

  // 8. Launch Playwright Chromium Browser
  console.log("Launching headless Chromium browser session...");
  const execPath = getChromiumExecutable();
  browser = await chromium.launch({
    executablePath: execPath,
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
  });

  const context: BrowserContext = await browser.newContext();
  const page = await context.newPage();

  page.on("console", (msg) => console.log(`[BROWSER CONSOLE ${msg.type()}]:`, msg.text()));
  page.on("pageerror", (err) => console.log(`[BROWSER PAGE ERROR]:`, err.message));
  page.on("request", (req) => console.log(`[BROWSER REQ ${req.method()}]:`, req.url()));
  page.on("response", (res) => console.log(`[BROWSER RES ${res.status()}]:`, res.url()));

  // ============================================================================
  // Test Phase 1: User 1 OAuth 2.1 Login via IdP Frontend
  // ============================================================================
  console.log("Phase 1: Testing initial OAuth 2.1 flow via real browser...");
  await page.goto(NEXT_URL, { waitUntil: "networkidle" });
  assert.ok(await page.textContent("h1"), "Next.js Consumer page must load");

  // Click Sign In link
  console.log("Navigating to login initiator...");
  await page.click('a[href="/api/auth/login"]');

  // Should redirect to IdP frontend SignIn page
  await page.waitForURL(`**/auth?**`, { timeout: 15000 });
  console.log("IdP sign-in page loaded successfully at:", page.url());
  const authHtml = await page.content();
  console.log("Rendered Auth Page HTML Snippet:", authHtml.slice(0, 1000));
  console.log("Inputs found on page:", await page.$$eval("input", (inputs) => inputs.map((i) => ({ name: i.name, type: i.type, placeholder: i.placeholder }))));

  // Helper to ensure form is fully interactive and filled before submit
  async function submitSignInForm(targetEmail: string, targetPass: string) {
    await page.waitForSelector('input[name="email"]', { timeout: 15000 });
    await page.waitForLoadState("networkidle");

    const inputsInfo = await page.$$eval("input", (inputs) => inputs.map((i) => ({
      name: i.name,
      id: i.id,
      value: i.value,
      visible: i.getBoundingClientRect().width > 0,
      disabled: i.disabled,
      readOnly: i.readOnly,
      outerHTML: i.outerHTML.slice(0, 150)
    })));
    console.log("Detailed inputs on page:", JSON.stringify(inputsInfo, null, 2));

    const emailInput = page.locator('input[name="email"]').first();
    const passInput = page.locator('input[name="password"]').first();

    await emailInput.waitFor({ state: "visible", timeout: 15000 });
    await passInput.waitFor({ state: "visible", timeout: 15000 });

    // Set value using prototype setter so React synthetic event listener detects change
    await page.evaluate(`
      (() => {
        const emailEl = document.querySelector('input[name="email"]');
        const passEl = document.querySelector('input[name="password"]');
        function setVal(input, val) {
          if (!input) return;
          const descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
          if (descriptor && descriptor.set) {
            descriptor.set.call(input, val);
          } else {
            input.value = val;
          }
          if (input._valueTracker) {
            input._valueTracker.setValue("");
          }
          input.dispatchEvent(new Event("input", { bubbles: true }));
          input.dispatchEvent(new Event("change", { bubbles: true }));
        }
        setVal(emailEl, ${JSON.stringify(targetEmail)});
        setVal(passEl, ${JSON.stringify(targetPass)});
      })()
    `);

    const finalEmail = await emailInput.inputValue();
    const finalPass = await passInput.inputValue();
    console.log("Verified input values before submit:", { email: finalEmail, passLength: finalPass.length });
    assert.strictEqual(finalEmail, targetEmail, "Email input value must match target");
    assert.strictEqual(finalPass, targetPass, "Password input value must match target");

    const submitBtn = page.locator('button[type="submit"]').first();
    await submitBtn.waitFor({ state: "visible", timeout: 10000 });
    await submitBtn.click();
  }

  // Fill credentials for User 1
  await submitSignInForm(USER1_EMAIL, USER1_PASS);

  // Wait for redirect to Next.js dashboard
  await page.waitForURL(`**/dashboard`, { timeout: 20000 });
  console.log("Successfully redirected to consumer dashboard at:", page.url());

  // Verify Dashboard content displays User 1
  const dashboardHeading = await page.textContent("h1");
  console.log("Dashboard heading:", dashboardHeading);
  assert.ok(
    dashboardHeading?.includes(USER1_NAME) || dashboardHeading?.includes("Authenticated Pilot"),
    "Dashboard must display authenticated pilot heading"
  );
  const pageContent = await page.content();
  assert.ok(pageContent.includes(USER1_EMAIL), "Dashboard must display User 1 email");
  assert.ok(pageContent.includes("OAuth 2.1 Authenticated"), "Dashboard must indicate OAuth 2.1 status");

  // ============================================================================
  // Test Phase 2: Cookie Behavior Verification in Browser Context
  // ============================================================================
  console.log("\nPhase 2: Verifying browser cookie behavior...");
  const cookies = await context.cookies();
  const nextSessionCookie = cookies.find((c) => c.name === "auth_session" && c.domain === "127.0.0.1");
  assert.ok(nextSessionCookie, "Next.js consumer auth_session cookie must be present");
  if (!nextSessionCookie) throw new Error("Missing auth_session cookie");
  assert.equal(nextSessionCookie.httpOnly, true, "Consumer session cookie must be HttpOnly");
  assert.equal(nextSessionCookie.sameSite.toLowerCase(), "lax", "Consumer session cookie must be SameSite Lax");

  const idpSessionCookie = cookies.find((c) => c.name.includes("session_token"));
  assert.ok(idpSessionCookie, "IdP Better Auth session token cookie must be present in browser context");
  console.log("[PASS] Cookies correctly isolated and configured with HttpOnly and Lax.");

  // ============================================================================
  // Test Phase 3: Automatic Token Refresh in Browser Context
  // ============================================================================
  console.log("\nPhase 3: Verifying automatic token refresh in browser context...");
  const h2Info = await page.evaluate(`
    (() => {
      const el = document.querySelector('h2');
      if (!el) return { found: false };
      const r = el.getBoundingClientRect();
      const style = window.getComputedStyle(el);
      return {
        found: true,
        text: el.innerText,
        rect: { x: r.x, y: r.y, width: r.width, height: r.height },
        display: style.display,
        visibility: style.visibility,
        opacity: style.opacity,
      };
    })()
  `);
  console.log("H2 info on dashboard:", h2Info);

  // Wait for telemetry data to load in TelemetryViewer
  await page.waitForSelector("text=Cryptographic Token Validation Status", { state: "attached", timeout: 10000 });
  console.log("[PASS] Initial telemetry stream loaded.");

  function parseCookieJson(raw: string) {
    try {
      return JSON.parse(raw);
    } catch {
      return JSON.parse(decodeURIComponent(raw));
    }
  }

  // Simulate access token expiry by modifying auth_session cookie creation timestamp
  const parsedNextSession = parseCookieJson(nextSessionCookie.value);
  const originalAccessToken = parsedNextSession.tokens.access_token;
  const originalRefreshToken = parsedNextSession.tokens.refresh_token;

  // Set createdAt in the past so that createdAt + expires_in * 1000 <= Date.now()
  parsedNextSession.createdAt = Date.now() - 3700 * 1000;
  await context.addCookies([
    {
      name: "auth_session",
      value: encodeURIComponent(JSON.stringify(parsedNextSession)),
      domain: "127.0.0.1",
      path: "/",
      httpOnly: true,
      sameSite: "Lax",
      expires: Math.floor(Date.now() / 1000) + 3600,
    },
  ]);

  // Click refresh telemetry button and wait for transparent refresh and response
  console.log("Triggering secure telemetry fetch with expired access token...");
  const [telemetryRes] = await Promise.all([
    page.waitForResponse((r) => r.url().includes("/api/secure-data") && r.status() === 200, { timeout: 15000 }),
    page.click('button:has-text("Refresh Telemetry")'),
  ]);
  const telemetryJson = await telemetryRes.json();
  assert.equal(telemetryJson.status, "SECURE_STREAM_ACTIVE", "Telemetry response status must be SECURE_STREAM_ACTIVE");

  // Read updated cookies from browser context
  const cookiesAfterRefresh = await context.cookies();
  const refreshedSessionCookie = cookiesAfterRefresh.find((c) => c.name === "auth_session" && c.domain === "127.0.0.1");
  assert.ok(refreshedSessionCookie, "Refreshed auth_session cookie must exist");
  if (!refreshedSessionCookie) throw new Error("Missing refreshed auth_session cookie");

  const refreshedPayload = parseCookieJson(refreshedSessionCookie.value);
  assert.ok(refreshedPayload.createdAt > parsedNextSession.createdAt, "Session createdAt must be updated to current time");
  assert.ok(refreshedPayload.tokens.access_token, "Refreshed access token must exist");
  assert.ok(refreshedPayload.tokens.refresh_token, "Rotated refresh token must exist");
  assert.notEqual(
    refreshedPayload.tokens.refresh_token,
    originalRefreshToken,
    "Refresh token must be rotated forward to new token in family"
  );
  console.log("[PASS] Automatic token refresh executed transparently, rotating tokens and updating browser cookie.");

  // ============================================================================
  // Test Phase 4: Account Switching within Same Browser Context (Preserving prompt=login)
  // ============================================================================
  console.log("\nPhase 4: Testing account switching within same browser context...");
  // Navigate to login endpoint again with prompt=login
  console.log("Navigating to /api/auth/login for account switch...");
  await page.goto(`${NEXT_URL}/api/auth/login`, { waitUntil: "networkidle" });

  // Verify that prompt=login preserves login prompt and does NOT auto-redirect existing User 1 session
  await page.waitForURL(`**/auth?**`, { timeout: 15000 });
  const currentUrl = page.url();
  console.log("Sign-in page URL with prompt=login:", currentUrl);
  assert.ok(currentUrl.includes("prompt=login"), "Authorize request must include prompt=login");

  // Ensure sign-in form is present and interactive
  await page.waitForSelector('input[name="email"], input[type="email"]', { timeout: 10000 });
  console.log("[PASS] prompt=login successfully forced re-authentication UI instead of auto-approving session.");

  // Fill in credentials for User 2
  console.log("Submitting credentials for User 2 (Pilot Bravo)...");
  await submitSignInForm(USER2_EMAIL, USER2_PASS);

  // Wait for redirect to dashboard
  await page.waitForURL(`**/dashboard`, { timeout: 20000 });
  console.log("Redirected to dashboard after account switch:", page.url());

  // Verify dashboard now displays User 2 info
  const switchedPageContent = await page.content();
  assert.ok(switchedPageContent.includes(USER2_EMAIL), "Dashboard must now display User 2 email");
  assert.ok(!switchedPageContent.includes(USER1_EMAIL), "Dashboard must no longer display User 1 email");

  const cookiesAfterSwitch = await context.cookies();
  const switchedSessionCookie = cookiesAfterSwitch.find((c) => c.name === "auth_session" && c.domain === "127.0.0.1");
  assert.ok(switchedSessionCookie, "Switched auth_session cookie must exist");
  if (!switchedSessionCookie) throw new Error("Missing switched auth_session cookie");
  const switchedPayload = parseCookieJson(switchedSessionCookie.value);
  assert.equal(switchedPayload.user.email, USER2_EMAIL, "Browser session cookie user must be User 2");
  console.log("[PASS] Account switching succeeded cleanly within the same browser context.");

  // ============================================================================
  // Test Phase 5: Express Consumer Verification in Same Browser Session
  // ============================================================================
  console.log("\nPhase 5: Verifying Express consumer in the same browser session...");
  await page.goto(`${EXPRESS_URL}/auth/login`, { waitUntil: "networkidle" });

  // Since Express consumer sets prompt=login, verify re-authentication UI appears
  await page.waitForURL(`**/auth?**`, { timeout: 15000 });
  console.log("Express initiated sign-in loaded at:", page.url());
  assert.ok(page.url().includes("prompt=login"), "Express login request must preserve prompt=login");

  // Submit User 2 credentials to complete authorization for Express consumer
  await submitSignInForm(USER2_EMAIL, USER2_PASS);

  // Express callback exchanges code, sets app_session cookie, and redirects to CLIENT_ORIGIN
  await page.waitForURL(`${EXPRESS_URL}/**`, { timeout: 20000 });
  console.log("Express consumer redirected successfully to:", page.url());

  const expressCookies = await context.cookies();
  const expressSessionCookie = expressCookies.find((c) => c.name === "app_session" && c.domain === "127.0.0.1");
  assert.ok(expressSessionCookie, "Express app_session cookie must be set");
  if (!expressSessionCookie) throw new Error("Missing express app_session cookie");
  assert.equal(expressSessionCookie.httpOnly, true, "Express session cookie must be HttpOnly");

  const parsedExpressSession = JSON.parse(decodeURIComponent(expressSessionCookie.value));
  assert.equal(parsedExpressSession.user.email, USER2_EMAIL, "Express consumer must be authenticated as User 2");
  console.log("[PASS] Express consumer successfully authenticated User 2 in shared browser context.");

  console.log("\n================================================================");
  console.log("  BROWSER E2E TEST: ALL 5 PHASES PASSED WITH ZERO FAILURES!");
  console.log("================================================================\n");

  await browser.close();
  killAllChildren();
  await mongoClient.close();
  await mongod.stop();
  process.exit(0);
} catch (err) {
  console.error("\n❌ BROWSER E2E TEST FAILED:", err);
  if (browser) {
    try { await browser.close(); } catch {}
  }
  killAllChildren();
  await mongoClient.close();
  await mongod.stop();
  process.exit(1);
}
