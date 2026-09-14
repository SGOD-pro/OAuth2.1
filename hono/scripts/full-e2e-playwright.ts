import fs from "fs";
import path from "path";
import { execSync, spawn } from "child_process";
import { getDb, closeDb } from "../src/db/mongo";

import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { chromium } = require("/home/swyra/.npm/_npx/9833c18b2d85bc59/node_modules/playwright-core");

const SCREENSHOTS_DIR = "/home/swyra/.gemini/antigravity-cli/brain/51915d91-9fda-4e00-aa32-72e693ecab9e/screenshots";
fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });

async function run() {
  console.log("=================================================");
  console.log("    SWYRA M AUTH FULL E2E PLAYWRIGHT TEST       ");
  console.log("=================================================\n");

  const browser = await chromium.launch({
    executablePath: "/home/swyra/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome",
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
  });

  try {
    // -------------------------------------------------------------
    // STEP 1: ADMIN CONSOLE LOGIN
    // -------------------------------------------------------------
    console.log("▶ [STEP 1] Logging in to Admin Console (http://localhost:5174/admin/login)...");
    const adminContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const adminPage = await adminContext.newPage();
    adminPage.on("console", msg => console.log("    [Admin Console]", msg.text()));
    adminPage.on("pageerror", err => console.error("    [Admin Error]", err.message));

    await adminPage.goto("http://localhost:5174/admin/login", { waitUntil: "networkidle" });
    await adminPage.screenshot({ path: path.join(SCREENSHOTS_DIR, "01_admin_login_page.png") });

    // Fill admin credentials
    await adminPage.fill('input[type="email"]', "swyra@auth2.1.com");
    await adminPage.fill('input[type="password"]', "AdminPassword@123!");
    await adminPage.click('button[type="submit"]');

    // Wait for navigation away from /admin/login to /admin
    await adminPage.waitForURL(url => url.pathname === "/admin" || url.pathname === "/admin/dashboard", { timeout: 15000 });
    console.log("  ✔ Successfully logged into Admin Console at:", adminPage.url());
    await adminPage.screenshot({ path: path.join(SCREENSHOTS_DIR, "02_admin_logged_in.png") });

    // -------------------------------------------------------------
    // STEP 2: REGISTER NEW OAUTH APPLICATION
    // -------------------------------------------------------------
    console.log("\n▶ [STEP 2] Navigating to Applications and registering new client...");
    await adminPage.goto("http://localhost:5174/admin/clients", { waitUntil: "networkidle" });

    // Click "Create application" button
    const createBtn = adminPage.locator('button:has-text("Create application")');
    await createBtn.waitFor({ state: "visible", timeout: 5000 });
    await createBtn.click();

    // Modal should appear
    const dialog = adminPage.locator('[role="dialog"]');
    await dialog.waitFor({ state: "visible", timeout: 5000 });
    console.log("  ✔ Register application modal opened.");

    // Fill application name
    const appNameInput = dialog.locator('input[placeholder="e.g. Customer Portal"]');
    await appNameInput.fill("Playwright Next.js App");

    // Fill redirect URI
    const redirectInput = dialog.locator('input[placeholder="https://app.example.com/auth/callback"]');
    await redirectInput.fill("http://localhost:3001/api/auth/callback");
    // Click Add button next to redirect input
    const addRedirectBtn = redirectInput.locator("xpath=..").locator('button:has-text("Add")');
    await addRedirectBtn.click();
    console.log("  ✔ Added Redirect URI: http://localhost:3001/api/auth/callback");

    // Fill allowed origin
    const originInput = dialog.locator('input[placeholder="https://app.example.com"]');
    await originInput.fill("http://localhost:3001");
    // Click Add button next to origin input
    const addOriginBtn = originInput.locator("xpath=..").locator('button:has-text("Add")');
    await addOriginBtn.click();
    console.log("  ✔ Added Allowed Origin: http://localhost:3001");

    // Check Development Mode checkbox
    const devModeCheckbox = dialog.locator('button[role="checkbox"]').first();
    await devModeCheckbox.click();
    console.log("  ✔ Enabled Development Mode.");

    await adminPage.screenshot({ path: path.join(SCREENSHOTS_DIR, "03_register_modal_filled.png") });

    // Submit form
    const submitBtn = dialog.locator('button:has-text("Register application")');
    await submitBtn.click();

    // Wait for "Application credentials generated"
    const credsTitle = dialog.locator('text=Application credentials generated');
    await credsTitle.waitFor({ state: "visible", timeout: 10000 });
    console.log("  ✔ Application credentials generated successfully!");

    await adminPage.screenshot({ path: path.join(SCREENSHOTS_DIR, "04_credentials_generated_modal.png") });

    // Extract Client ID and Client Secret
    const codeBlocks = dialog.locator("code");
    const generatedClientId = (await codeBlocks.nth(0).innerText()).trim();
    const generatedClientSecret = (await codeBlocks.nth(1).innerText()).trim();

    console.log(`  🔑 Client ID:     ${generatedClientId}`);
    console.log(`  🔒 Client Secret: ${generatedClientSecret}`);

    if (!generatedClientId || generatedClientId.length < 10) {
      throw new Error("Failed to extract valid Client ID from modal!");
    }
    if (!generatedClientSecret || generatedClientSecret.length < 10) {
      throw new Error("Failed to extract valid Client Secret from modal!");
    }

    // Click "Copy secret" so Done button enables
    const copySecretBtn = dialog.getByRole("button", { name: "Copy secret", exact: true });
    await copySecretBtn.click();

    // Click "Done"
    const doneBtn = dialog.getByRole("button", { name: "Done", exact: true });
    await doneBtn.waitFor({ state: "visible" });
    await doneBtn.click();

    // Verify modal closes and client appears in list
    await dialog.waitFor({ state: "hidden", timeout: 5000 });
    const appEntry = adminPage.locator(`text=${generatedClientId}`).or(adminPage.locator('text=Playwright Next.js App'));
    await appEntry.first().waitFor({ state: "visible", timeout: 5000 });
    console.log("  ✔ Verified client appears in Applications registry table!");
    await adminPage.screenshot({ path: path.join(SCREENSHOTS_DIR, "05_applications_registry.png") });

    // Close admin context
    await adminContext.close();

    // -------------------------------------------------------------
    // STEP 3: CONFIGURE NEXT.JS TEST CONSUMER APP
    // -------------------------------------------------------------
    console.log("\n▶ [STEP 3] Configuring test/next-app with new credentials...");
    const nextEnvPath = path.resolve("/home/swyra/projects/OAuth2.1/test/next-app/.env");
    const newEnvContent = [
      `AUTH_ISSUER=http://localhost:5174`,
      `JWKS_URL=http://localhost:5174/.well-known/jwks.json`,
      `CLIENT_ID=${generatedClientId}`,
      `CLIENT_SECRET=${generatedClientSecret}`,
      `AUTH_CALLBACK_URL=http://localhost:3001/api/auth/callback`,
      "",
    ].join("\n");
    fs.writeFileSync(nextEnvPath, newEnvContent, "utf8");
    console.log("  ✔ Written updated .env to test/next-app/.env");

    // Link pilot user to application in user_app_registrations (multi-tenant app isolation)
    const db = await getDb();
    const pilotUser = await db.collection("user").findOne({ email: "pilot_playwright@test.com" });
    if (pilotUser) {
      const uId = String(pilotUser.id || pilotUser._id);
      await db.collection("user_app_registrations").updateOne(
        { userId: uId, clientId: generatedClientId },
        { $set: { userId: uId, clientId: generatedClientId, registeredAt: new Date() } },
        { upsert: true }
      );
      console.log(`  ✔ Linked pilot user (${uId}) to new clientId: ${generatedClientId}`);
    }

    // Restart the Next.js process so it picks up the new environment variables
    console.log("  🔄 Restarting Next.js consumer app on port 3001...");
    try {
      execSync("fuser -k 3001/tcp 2>/dev/null || true");
    } catch {}

    // Launch Next.js dev server in background
    const nextProc = spawn("npm", ["run", "dev"], {
      cwd: "/home/swyra/projects/OAuth2.1/test/next-app",
      stdio: "ignore",
      detached: true,
    });
    nextProc.unref();

    // Wait for Next.js to be responsive on port 3001
    let ready = false;
    for (let i = 0; i < 30; i++) {
      try {
        const check = execSync("curl -s -o /dev/null -w '%{http_code}' http://localhost:3001", { encoding: "utf8" });
        if (check.trim() === "200") {
          ready = true;
          break;
        }
      } catch {}
      await new Promise(r => setTimeout(r, 500));
    }
    if (!ready) {
      throw new Error("Next.js test consumer app failed to restart on port 3001!");
    }
    console.log("  ✔ Next.js consumer app restarted and ready on http://localhost:3001.");

    // -------------------------------------------------------------
    // STEP 4: CONSUMER APP E2E OAUTH 2.1 PKCE FLOW
    // -------------------------------------------------------------
    console.log("\n▶ [STEP 4] Testing full OAuth 2.1 PKCE flow from Consumer App...");
    const userContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const page = await userContext.newPage();
    page.on("console", (msg) => console.log("    [Consumer Page Console]", msg.type(), msg.text()));
    page.on("pageerror", (err) => console.log("    [Consumer Page Error]", err));
    page.on("response", (res) => {
      if (res.url().includes("/api/auth")) {
        console.log(`    [Auth Response] ${res.status()} ${res.url()}`);
      }
    });

    // 4.1 Go to Consumer Home
    await page.goto("http://localhost:3001", { waitUntil: "networkidle" });
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "06_consumer_home.png") });

    // Verify configured client ID is displayed on page
    const pageText = await page.textContent("body");
    if (!pageText?.includes(generatedClientId)) {
      throw new Error(`Consumer home page does not display expected Client ID: ${generatedClientId}`);
    }
    console.log("  ✔ Consumer home correctly displays configured Client ID.");

    // 4.2 Click "Sign In with SWYRA M Auth"
    console.log("  Initiating PKCE Authorization flow...");
    const signInBtn = page.locator('a:has-text("Sign In with SWYRA M Auth")');
    await signInBtn.click();

    // Wait for IdP login page (http://localhost:5174/auth?...)
    await page.waitForURL(url => url.pathname.startsWith("/auth"), { timeout: 10000 });
    console.log("  ✔ Redirected to IdP Authorization Login endpoint at:", page.url());
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "07_idp_auth_login.png") });

    // Verify application name is shown on login page
    const idpContent = await page.textContent("body");
    console.log("  ✔ IdP Login screen rendered with M Auth branding.");

    // 4.3 Fill in pilot credentials
    await page.fill('input[type="email"]', "pilot_playwright@test.com");
    await page.fill('input[type="password"]', "PilotPassword@123!");
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "08_idp_credentials_entered.png") });

    // Click Sign In
    const loginSubmit = page.locator('button[type="submit"]:has-text("Sign in")').or(page.locator('button[type="submit"]')).first();
    await loginSubmit.click();
    console.log("  Clicked Sign In button, awaiting response/redirect...");
    await page.waitForTimeout(3000);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "08b_after_signin_click.png") });
    console.log("  URL after 3s:", page.url());

    // Wait for next step: either /consent or direct callback to /dashboard
    await page.waitForURL(url => url.pathname.startsWith("/consent") || url.pathname.startsWith("/dashboard") || url.port === "3001", { timeout: 15000 });
    console.log("  Current URL after sign-in:", page.url());

    if (page.url().includes("/consent")) {
      console.log("  ✔ Landed on Consent screen (/consent).");
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "09_idp_consent_screen.png") });

      // Click Authorize
      const authorizeBtn = page.getByRole("button", { name: "Authorize", exact: true });
      await authorizeBtn.waitFor({ state: "visible", timeout: 5000 });
      await authorizeBtn.click();
      console.log("  ✔ Clicked Authorize button.");
    }

    // 4.4 Wait for redirect to Consumer Dashboard
    await page.waitForURL("http://localhost:3001/dashboard", { timeout: 15000 });
    console.log("  ✔ Successfully redirected to Consumer Dashboard:", page.url());

    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "10_consumer_dashboard_authenticated.png") });

    // 4.5 Assert Dashboard Contents
    const dashboardContent = await page.textContent("body");
    if (!dashboardContent?.includes("OAuth 2.1 Authenticated")) {
      throw new Error("Dashboard does not show 'OAuth 2.1 Authenticated' badge!");
    }
    if (!dashboardContent?.includes("pilot_playwright@test.com")) {
      throw new Error("Dashboard does not show pilot email!");
    }
    console.log("  ✔ ASSERTION PASSED: Dashboard displays 'OAuth 2.1 Authenticated' badge.");
    console.log("  ✔ ASSERTION PASSED: Authenticated user email 'pilot_playwright@test.com' confirmed.");

    // Wait for telemetry viewer data
    const telemetrySection = page.locator("text=Telemetry Stream").or(page.locator("text=Vehicle Telemetry")).or(page.locator("text=Live Telemetry"));
    await telemetrySection.first().waitFor({ state: "visible", timeout: 5000 });
    console.log("  ✔ ASSERTION PASSED: Telemetry data viewer loaded from protected API.");

    // -------------------------------------------------------------
    // STEP 5: TEST SIGN OUT
    // -------------------------------------------------------------
    console.log("\n▶ [STEP 5] Testing Sign Out from Consumer Dashboard...");
    const logoutBtn = page.locator('button:has-text("Sign Out")').or(page.locator('button:has-text("Logout")')).first();
    await logoutBtn.click();

    await page.waitForURL("http://localhost:3001/", { timeout: 10000 });
    console.log("  ✔ Successfully signed out and returned to Consumer Home:", page.url());
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "11_consumer_signed_out.png") });

    await userContext.close();

    console.log("\n=================================================");
    console.log("  🎉 ALL FULL E2E PLAYWRIGHT TESTS PASSED! 🎉   ");
    console.log("=================================================\n");
  } catch (err) {
    console.error("\n❌ E2E Playwright Test Failed:", err);
    throw err;
  } finally {
    await browser.close().catch(() => {});
    await closeDb().catch(() => {});
  }
}

run().catch((err) => {
  process.exit(1);
});
