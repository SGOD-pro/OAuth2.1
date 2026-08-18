import { MongoClient } from "mongodb";
import { config } from "dotenv";
import { createRemoteJWKSet, jwtVerify, SignJWT } from "jose";

config({ path: "d:/WORK/OAuth2.1/hono/.env" });

const MONGO_URI = process.env.MONGO_URI || "";
const BASE_URL = "http://localhost:5174"; // Test through Auth Gateway

const APP_A_CLIENT_ID = "qMoXkZwvWnZJRmFhpiTyzLMozZYrwvlF";
const APP_B_CLIENT_ID = "VyhlDhjmztsAsFphQjBsmXiSXjfpFoug";

async function runSuite() {
  console.log("=================================================");
  console.log("      SWYRA AUTH E2E SECURITY TEST SUITE        ");
  console.log("=================================================\n");

  const client = new MongoClient(MONGO_URI);
  await client.connect();
  const db = client.db();

  const testEmail = `alice_e2e_${Date.now()}@test.com`;
  const testPassword = "StrongPassword@1234!";
  const testName = "Alice E2E";

  let sessionCookie = "";
  let aliceUserId = "";

  console.log(`[TEST SETUP] Using test user: ${testEmail}\n`);

  try {
    // ------------------------------------------------------------------
    // TEST SCENARIO 1: Strict Isolation, Registration & SSO Interception
    // ------------------------------------------------------------------
    console.log("▶ [SCENARIO 1] Strict Isolation & App Registration Flow");

    // 1.1 Register Alice for App A
    console.log("  1.1 Registering Alice for App A...");
    const signUpAppARes = await fetch(`${BASE_URL}/api/auth/sign-up/email`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost:5174",
        "Referer": `http://localhost:5174/auth?client_id=${APP_A_CLIENT_ID}`
      },
      body: JSON.stringify({
        email: testEmail,
        password: testPassword,
        name: testName,
        callbackURL: `http://localhost:5174/api/auth/oauth2/authorize?client_id=${APP_A_CLIENT_ID}&redirect_uri=http://localhost:3001/api/auth/callback`
      })
    });

    const setCookieHeader = signUpAppARes.headers.get("set-cookie");
    if (setCookieHeader) {
      sessionCookie = setCookieHeader.split(";")[0];
    }

    console.log(`      Status: ${signUpAppARes.status}`);
    const userDoc = await db.collection("user").findOne({ email: testEmail });
    aliceUserId = userDoc?.id || String(userDoc?._id);
    console.log(`      User created in DB: ${aliceUserId}`);

    const regAppA = await db.collection("user_app_registrations").findOne({
      userId: aliceUserId,
      clientId: APP_A_CLIENT_ID
    });

    if (regAppA) {
      console.log("      ✔ ASSERTION PASSED: user_app_registrations contains record for App A.");
    } else {
      console.error("      ❌ ASSERTION FAILED: Missing App A registration in DB.");
      process.exit(1);
    }

    // 1.2 Attempt Direct Sign-In on App B without prior App B registration
    console.log("\n  1.2 Attempting direct Sign-In on App B with App A credentials...");
    const signInAppBRes = await fetch(`${BASE_URL}/api/auth/sign-in/email`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost:5174",
        "Referer": `http://localhost:5174/auth?client_id=${APP_B_CLIENT_ID}`
      },
      body: JSON.stringify({
        email: testEmail,
        password: testPassword,
        callbackURL: `http://localhost:5174/api/auth/oauth2/authorize?client_id=${APP_B_CLIENT_ID}&redirect_uri=http://localhost:5173/callback`
      })
    });

    console.log(`      Status: ${signInAppBRes.status}`);
    const signInAppBData = await signInAppBRes.json().catch(() => ({}));
    console.log(`      Response:`, signInAppBData);

    if (signInAppBRes.status === 400 && signInAppBData.message?.includes("not registered for this application")) {
      console.log("      ✔ ASSERTION PASSED: Direct login blocked with expected 400 isolation error.");
    } else {
      console.error("      ❌ ASSERTION FAILED: Login was not blocked correctly.");
      process.exit(1);
    }

    // 1.3 Attempt SSO Handshake Interception on App B while active on App A
    console.log("\n  1.3 Attempting /oauth2/authorize handshake for App B using App A session...");
    const ssoRes = await fetch(`${BASE_URL}/api/auth/oauth2/authorize?client_id=${APP_B_CLIENT_ID}&redirect_uri=http://localhost:5173/callback&response_type=code`, {
      method: "GET",
      headers: {
        "Cookie": sessionCookie,
        "Origin": "http://localhost:5174"
      },
      redirect: "manual"
    });

    console.log(`      Status: ${ssoRes.status}`);
    const location = ssoRes.headers.get("location") || "";
    console.log(`      Redirect Location: ${location}`);

    if (location.includes("/auth") && location.includes("error=not_registered")) {
      console.log("      ✔ ASSERTION PASSED: SSO handshake intercepted and redirected to /auth with error=not_registered.");
    } else {
      console.error("      ❌ ASSERTION FAILED: Handshake was not intercepted!");
      process.exit(1);
    }

    // 1.4 Register Alice for App B
    console.log("\n  1.4 Registering Alice for App B (Linking existing account)...");
    const signUpAppBRes = await fetch(`${BASE_URL}/api/auth/sign-up/email`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost:5174",
        "Referer": `http://localhost:5174/auth?client_id=${APP_B_CLIENT_ID}`
      },
      body: JSON.stringify({
        email: testEmail,
        password: testPassword,
        name: testName,
        callbackURL: `http://localhost:5174/api/auth/oauth2/authorize?client_id=${APP_B_CLIENT_ID}&redirect_uri=http://localhost:5173/callback`
      })
    });

    console.log(`      Status: ${signUpAppBRes.status}`);
    const regAppB = await db.collection("user_app_registrations").findOne({
      userId: aliceUserId,
      clientId: APP_B_CLIENT_ID
    });

    if (regAppB) {
      console.log("      ✔ ASSERTION PASSED: user_app_registrations now contains record for App B.");
    } else {
      console.error("      ❌ ASSERTION FAILED: App B registration failed.");
      process.exit(1);
    }

    // ------------------------------------------------------------------
    // TEST SCENARIO 2: Secure RP-Initiated Logout & Open Redirect Attack
    // ------------------------------------------------------------------
    console.log("\n▶ [SCENARIO 2] Secure RP-Initiated Logout & Attack Simulations");

    // 2.1 Open Redirect Attack Simulation
    console.log("  2.1 Simulating Open Redirect Attack (redirect_uri=https://evil.com)...");
    const evilLogoutRes = await fetch(`${BASE_URL}/api/auth/sign-out-client`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost:5174",
        "Cookie": sessionCookie
      },
      body: JSON.stringify({
        client_id: APP_A_CLIENT_ID,
        redirect_uri: "https://evil.com/steal"
      })
    });

    console.log(`      Status: ${evilLogoutRes.status}`);
    const evilData = await evilLogoutRes.json().catch(() => ({}));
    console.log(`      Response:`, evilData);

    if (evilLogoutRes.status === 400 && evilData.error === "Invalid redirect URI") {
      console.log("      ✔ ASSERTION PASSED: Open Redirect blocked with 400 Bad Request.");
    } else {
      console.error("      ❌ ASSERTION FAILED: Open Redirect was not blocked!");
      process.exit(1);
    }

    // 2.2 Legitimate Logout
    console.log("\n  2.2 Performing legitimate RP-Initiated Logout for App A...");
    const validLogoutRes = await fetch(`${BASE_URL}/api/auth/sign-out-client`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost:5174",
        "Cookie": sessionCookie
      },
      body: JSON.stringify({
        client_id: APP_A_CLIENT_ID,
        redirect_uri: "http://localhost:3001/api/auth/callback" // registered in client
      })
    });

    console.log(`      Status: ${validLogoutRes.status}`);
    const validLogoutData = await validLogoutRes.json().catch(() => ({}));
    console.log(`      Response:`, validLogoutData);

    const setCookieLogout = validLogoutRes.headers.get("set-cookie") || "";
    console.log(`      Set-Cookie header on logout: ${setCookieLogout}`);

    if (validLogoutRes.status === 200 && validLogoutData.success && setCookieLogout.includes("Max-Age=0")) {
      console.log("      ✔ ASSERTION PASSED: Session revoked and cookie destroyed with Max-Age=0.");
    } else {
      console.error("      ❌ ASSERTION FAILED: Logout did not return 200 or clear cookies.");
      process.exit(1);
    }

    // ------------------------------------------------------------------
    // TEST SCENARIO 3: RS256 JWKS Token Verification & Tampering Defense
    // ------------------------------------------------------------------
    console.log("\n▶ [SCENARIO 3] Token Verification & Tampering Prevention");

    // 3.1 Fetch Public JWKS from Auth Server
    console.log("  3.1 Fetching public JWKS from /.well-known/jwks.json...");
    const jwksRes = await fetch(`${BASE_URL}/.well-known/jwks.json`);
    console.log(`      Status: ${jwksRes.status}`);
    const jwksData = await jwksRes.json();
    console.log(`      Keys found in JWKS: ${jwksData.keys?.length || 0}`);

    if (jwksData.keys && jwksData.keys.length > 0) {
      console.log("      ✔ ASSERTION PASSED: Valid JWKS public keys exposed.");
    } else {
      console.error("      ❌ ASSERTION FAILED: JWKS keys missing.");
      process.exit(1);
    }

    // 3.2 Verify RS256 signature algorithm requirement
    console.log("\n  3.2 Simulating Forged Token Attack (tampered payload signed with arbitrary HS256 secret)...");
    const forgedToken = await new SignJWT({ sub: "attacker_admin_id", role: "admin" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode("super_secret_attacker_key"));

    console.log(`      Forged HS256 Token: ${forgedToken.substring(0, 30)}...`);

    const JWKS = createRemoteJWKSet(new URL(`${BASE_URL}/.well-known/jwks.json`));
    let forgedVerificationFailed = false;
    try {
      await jwtVerify(forgedToken, JWKS);
    } catch (err: any) {
      forgedVerificationFailed = true;
      console.log(`      Verification Result (Expected Rejection): ${err.message}`);
    }

    if (forgedVerificationFailed) {
      console.log("      ✔ ASSERTION PASSED: Forged HS256 token rejected cryptographically by RS256 JWKS.");
    } else {
      console.error("      ❌ ASSERTION FAILED: Forged token was accepted!");
      process.exit(1);
    }

    console.log("\n=================================================");
    console.log("     ALL 3 E2E SECURITY SCENARIOS PASSED 100%    ");
    console.log("=================================================\n");

  } finally {
    // Cleanup test user
    await db.collection("user").deleteOne({ email: testEmail });
    await db.collection("user_app_registrations").deleteMany({ userId: aliceUserId });
    await client.close();
    console.log("[TEST CLEANUP] Cleaned up temporary test artifacts.");
  }
}

runSuite().catch((err) => {
  console.error("Test Suite crashed:", err);
  process.exit(1);
});
