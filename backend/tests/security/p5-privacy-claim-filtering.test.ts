import assert from "node:assert/strict";
import crypto from "node:crypto";
import { describe, it, before, after } from "node:test";
import { decodeJwt } from "jose";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { enrollAndLoginAdminMfa } from "../fixtures/admin-mfa-fixture";

describe("P5.4 Owner Privacy & Consumer Claim Filtering", { timeout: 60_000 }, () => {
  let app: any;
  let db: any;
  let suiteCtx: Awaited<ReturnType<typeof setupSuiteDatabase>> | undefined;
  let origin: string;
  let gatewaySecret: string;

  before(async () => {
    process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
    process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
    process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
    process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
    process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
    isolateTestEnvironment();
    process.env.NODE_ENV = "test";
    process.env.ALLOW_PUBLIC_SIGNUP = "true";
    process.env.REQUIRE_EMAIL_VERIFICATION = "false";
    process.env.TOTP_ENCRYPTION_KEY = process.env.TOTP_ENCRYPTION_KEY || "c".repeat(32);
    process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
    gatewaySecret = process.env.INTERNAL_GATEWAY_SECRET;
    origin = process.env.FRONTEND_URL;

    suiteCtx = await setupSuiteDatabase("p5_privacy_claims");
    const { getDb } = await import("../../src/db/mongo");
    db = await getDb();
    const { default: appInstance } = await import("../../src/app");
    app = appInstance;
  });

  after(async () => {
    const { closeDb } = await import("../../src/db/mongo");
    await closeDb();
    await suiteCtx?.cleanup();
  });

  function headers(extra: Record<string, string> = {}) {
    return {
      "Content-Type": "application/json",
      Origin: origin,
      "x-gateway-secret": gatewaySecret,
      "x-csrf-token": "any",
      "x-forwarded-for": "198.51.100.94, 10.0.0.1",
      ...extra,
    };
  }

  function extractCookies(res: Response): string {
    const raw = (res.headers as any).getSetCookie?.() || [];
    return raw.map((c: string) => c.split(";")[0]).join("; ");
  }

  async function issueTokens(cookie: string, clientId: string, clientSecret: string, redirectUri: string, scope: string) {
    const verifier = crypto.randomBytes(32).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    const state = crypto.randomBytes(16).toString("hex");

    const authUrl = `/api/auth/oauth2/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scope)}&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`;
    const authRes = await app.request(authUrl, { method: "GET", headers: headers({ Cookie: cookie }) });
    if (authRes.status !== 302) {
      assert.fail(`Expected 302 from authorize, got ${authRes.status}: ${await authRes.text()}`);
    }
    let location = authRes.headers.get("location") || "";
    if (location.includes("/consent")) {
      const consentQuery = new URL(location).search.slice(1);
      const consentRes = await app.request("/api/auth/oauth2/consent", {
        method: "POST",
        headers: headers({ Cookie: cookie }),
        body: JSON.stringify({ accept: true, scope, oauth_query: consentQuery }),
      });
      assert.equal(consentRes.status, 200);
      const consentJson = await consentRes.json();
      location = consentJson.redirectURI || consentJson.url || "";
    }
    const code = new URL(location, "http://localhost:3000").searchParams.get("code");
    assert.ok(code, `Authorization code must be issued (location: ${location})`);

    const tokenRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: headers({
        "Content-Type": "application/x-www-form-urlencoded",
      }),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      }).toString(),
    });
    if (tokenRes.status !== 200) {
      assert.fail(`Expected 200 from token, got ${tokenRes.status}: ${await tokenRes.text()} (secretPresent=${Boolean(clientSecret)})`);
    }
    return await tokenRes.json();
  }

  it("enforces versioned defaults, owner context isolation, and claim filtering across issuance, refresh, and userinfo", async () => {
    const emailA = `p54_a_${Date.now()}@example.com`;
    const emailB = `p54_b_${Date.now()}@example.com`;
    const pass = "P54!Privacy#Pass123";

    await app.request("/api/auth/sign-up/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailA, password: pass, name: "User Alpha" }) });
    await db.collection("user").updateOne({ email: emailA }, { $set: { emailVerified: true } });
    const signInA = await app.request("/api/auth/sign-in/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailA, password: pass }) });
    const cookieA = extractCookies(signInA);
    const userA = await db.collection("user").findOne({ email: emailA });

    await app.request("/api/auth/sign-up/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailB, password: pass, name: "User Beta" }) });
    await db.collection("user").updateOne({ email: emailB }, { $set: { emailVerified: true } });
    const signInB = await app.request("/api/auth/sign-in/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailB, password: pass }) });
    const cookieB = extractCookies(signInB);

    const regSet = await db.collection("browser_session_sets").findOne({ "entries.userId": String(userA._id) });
    const entryA = regSet.entries.find((e: any) => e.userId === String(userA._id));
    assert.ok(entryA, "Account A must be in browser_session_sets");

    const ctxResA = await app.request("/api/identity/contexts", { method: "POST", headers: headers({ Cookie: cookieA }), body: JSON.stringify({ entryId: entryA.entryId, purpose: "owner_dashboard" }) });
    assert.equal(ctxResA.status, 201);
    const ctxA = (await ctxResA.json()).contextHandle;

    // 1. Default privacy settings for existing user (v1, both true)
    const getPrivA = await app.request("/api/identity/privacy", { method: "GET", headers: headers({ Cookie: cookieA, "x-identity-context": ctxA }) });
    assert.equal(getPrivA.status, 200);
    const privJsonA = await getPrivA.json();
    assert.equal(privJsonA.privacyVersion, 1);
    assert.equal(privJsonA.shareEmail, true);
    assert.equal(privJsonA.shareProfile, true);

    // Register open confidential client via admin API
    const adminEmail = `p54_admin_${Date.now()}@example.com`;
    await app.request("/api/auth/sign-up/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: adminEmail, password: pass, name: "P54 Admin" }) });
    await db.collection("user").updateOne({ email: adminEmail }, { $set: { emailVerified: true, role: "super-admin" } });
    const adminCookie = await enrollAndLoginAdminMfa(app, adminEmail, pass, headers);

    const redirectUri = "https://consumer.example.com/callback";
    const clientRes = await app.request("/api/admin/clients", {
      method: "POST",
      headers: headers({ Cookie: adminCookie }),
      body: JSON.stringify({
        name: "P54 Consumer",
        redirectUris: [redirectUri],
        clientType: "public",
        accessPolicy: "open",
      }),
    });
    assert.equal(clientRes.status, 201);
    const clientJson = await clientRes.json();
    const clientId = clientJson.client?.clientId || clientJson.clientId;
    const clientSecret = clientJson.client?.clientSecret || clientJson.clientSecret;
    await db.collection("oauthApplication").updateOne({ clientId }, { $set: { skipConsent: true } });

    // 2. Scope absent (openid only): email and name absent even when sharing is on
    const { filterConsumerClaims } = await import("../../src/identity/claim-policy");
    const openidFiltered = filterConsumerClaims(
      { sub: String(userA._id), email: emailA, email_verified: true, name: "User Alpha" },
      "openid",
      { shareEmail: true, shareProfile: true }
    );
    assert.equal(openidFiltered.sub, String(userA._id));
    assert.equal(openidFiltered.email, undefined);
    assert.equal(openidFiltered.name, undefined);

    // 3. Both scope and sharing allowed
    const fullTokensA = await issueTokens(cookieA, clientId, clientSecret, redirectUri, "openid profile email offline_access");
    const fullIdClaimsA = decodeJwt(fullTokensA.id_token);
    if (fullIdClaimsA.email !== undefined) {
      assert.equal(fullIdClaimsA.email, emailA);
    }
    if (fullIdClaimsA.name !== undefined) {
      assert.equal(fullIdClaimsA.name, "User Alpha");
    }

    const uiFullA = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: headers({ Authorization: `Bearer ${fullTokensA.access_token}` }) });
    assert.equal(uiFullA.status, 200);
    const uiFullJsonA = await uiFullA.json();
    assert.equal(uiFullJsonA.email, emailA);
    assert.equal(uiFullJsonA.name, "User Alpha");

    // 4. Turn sharing off for A -> affects subsequent userinfo & refresh, leaves B unchanged
    const patchPrivA = await app.request("/api/identity/privacy", {
      method: "PATCH",
      headers: headers({ Cookie: cookieA, "x-identity-context": ctxA }),
      body: JSON.stringify({ shareEmail: false, shareProfile: false }),
    });
    assert.equal(patchPrivA.status, 200);

    const uiAfterA = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: headers({ Authorization: `Bearer ${fullTokensA.access_token}` }) });
    assert.equal(uiAfterA.status, 200);
    const uiAfterJsonA = await uiAfterA.json();
    assert.equal(uiAfterJsonA.sub, String(userA._id));
    assert.equal(uiAfterJsonA.email, undefined);
    assert.equal(uiAfterJsonA.name, undefined);

    const refreshResA = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: headers({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: fullTokensA.refresh_token,
        client_id: clientId,
      }).toString(),
    });
    assert.equal(refreshResA.status, 200);
    const refreshedA = await refreshResA.json();
    const refreshedClaimsA = decodeJwt(refreshedA.id_token);
    assert.equal(refreshedClaimsA.sub, String(userA._id));
    assert.equal(refreshedClaimsA.email, undefined);
    assert.equal(refreshedClaimsA.name, undefined);

    // Owner's own /api/identity/me still sees emailA
    const meA = await app.request("/api/identity/me", { method: "GET", headers: headers({ Cookie: cookieA, "x-identity-context": ctxA }) });
    assert.equal((await meA.json()).email, emailA);

    // User B still shares email and profile
    const fullTokensB = await issueTokens(cookieB, clientId, clientSecret, redirectUri, "openid profile email");
    const uiFullB = await app.request("/api/auth/oauth2/userinfo", { method: "GET", headers: headers({ Authorization: `Bearer ${fullTokensB.access_token}` }) });
    assert.equal(uiFullB.status, 200);
    const uiFullJsonB = await uiFullB.json();
    assert.equal(uiFullJsonB.email, emailB);
    assert.equal(uiFullJsonB.name, "User Beta");
  });
});
