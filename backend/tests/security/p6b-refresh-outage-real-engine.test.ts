import assert from "node:assert/strict";
import crypto from "node:crypto";
import { after, before, describe, it } from "node:test";
import { Hono } from "hono";
import { decodeProtectedHeader, jwtVerify } from "jose";
import { ObjectId } from "mongodb";
import { InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import { MongoProfileCollection, writeProtectedProfile } from "../../src/identity/protected-profile-store";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

let suite: Awaited<ReturnType<typeof setupSuiteDatabase>> | undefined;
let db: any;
let app: any;
let authProvider: any;
let getIdpPublicKey: any;
let hashToken: any;
let createOAuthTokenHandler: any;

function makePkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

describe("P6b Real-Engine Retryable Refresh on Transient Protected-Profile Outage", { timeout: 60_000 }, () => {
  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p6b_refresh_outage_real");
    Object.assign(process.env, {
      NODE_ENV: "test",
      MONGO_URI: suite.uri,
      DB_NAME: suite.dbName,
      BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000",
      FRONTEND_URL: "http://localhost:5174",
      INTERNAL_GATEWAY_SECRET: "g".repeat(32),
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret",
      OPEN_APP_MEMBERSHIP_BYPASS_ENABLED: "true",
    });

    const { getDb } = await import("../../src/db/mongo");
    db = await getDb();
    ({ authProvider } = await import("../../src/utils/auth"));
    ({ getIdpPublicKey } = await import("../../src/middleware/admin-auth"));
    ({ hashToken } = await import("../../src/utils/security"));
    const authTokenMod = await import("../../src/routes/auth-token");
    createOAuthTokenHandler = (authTokenMod as any).createOAuthTokenHandler;
    ({ default: app } = await import("../../src/app"));
  });

  after(async () => {
    const { closeDb } = await import("../../src/db/mongo");
    await closeDb();
    await suite?.cleanup();
  });

  it("returns 503 on transient outage without consuming engine token and succeeds on retry after recovery", async () => {
    assert.equal(typeof createOAuthTokenHandler, "function", "createOAuthTokenHandler must be exported");

    const email = `legacy.real.${Date.now()}@example.com`;
    const pass = "RealEngine!Pass123";
    const created = await authProvider.api.signUpEmail({
      body: { email, password: pass, name: "Legacy Real User" },
    });
    const userId = String(created?.user?.id || created?.id);
    await db.collection("user").updateOne(
      { $or: [{ id: userId }, ...(ObjectId.isValid(userId) ? [{ _id: new ObjectId(userId) }] : [])] },
      { $set: { emailVerified: true, shareEmail: true, shareProfile: true } }
    );

    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "http://localhost:5174" },
      body: JSON.stringify({ email, password: pass }),
    });
    assert.equal(loginRes.status, 200);
    const cookieMatch = (loginRes.headers.get("set-cookie") || "").match(/better-auth\.session_token=([^;]+)/);
    assert.ok(cookieMatch);
    const sessionCookie = `better-auth.session_token=${cookieMatch[1]}`;

    const clientId = `real-refresh-pub-${Date.now()}`;
    await db.collection("oauthClient").insertOne({
      clientId,
      name: "Real Refresh Public",
      redirectUrls: ["https://pub.example.com/cb"],
      redirectUris: ["https://pub.example.com/cb"],
      type: "public",
      clientType: "public",
      accessPolicy: "open",
      isPublic: true,
      is_public: true,
      tokenEndpointAuthMethod: "none",
      token_endpoint_auth_method: "none",
      skipConsent: true,
      disabled: false,
      createdAt: new Date(),
    });

    const baseProvider = new InMemoryAccountKeyProvider();
    let forceReadableAfterDenial = false;
    const provider = {
      wrapDataKey: baseProvider.wrapDataKey.bind(baseProvider),
      denyAccess: baseProvider.denyAccess.bind(baseProvider),
      scheduleDestruction: baseProvider.scheduleDestruction.bind(baseProvider),
      getKeyState: baseProvider.getKeyState.bind(baseProvider),
      setOutage: baseProvider.setOutage.bind(baseProvider),
      async unwrapDataKey(accountId: string, keyRef: string, wrappedKey: string) {
        if (forceReadableAfterDenial) {
          const prev = (baseProvider as any).states.get(keyRef);
          if (prev) (baseProvider as any).states.set(keyRef, { ...prev, state: "active" });
        }
        return baseProvider.unwrapDataKey(accountId, keyRef, wrappedKey);
      },
    };
    const mongoStore = new MongoProfileCollection(db);
    const written = await writeProtectedProfile({
      store: mongoStore,
      provider,
      accountId: userId,
      name: "Protected Real User",
      email: "real.protected@example.com",
    });

    const tokenApp = new Hono();
    tokenApp.post("/api/auth/oauth2/token", createOAuthTokenHandler({
      protectedProfileStore: mongoStore,
      accountKeyProvider: provider,
      migrationMode: "strict",
    }));

    const pkce = makePkce();
    const authRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent("https://pub.example.com/cb")}&response_type=code&scope=${encodeURIComponent("openid profile email offline_access")}&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=s1`,
      { method: "GET", headers: { Cookie: sessionCookie }, redirect: "manual" }
    );
    assert.equal(authRes.status, 302);
    const code = new URL(authRes.headers.get("location") || "").searchParams.get("code");
    assert.ok(code);

    const codeExchangeRes = await tokenApp.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: "https://pub.example.com/cb",
        code_verifier: pkce.verifier,
        client_id: clientId,
      }).toString(),
    });
    assert.equal(codeExchangeRes.status, 200);
    const codeTokens = await codeExchangeRes.json();
    assert.ok(codeTokens.refresh_token, "Real Better Auth engine must issue a refresh_token");
    assert.ok(codeTokens.id_token, "Real Better Auth engine must issue an id_token");
    const rt1 = codeTokens.refresh_token as string;
    const famBefore = await db.collection("oauth_token_families").findOne({ clientId, userId });
    assert.equal(famBefore?.status, "active");
    const rtCountBefore = await db.collection("oauthRefreshToken").countDocuments({ clientId, userId });
    const atCountBefore = await db.collection("oauthAccessToken").countDocuments({ clientId, userId });

    // 1. Transient outage on real refresh -> 503, zero tokens/plaintext, zero consumption/rotation, no stranded lease
    provider.setOutage(true);
    const refreshReqBody = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: rt1,
      client_id: clientId,
    }).toString();
    const outageRes = await tokenApp.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: refreshReqBody,
    });
    assert.equal(outageRes.status, 503);
    const outageText = await outageRes.text();
    assert.equal(outageText.includes("Protected Real User"), false);
    assert.equal(outageText.includes("real.protected@example.com"), false);
    assert.equal(outageText.includes("Legacy Real User"), false);
    assert.equal(outageText.includes(email), false);
    const outageJson = JSON.parse(outageText);
    assert.equal(outageJson.access_token, undefined);
    assert.equal(outageJson.refresh_token, undefined);
    assert.equal(outageJson.id_token, undefined);

    const famDuringOutage = await db.collection("oauth_token_families").findOne({ familyId: famBefore.familyId });
    assert.equal(famDuringOutage?.status, "active", "Family must stay active on transient outage");
    assert.equal(famDuringOutage?.activeTokenHash, hashToken(rt1, "hex"), "Original token hash must stay active");
    assert.equal(famDuringOutage?.consumedTokenHashes?.length || 0, 0, "Original token must not be consumed");
    assert.equal(famDuringOutage?.rotating, false, "Rotation lease must not be stranded");
    assert.equal(famDuringOutage?.rotationOwner, undefined);
    assert.equal(await db.collection("oauthRefreshToken").countDocuments({ clientId, userId }), rtCountBefore);
    assert.equal(await db.collection("oauthAccessToken").countDocuments({ clientId, userId }), atCountBefore);

    // 2. Restore provider and retry the exact same rt1 through real Better Auth -> 200!
    provider.setOutage(false);
    const retryRes = await tokenApp.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: refreshReqBody,
    });
    assert.equal(retryRes.status, 200, "Original refresh token must succeed after provider recovery");
    const retryTokens = await retryRes.json();
    assert.ok(retryTokens.access_token);
    assert.ok(retryTokens.refresh_token);
    assert.notEqual(retryTokens.refresh_token, rt1);

    const idHeader = decodeProtectedHeader(retryTokens.id_token);
    const pubKey = await getIdpPublicKey(idHeader.kid);
    assert.ok(pubKey);
    const verifiedId = await jwtVerify(retryTokens.id_token, pubKey, { algorithms: ["RS256"] });
    assert.equal(verifiedId.payload.name, "Protected Real User");
    assert.equal(verifiedId.payload.email, "real.protected@example.com");
    assert.equal(
      verifiedId.payload.at_hash,
      crypto.createHash("sha256").update(retryTokens.access_token).digest().subarray(0, 16).toString("base64url")
    );

    // 3. Concurrent refresh on rt2 permits at most one replacement
    const rt2 = retryTokens.refresh_token as string;
    const [concA, concB] = await Promise.all([
      tokenApp.request("/api/auth/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt2, client_id: clientId }).toString(),
      }),
      tokenApp.request("/api/auth/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt2, client_id: clientId }).toString(),
      }),
    ]);
    const winners = [concA, concB].filter((r) => r.status === 200);
    assert.equal(winners.length, 1, "Concurrent refresh must allow at most one replacement");
    const rt3 = (await winners[0].json()).refresh_token as string;

    // 4. Replay safeguard after successful rotation on active family -> 401 and revokes family
    await db.collection("oauth_token_families").updateOne(
      { familyId: famBefore.familyId },
      { $set: { rotatedAt: new Date(Date.now() - 60_000), updatedAt: new Date(Date.now() - 60_000) } }
    );
    const replayRes = await tokenApp.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: refreshReqBody,
    });
    assert.equal(replayRes.status, 401);
    const famAfterReplay = await db.collection("oauth_token_families").findOne({ familyId: famBefore.familyId });
    assert.equal(famAfterReplay?.status, "revoked");
    assert.equal(famAfterReplay?.rotating, false);

    // 5. Key denial on a fresh active family -> 403, no tokens/plaintext, no stranded lease, family durably revoked
    const pkceDeny = makePkce();
    const authDenyRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent("https://pub.example.com/cb")}&response_type=code&scope=${encodeURIComponent("openid profile email offline_access")}&code_challenge=${pkceDeny.challenge}&code_challenge_method=S256&state=s_deny`,
      { method: "GET", headers: { Cookie: sessionCookie }, redirect: "manual" }
    );
    const codeDeny = new URL(authDenyRes.headers.get("location") || "").searchParams.get("code");
    const exDenyRes = await tokenApp.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: codeDeny!,
        redirect_uri: "https://pub.example.com/cb",
        code_verifier: pkceDeny.verifier,
        client_id: clientId,
      }).toString(),
    });
    assert.equal(exDenyRes.status, 200);
    const denyTokens = await exDenyRes.json();
    const rtDeny = denyTokens.refresh_token as string;
    const famDenyBefore = await db.collection("oauth_token_families").findOne({ activeTokenHash: hashToken(rtDeny, "hex") });
    assert.equal(famDenyBefore?.status, "active");

    await provider.denyAccess(userId, written.nameEnvelope.keyRef, "owner_revoked");
    const deniedRes = await tokenApp.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rtDeny, client_id: clientId }).toString(),
    });
    assert.equal(deniedRes.status, 403);
    const deniedText = await deniedRes.text();
    assert.equal(deniedText.includes("Protected Real User"), false);
    assert.equal(deniedText.includes("real.protected@example.com"), false);
    assert.equal(deniedText.includes("Legacy Real User"), false);
    const deniedJson = JSON.parse(deniedText);
    assert.equal(deniedJson.access_token, undefined);
    assert.equal(deniedJson.refresh_token, undefined);
    assert.equal(deniedJson.id_token, undefined);

    const famAfterDenial = await db.collection("oauth_token_families").findOne({ familyId: famDenyBefore.familyId });
    assert.equal(famAfterDenial?.status, "revoked", "Key denial must durably revoke the token family");
    assert.equal(famAfterDenial?.rotating, false, "Lease must not be stranded after key denial");
    assert.equal(famAfterDenial?.rotationOwner, undefined);

    // Even if provider could read the profile again, rtDeny must remain rejected because family is revoked
    forceReadableAfterDenial = true;
    const postDenialRetry = await tokenApp.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rtDeny, client_id: clientId }).toString(),
    });
    assert.equal(postDenialRetry.status, 401);
    const postDenialJson = await postDenialRetry.json();
    assert.equal(postDenialJson.access_token, undefined);
    assert.equal(postDenialJson.refresh_token, undefined);

    // 6. Feature-off path on default app preserves legacy behavior
    const pkceOff = makePkce();
    const authOffRes = await app.request(
      `/api/auth/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent("https://pub.example.com/cb")}&response_type=code&scope=${encodeURIComponent("openid profile email offline_access")}&code_challenge=${pkceOff.challenge}&code_challenge_method=S256&state=s2`,
      { method: "GET", headers: { Cookie: sessionCookie }, redirect: "manual" }
    );
    const codeOff = new URL(authOffRes.headers.get("location") || "").searchParams.get("code");
    const tokenOffRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: codeOff!,
        redirect_uri: "https://pub.example.com/cb",
        code_verifier: pkceOff.verifier,
        client_id: clientId,
      }).toString(),
    });
    assert.equal(tokenOffRes.status, 200);
    const offTokens = await tokenOffRes.json();
    const offPubKey = await getIdpPublicKey(decodeProtectedHeader(offTokens.access_token).kid);
    const offAt = await jwtVerify(offTokens.access_token, offPubKey, { algorithms: ["RS256"] });
    assert.equal(offAt.payload.name, "Legacy Real User");
    assert.equal(offAt.payload.email, email);
  });
});
