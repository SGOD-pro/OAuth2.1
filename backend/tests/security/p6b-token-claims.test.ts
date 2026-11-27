import assert from "node:assert/strict";
import crypto from "node:crypto";
import { after, before, describe, it } from "node:test";
import { Hono } from "hono";
import { decodeJwt, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { ObjectId } from "mongodb";
import { AccountKeyAccessError, InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import { InMemoryProfileCollection, writeProtectedProfile } from "../../src/identity/protected-profile-store";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

process.env.NODE_ENV = process.env.NODE_ENV || "test";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);

let mintJwtAccessToken: any;
let resignIdTokenWithNewAtHash: any;
let buildCodeIdTokenClaimFilter: any;
let handleAuthorizationCodeGrant: any;
let buildRefreshIdTokenClaimFilter: any;
let handleRefreshTokenGrant: any;
let hashToken: any;
let suiteCtx: Awaited<ReturnType<typeof setupSuiteDatabase>> | undefined;
let db: any;

before(async () => {
  isolateTestEnvironment();
  process.env.NODE_ENV = "test";
  suiteCtx = await setupSuiteDatabase("p6b_token_claims_grants");
  const { getDb } = await import("../../src/db/mongo");
  db = await getDb();
  ({ mintJwtAccessToken, resignIdTokenWithNewAtHash } = await import("../../src/routes/auth-jwt"));
  ({ buildCodeIdTokenClaimFilter, handleAuthorizationCodeGrant } = await import("../../src/routes/auth-token-code"));
  ({ buildRefreshIdTokenClaimFilter, handleRefreshTokenGrant } = await import("../../src/routes/auth-token-refresh"));
  ({ hashToken } = await import("../../src/utils/security"));
});

after(async () => {
  const { closeDb } = await import("../../src/db/mongo");
  await closeDb();
  await suiteCtx?.cleanup();
});

describe("P6b Protected Token Claims (Access Token & ID Token Issuance Paths)", () => {
  it("mints JWT access tokens using protected values over stale legacy copies and respects scope/privacy", async () => {
    const { privateKey } = await generateKeyPair("RS256");
    const userId = new ObjectId().toHexString();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const written = await writeProtectedProfile({
      store,
      provider,
      accountId: userId,
      name: "Protected Token Name",
      email: "protected.token@example.com",
    });

    const unwrapCalls: string[] = [];
    const spyingProvider = {
      wrapDataKey: provider.wrapDataKey.bind(provider),
      denyAccess: provider.denyAccess.bind(provider),
      scheduleDestruction: provider.scheduleDestruction.bind(provider),
      getKeyState: provider.getKeyState.bind(provider),
      async unwrapDataKey(accountId: string, keyRef: string, wrappedKey: string) {
        unwrapCalls.push(keyRef);
        return provider.unwrapDataKey(accountId, keyRef, wrappedKey);
      },
    };

    const userDoc = {
      _id: new ObjectId(userId),
      id: userId,
      name: "Stale Legacy Name",
      email: "stale.legacy@example.com",
      emailVerified: true,
      tokenVersion: 1,
      shareEmail: true,
      shareProfile: true,
    };

    const mockDb = {
      collection(name: string) {
        if (name === "user") return { async findOne() { return userDoc; } };
        return { async findOne() { return null; } };
      },
    };

    // 1. Authorized openid profile email -> protected values win
    unwrapCalls.length = 0;
    const jwtAll = await mintJwtAccessToken(
      { userId, clientId: "client-1", scope: "openid profile email" },
      {
        getDb: async () => mockDb,
        getSigningKey: async () => ({ kid: "test-kid", privateKey }),
        resolveRole: async () => ({ role: "user", scopedClientId: null }),
        protectedProfileStore: store,
        accountKeyProvider: spyingProvider,
        migrationMode: "strict",
      }
    );
    assert.ok(jwtAll);
    const decodedAll = decodeJwt(jwtAll);
    assert.equal(decodedAll.name, "Protected Token Name");
    assert.equal(decodedAll.email, "protected.token@example.com");
    assert.equal(unwrapCalls.length, 2);

    // 2. openid profile only -> email absent, only 1 decrypt
    unwrapCalls.length = 0;
    const jwtProfile = await mintJwtAccessToken(
      { userId, clientId: "client-1", scope: "openid profile" },
      {
        getDb: async () => mockDb,
        getSigningKey: async () => ({ kid: "test-kid", privateKey }),
        resolveRole: async () => ({ role: "user", scopedClientId: null }),
        protectedProfileStore: store,
        accountKeyProvider: spyingProvider,
        migrationMode: "strict",
      }
    );
    assert.ok(jwtProfile);
    const decodedProfile = decodeJwt(jwtProfile);
    assert.equal(decodedProfile.name, "Protected Token Name");
    assert.equal(decodedProfile.email, undefined);
    assert.equal(unwrapCalls.length, 1);

    // 3. Feature off preserves legacy contract
    const jwtOff = await mintJwtAccessToken(
      { userId, clientId: "client-1", scope: "openid profile email" },
      {
        getDb: async () => mockDb,
        getSigningKey: async () => ({ kid: "test-kid", privateKey }),
        resolveRole: async () => ({ role: "user", scopedClientId: null }),
      }
    );
    assert.ok(jwtOff);
    const decodedOff = decodeJwt(jwtOff);
    assert.equal(decodedOff.name, "Stale Legacy Name");
    assert.equal(decodedOff.email, "stale.legacy@example.com");

    // 4. Key denial fails closed (no JWT minted, no plaintext fallback)
    await provider.denyAccess(userId, written.nameEnvelope.keyRef, "owner_revoked");
    await assert.rejects(
      () =>
        mintJwtAccessToken(
          { userId, clientId: "client-1", scope: "openid profile email" },
          {
            getDb: async () => mockDb,
            getSigningKey: async () => ({ kid: "test-kid", privateKey }),
            resolveRole: async () => ({ role: "user", scopedClientId: null }),
            protectedProfileStore: store,
            accountKeyProvider: provider,
            migrationMode: "compat",
          }
        ),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_denied"
    );
  });

  it("applies protected claims in authorization_code and refresh_token ID token builders and fails closed on outage", async () => {
    const { privateKey } = await generateKeyPair("RS256");
    const userId = new ObjectId().toHexString();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    await writeProtectedProfile({
      store,
      provider,
      accountId: userId,
      name: "Protected ID Name",
      email: "protected.id@example.com",
    });

    const userDoc = {
      _id: new ObjectId(userId),
      id: userId,
      name: "Stale ID Name",
      email: "stale.id@example.com",
      emailVerified: true,
      shareEmail: true,
      shareProfile: true,
    };

    const rawIdToken = await new SignJWT({
      sub: userId,
      name: "Stale ID Name",
      email: "stale.id@example.com",
      email_verified: true,
      at_hash: "old",
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
      .sign(privateKey);

    const codeFilter = buildCodeIdTokenClaimFilter("openid profile email", userDoc, {
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    });
    const codeSigned = await resignIdTokenWithNewAtHash(rawIdToken, "new-at", codeFilter, async () => ({
      kid: "test-kid",
      privateKey,
    }));
    const codePayload = decodeJwt(codeSigned);
    assert.equal(codePayload.name, "Protected ID Name");
    assert.equal(codePayload.email, "protected.id@example.com");

    const refreshFilter = buildRefreshIdTokenClaimFilter("openid profile", userDoc, {
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    });
    const refreshSigned = await resignIdTokenWithNewAtHash(rawIdToken, "new-at", refreshFilter, async () => ({
      kid: "test-kid",
      privateKey,
    }));
    const refreshPayload = decodeJwt(refreshSigned);
    assert.equal(refreshPayload.name, "Protected ID Name");
    assert.equal(refreshPayload.email, undefined);

    // Outage fails closed without falling back to stale ID token
    provider.setOutage(true);
    await assert.rejects(
      () =>
        resignIdTokenWithNewAtHash(
          rawIdToken,
          "new-at",
          buildCodeIdTokenClaimFilter("openid profile email", userDoc, {
            protectedProfileStore: store,
            accountKeyProvider: provider,
            migrationMode: "compat",
          }),
          async () => ({ kid: "test-kid", privateKey })
        ),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "provider_outage"
    );
  });
});

describe("P6b Token Grant Handlers (authorization_code & refresh_token with Docker MongoDB)", { timeout: 60_000 }, () => {
  it("issues protected access/ID tokens with verified signatures and at_hash, and fails closed on authorization_code grant", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const userId = new ObjectId().toHexString();
    const clientId = `grant-code-client-${Date.now()}`;
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    await writeProtectedProfile({ store, provider, accountId: userId, name: "Code Protected", email: "code.protected@example.com" });

    await db.collection("user").insertOne({
      _id: new ObjectId(userId),
      id: userId,
      name: "Stale Code Name",
      email: "stale.code@example.com",
      emailVerified: true,
      tokenVersion: 1,
      shareEmail: true,
      shareProfile: true,
    });
    const clientDoc = { clientId, clientType: "public", accessPolicy: "open", isPublic: true, tokenVersion: 1 };
    await db.collection("oauthClient").insertOne(clientDoc);

    const makeAuthCodeReq = async (code: string, scope: string) => {
      const codeVerifier = "verifier-" + crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
      await db.collection("oauthAuthorizationCode").insertOne({
        code,
        clientId,
        userId,
        redirectUri: "https://app.example.com/cb",
        codeChallenge,
        codeChallengeMethod: "S256",
        expiresAt: new Date(Date.now() + 60_000),
        createdAt: new Date(),
        tokenVersion: 1,
      });
      const rawIdToken = await new SignJWT({ sub: userId, name: "Stale Code Name", email: "stale.code@example.com", email_verified: true, at_hash: "old-at-hash" })
        .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
        .sign(privateKey);
      const body = new URLSearchParams({ grant_type: "authorization_code", code, client_id: clientId, redirect_uri: "https://app.example.com/cb", code_verifier: codeVerifier });
      const req = new Request("http://localhost/api/auth/oauth2/token", { method: "POST", body: body.toString(), headers: { "content-type": "application/x-www-form-urlencoded" } });
      const app = new Hono();
      app.post("/token", (c) =>
        (handleAuthorizationCodeGrant as any)(
          c,
          { canonicalClientId: clientId, clientDoc, reqToForward: req, params: body, authMethod: "none" },
          {
            getSigningKey: async () => ({ kid: "test-kid", privateKey }),
            protectedProfileStore: store,
            accountKeyProvider: provider,
            migrationMode: "strict",
            authHandler: async () =>
              new Response(JSON.stringify({ access_token: "engine-at-" + code, refresh_token: "engine-rt-" + code, id_token: rawIdToken, expires_in: 900, scope }), {
                status: 200,
                headers: { "content-type": "application/json" },
              }),
          }
        )
      );
      return app.request("/token", { method: "POST" });
    };

    const okRes = await makeAuthCodeReq("code-ok-1", "openid profile email");
    assert.equal(okRes.status, 200);
    const okJson = await okRes.json();
    const verifiedAt = await jwtVerify(okJson.access_token, publicKey, { algorithms: ["RS256"] });
    const verifiedId = await jwtVerify(okJson.id_token, publicKey, { algorithms: ["RS256"] });
    assert.equal(verifiedId.protectedHeader.alg, "RS256");
    assert.equal(verifiedAt.payload.name, "Code Protected");
    assert.equal(verifiedAt.payload.email, "code.protected@example.com");
    assert.equal(verifiedAt.payload.client_id, clientId);
    assert.equal(verifiedId.payload.name, "Code Protected");
    assert.equal(verifiedId.payload.email, "code.protected@example.com");
    const recomputedAtHash = crypto.createHash("sha256").update(okJson.access_token).digest().subarray(0, 16).toString("base64url");
    assert.equal(verifiedId.payload.at_hash, recomputedAtHash);

    provider.setOutage(true);
    const failRes = await makeAuthCodeReq("code-fail-1", "openid profile email");
    assert.equal(failRes.status, 503);
    const failText = await failRes.text();
    assert.equal(failText.includes("Code Protected"), false);
    assert.equal(failText.includes("code.protected@example.com"), false);
    const failJson = JSON.parse(failText);
    assert.equal(failJson.access_token, undefined);
    assert.equal(failJson.refresh_token, undefined);
    assert.equal(failJson.id_token, undefined);
    const consumedCode = await db.collection("oauthAuthorizationCode").findOne({ code: "code-fail-1" });
    assert.ok(consumedCode?.consumedAt, "Code must remain consumed on protected-read failure");
    assert.equal(await db.collection("oauthAccessToken").countDocuments({ userId, clientId }), 1, "Failed code grant must not leave extra access token");
    assert.equal(await db.collection("oauthRefreshToken").countDocuments({ token: "engine-rt-code-fail-1" }), 0, "Failed code grant must purge refresh token");
    assert.equal(await db.collection("oauth_token_families").countDocuments({ userId, clientId }), 1, "Failed code grant must not leave extra active family");
  });

  it("verifies refresh signatures/at_hash, replay protection, concurrent refresh, transient outage recovery, and key denial", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const userId = new ObjectId().toHexString();
    const clientId = `grant-refresh-client-${Date.now()}`;
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const written = await writeProtectedProfile({ store, provider, accountId: userId, name: "Refresh Protected", email: "refresh.protected@example.com" });

    await db.collection("user").insertOne({
      _id: new ObjectId(userId),
      id: userId,
      name: "Stale Refresh Name",
      email: "stale.refresh@example.com",
      emailVerified: true,
      tokenVersion: 1,
      shareEmail: false,
      shareProfile: true,
    });
    const clientDoc = { clientId, clientType: "public", accessPolicy: "open", isPublic: true, tokenVersion: 1 };
    await db.collection("oauthClient").insertOne(clientDoc);

    const makeRefreshHelper = (famId: string, rtInit: string) => async (incomingRt: string, nextRt: string) => {
      const rawIdToken = await new SignJWT({ sub: userId, name: "Stale Refresh Name", email: "stale.refresh@example.com", email_verified: true, at_hash: "old-at" })
        .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
        .sign(privateKey);
      const body = new URLSearchParams({ grant_type: "refresh_token", refresh_token: incomingRt, client_id: clientId });
      const req = new Request("http://localhost/api/auth/oauth2/token", { method: "POST", body: body.toString(), headers: { "content-type": "application/x-www-form-urlencoded" } });
      const app = new Hono();
      app.post("/token", (c) =>
        (handleRefreshTokenGrant as any)(
          c,
          { canonicalClientId: clientId, clientDoc, reqToForward: req, params: body, authMethod: "none" },
          incomingRt,
          {
            getSigningKey: async () => ({ kid: "test-kid", privateKey }),
            protectedProfileStore: store,
            accountKeyProvider: provider,
            migrationMode: "strict",
            authHandler: async () =>
              new Response(JSON.stringify({ access_token: "engine-at-" + nextRt, refresh_token: nextRt, id_token: rawIdToken, expires_in: 900, scope: "openid profile email" }), {
                status: 200,
                headers: { "content-type": "application/json" },
              }),
          }
        )
      );
      return app.request("/token", { method: "POST" });
    };

    // 1. Successful refresh + signature/at_hash verification + replay safeguard
    const rt1 = "rt-raw-1-" + crypto.randomBytes(8).toString("hex");
    const rt2 = "rt-raw-2-" + crypto.randomBytes(8).toString("hex");
    const rt3 = "rt-raw-3-" + crypto.randomBytes(8).toString("hex");
    await db.collection("oauth_token_families").insertOne({
      familyId: "fam-refresh-1",
      clientId,
      userId,
      activeTokenHash: hashToken(rt1, "hex"),
      consumedTokenHashes: [],
      status: "active",
      rotating: false,
      tokenVersion: 1,
      createdAt: new Date(),
    });
    await db.collection("oauthRefreshToken").insertOne({ token: rt1, clientId, userId, createdAt: new Date(), tokenVersion: 1 });
    const runFam1 = makeRefreshHelper("fam-refresh-1", rt1);

    const okRes = await runFam1(rt1, rt2);
    assert.equal(okRes.status, 200);
    const okJson = await okRes.json();
    const verifiedAt = await jwtVerify(okJson.access_token, publicKey, { algorithms: ["RS256"] });
    const verifiedId = await jwtVerify(okJson.id_token, publicKey, { algorithms: ["RS256"] });
    assert.equal(verifiedId.protectedHeader.alg, "RS256");
    assert.equal(verifiedAt.payload.name, "Refresh Protected");
    assert.equal(verifiedAt.payload.email, undefined);
    assert.equal(verifiedId.payload.name, "Refresh Protected");
    assert.equal(verifiedId.payload.email, undefined);
    assert.equal(verifiedId.payload.at_hash, crypto.createHash("sha256").update(okJson.access_token).digest().subarray(0, 16).toString("base64url"));

    // Replay of rt1 after grace window revokes fam-refresh-1 and blocks rt2
    await db.collection("oauth_token_families").updateOne(
      { familyId: "fam-refresh-1" },
      { $set: { rotatedAt: new Date(Date.now() - 60_000), updatedAt: new Date(Date.now() - 60_000) } }
    );
    const replayRes = await runFam1(rt1, rt3);
    assert.equal(replayRes.status, 401);
    const fam1AfterReplay = await db.collection("oauth_token_families").findOne({ familyId: "fam-refresh-1" });
    assert.equal(fam1AfterReplay?.status, "revoked");
    const postReplayRt2 = await runFam1(rt2, rt3);
    assert.equal(postReplayRt2.status, 401);

    // 2. Transient outage on active fam-refresh-2 -> 503, no tokens/plaintext, no stranded lease, retry after restore
    const rtOut1 = "rt-out-1-" + crypto.randomBytes(8).toString("hex");
    const rtOut2 = "rt-out-2-" + crypto.randomBytes(8).toString("hex");
    await db.collection("oauth_token_families").insertOne({
      familyId: "fam-refresh-outage",
      clientId,
      userId,
      activeTokenHash: hashToken(rtOut1, "hex"),
      consumedTokenHashes: [],
      status: "active",
      rotating: false,
      tokenVersion: 1,
      createdAt: new Date(),
    });
    const runOut = makeRefreshHelper("fam-refresh-outage", rtOut1);
    provider.setOutage(true);
    const outageRes = await runOut(rtOut1, rtOut2);
    assert.equal(outageRes.status, 503);
    const outageText = await outageRes.text();
    assert.equal(outageText.includes("Refresh Protected"), false);
    assert.equal(outageText.includes("refresh.protected@example.com"), false);
    assert.equal(outageText.includes("Stale Refresh Name"), false);
    const outageJson = JSON.parse(outageText);
    assert.equal(outageJson.access_token, undefined);
    assert.equal(outageJson.refresh_token, undefined);
    assert.equal(outageJson.id_token, undefined);
    assert.equal(await db.collection("oauthAccessToken").countDocuments({ familyId: "fam-refresh-outage" }), 0);
    assert.equal(await db.collection("oauthRefreshToken").countDocuments({ token: rtOut2 }), 0);
    const famOutage = await db.collection("oauth_token_families").findOne({ familyId: "fam-refresh-outage" });
    assert.equal(famOutage?.rotating, false);
    assert.equal(famOutage?.rotationOwner, undefined);
    assert.equal(famOutage?.status, "active", "Family must remain active on transient outage before rotation");

    // Restore provider and retry original token -> 200 OK
    provider.setOutage(false);
    const retryAfterOutage = await runOut(rtOut1, "rt-out-3");
    assert.equal(retryAfterOutage.status, 200);
    const famOutageAfterRetry = await db.collection("oauth_token_families").findOne({ familyId: "fam-refresh-outage" });
    assert.equal(famOutageAfterRetry?.status, "active");
    assert.equal(famOutageAfterRetry?.rotating, false);

    // 3. Concurrent refresh permits at most one replacement
    const rtConc = "rt-conc-1-" + crypto.randomBytes(8).toString("hex");
    await db.collection("oauth_token_families").insertOne({
      familyId: "fam-refresh-conc",
      clientId,
      userId,
      activeTokenHash: hashToken(rtConc, "hex"),
      consumedTokenHashes: [],
      status: "active",
      rotating: false,
      tokenVersion: 1,
      createdAt: new Date(),
    });
    const runConc = makeRefreshHelper("fam-refresh-conc", rtConc);
    const [concA, concB] = await Promise.all([runConc(rtConc, "rt-conc-next-a"), runConc(rtConc, "rt-conc-next-b")]);
    const okCount = [concA.status, concB.status].filter((s) => s === 200).length;
    assert.equal(okCount, 1, "Concurrent refresh must permit at most one replacement");
    assert.equal(await db.collection("oauthAccessToken").countDocuments({ familyId: "fam-refresh-conc" }), 1);

    // 4. Key denial separately -> 403, no tokens/plaintext, no usable replacement, no stranded lease
    const rtDeny = "rt-deny-1-" + crypto.randomBytes(8).toString("hex");
    await db.collection("oauth_token_families").insertOne({
      familyId: "fam-refresh-deny",
      clientId,
      userId,
      activeTokenHash: hashToken(rtDeny, "hex"),
      consumedTokenHashes: [],
      status: "active",
      rotating: false,
      tokenVersion: 1,
      createdAt: new Date(),
    });
    await provider.denyAccess(userId, written.nameEnvelope.keyRef, "owner_revoked");
    const denyRes = await makeRefreshHelper("fam-refresh-deny", rtDeny)(rtDeny, "rt-deny-2");
    assert.equal(denyRes.status, 403);
    const denyText = await denyRes.text();
    assert.equal(denyText.includes("Refresh Protected"), false);
    assert.equal(denyText.includes("Stale Refresh Name"), false);
    const famDeny = await db.collection("oauth_token_families").findOne({ familyId: "fam-refresh-deny" });
    assert.equal(famDeny?.rotating, false);
    assert.equal(famDeny?.rotationOwner, undefined);
    assert.equal(await db.collection("oauthAccessToken").countDocuments({ familyId: "fam-refresh-deny" }), 0);
  });
});
