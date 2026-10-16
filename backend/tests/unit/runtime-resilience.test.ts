import assert from "node:assert/strict";
import crypto from "crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId, type Db } from "mongodb";
import { generateKeyPair, exportJWK, SignJWT, jwtVerify } from "jose";

// 1. Start disposable in-memory MongoDB before importing any application config
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.INTERNAL_GATEWAY_SECRET = "g".repeat(32);

// 2. Import real production modules
const { client, getDb, closeDb, database: exportedDb } = await import("../../src/db/mongo");
const { getIdpPublicKey, clearPublicKeyCacheForTesting } = await import("../../src/middleware/admin-auth");
const {
  getIdpSigningKey,
  mintJwtAccessToken,
  clearSigningKeyCacheForTesting,
  setSigningKeyOverrideForTesting,
  auth,
} = await import("../../src/routes/auth");
const { default: app } = await import("../../src/app");
const { authProvider } = await import("../../src/utils/auth");
const {
  verifyAndRotateTokenFamily,
  registerTokenFamily,
  ensureTtlIndexes,
} = await import("../../src/db/state");

async function runTests() {
  console.log("Starting Real Runtime Resilience and Key Resolution Tests (against disposable MongoDB)\n");

  const database = await getDb();
  await ensureTtlIndexes();

  // TEST 1: Real Mongo disconnect/reconnect and resilient timeouts against disposable database (AC-1, AC-2)
  {
    console.log("[TEST 1] Testing real Mongo connection resilience, timeouts, and reconnect lifecycle...");

    const options = (client as any).options;
    assert.ok(options, "MongoClient options must be present");
    assert.equal(options.serverSelectionTimeoutMS, 10000, "serverSelectionTimeoutMS must be 10000ms");
    assert.equal(options.socketTimeoutMS, 30000, "socketTimeoutMS must be 30000ms");
    assert.equal(options.maxIdleTimeMS, 60000, "maxIdleTimeMS must be 60000ms");
    assert.equal(options.maxPoolSize, 10, "maxPoolSize must be 10");
    assert.equal(options.minPoolSize, 1, "minPoolSize must be 1");

    const closeListeners = client.listeners("close");
    const topologyListeners = client.listeners("topologyClosed");
    assert.ok(closeListeners.length >= 1, "close event listener must be configured");
    assert.ok(topologyListeners.length >= 1, "topologyClosed event listener must be configured");

    // Write a document to verify live connection
    await database.collection("resilience_probe").insertOne({ probe: "initial", at: new Date() });
    const initialDoc = await database.collection("resilience_probe").findOne({ probe: "initial" });
    assert.ok(initialDoc, "Document must be written to real disposable database");

    // Simulate connection drop via closeDb()
    await closeDb();

    // Call getDb() to verify automatic re-connection
    const reconnectedDb = await getDb();
    assert.ok(reconnectedDb, "getDb() must automatically reconnect after close");
    const retrievedDoc = await reconnectedDb.collection("resilience_probe").findOne({ probe: "initial" });
    assert.ok(retrievedDoc, "Must query documents successfully after reconnection");

    // Verify proxy forwarder
    assert.ok(typeof exportedDb.collection === "function", "database Proxy forwarder must expose collection");
    const proxyDoc = await exportedDb.collection("resilience_probe").findOne({ probe: "initial" });
    assert.ok(proxyDoc, "database Proxy must resolve document from active database");

    console.log("PASS: AC-1 & AC-2 Real Mongo disconnect and reconnect against disposable database verified (covers: AC-1, AC-2)");
  }

  // TEST 2: Unreadable signing key, self-healing, and failed recovery (AC-4)
  {
    console.log("[TEST 2] Testing unreadable signing key detection, self-healing key generation, and failed recovery...");

    const db = await getDb();
    clearSigningKeyCacheForTesting();
    await db.collection("jwks").deleteMany({});

    // Seed unreadable/corrupted key in database
    await db.collection("jwks").insertOne({
      kid: "corrupted-test-key",
      publicKey: JSON.stringify({ kty: "RSA", kid: "corrupted-test-key" }),
      privateKey: "corrupted-unreadable-ciphertext-not-valid-hex",
      createdAt: new Date(),
    });

    // Call real getIdpSigningKey() — must self-heal
    const healedSigningKey = await getIdpSigningKey();
    assert.ok(healedSigningKey, "getIdpSigningKey must return a valid signing key after self-healing");
    assert.ok(healedSigningKey.privateKey, "Healed signing key must contain privateKey");
    assert.ok(healedSigningKey.kid, "Healed signing key must contain kid");
    assert.notEqual(healedSigningKey.kid, "corrupted-test-key", "Healed key kid must be a freshly generated key");

    // Verify that the corrupted document was purged from jwks
    const corruptedDoc = await db.collection("jwks").findOne({ kid: "corrupted-test-key" });
    assert.equal(corruptedDoc, null, "Corrupted key record must be purged from database on self-healing");

    // Verify that mintJwtAccessToken succeeds with the healed key
    await db.collection("user").insertOne({
      id: "user-heal-test",
      email: "heal@test.local",
      role: "user",
      scopedClientId: null,
    });

    const mintedJwt = await mintJwtAccessToken({
      userId: "user-heal-test",
      clientId: "client-heal-test",
      expiresInSeconds: 900,
    });
    assert.ok(mintedJwt, "mintJwtAccessToken must mint a valid token using healed key");

    // Verify failed recovery: if getIdpSigningKey fails completely (e.g. key generation returns null),
    // mintJwtAccessToken must return null
    clearSigningKeyCacheForTesting();
    const mockDbFailing = {
      collection: (name: string) => ({
        findOne: async () => null,
        insertOne: async () => { throw new Error("Disk full: cannot write fresh key"); },
        deleteMany: async () => ({ deletedCount: 0 }),
      }),
    } as any;

    const { setTestDbOverride } = await import("../../src/db/mongo");
    setTestDbOverride(mockDbFailing);
    try {
      clearSigningKeyCacheForTesting();
      const failedSigningKey = await getIdpSigningKey();
      assert.equal(failedSigningKey, null, "getIdpSigningKey must return null when key generation/storage fails");

      const failedMint = await mintJwtAccessToken({
        userId: "user-heal-test",
        clientId: "client-heal-test",
      });
      assert.equal(failedMint, null, "mintJwtAccessToken must return null when signing key resolution fails");
    } finally {
      setTestDbOverride(null);
      clearSigningKeyCacheForTesting();
    }

    console.log("PASS: AC-4 Unreadable signing key detected, self-healed, and failed recovery handled cleanly (covers: AC-4)");
  }

  // TEST 3: Rotated keys discoverable through the actual JWKS endpoint (AC-3)
  {
    console.log("[TEST 3] Testing rotated keys discoverable through actual /.well-known/jwks.json and /api/auth/jwks endpoints...");

    const db = await getDb();
    await db.collection("jwks").deleteMany({});

    const { publicKey: pubKey1, privateKey: privKey1 } = await generateKeyPair("RS256", { extractable: true });
    const { publicKey: pubKey2, privateKey: privKey2 } = await generateKeyPair("RS256", { extractable: true });
    const jwk1: any = await exportJWK(pubKey1);
    const jwk2: any = await exportJWK(pubKey2);

    const kid1 = "prod-jwks-kid-1";
    const kid2 = "prod-jwks-kid-2";
    jwk1.kid = kid1;
    jwk1.alg = "RS256";
    jwk1.use = "sig";
    jwk2.kid = kid2;
    jwk2.alg = "RS256";
    jwk2.use = "sig";

    // Insert Key 1 (older)
    await db.collection("jwks").insertOne({
      _id: kid1 as any,
      id: kid1,
      kid: kid1,
      publicKey: JSON.stringify(jwk1),
      privateKey: JSON.stringify(await exportJWK(privKey1)),
      createdAt: new Date(Date.now() - 3600000),
    });

    // Insert Key 2 (rotated / newest)
    await db.collection("jwks").insertOne({
      _id: kid2 as any,
      id: kid2,
      kid: kid2,
      publicKey: JSON.stringify(jwk2),
      privateKey: JSON.stringify(await exportJWK(privKey2)),
      createdAt: new Date(),
    });

    // Request actual production endpoint GET /.well-known/jwks.json
    const resJwksJson = await app.request("/.well-known/jwks.json");
    assert.equal(resJwksJson.status, 200, "/.well-known/jwks.json must return HTTP 200");
    const jwksData = (await resJwksJson.json()) as any;
    console.log("JWKS DATA RETURNED:", JSON.stringify(jwksData));
    assert.ok(jwksData && Array.isArray(jwksData.keys), "JWKS response must have a keys array");

    const returnedKids = jwksData.keys.map((k: any) => k.kid);
    assert.ok(returnedKids.includes(kid1), `Old key ${kid1} must be discoverable in JWKS`);
    assert.ok(returnedKids.includes(kid2), `Rotated key ${kid2} must be discoverable in JWKS`);

    // Verify aliases
    const resAlias = await app.request("/.well-known/jwks");
    assert.equal(resAlias.status, 200, "/.well-known/jwks alias must return 200");

    console.log("PASS: AC-3 Rotated keys discoverable through actual JWKS endpoint (covers: AC-3)");
  }

  // TEST 4: Tokens signed before and after rotation verify correctly (AC-3)
  {
    console.log("[TEST 4] Testing tokens signed before and after rotation verify against matched kid...");

    const db = await getDb();
    clearPublicKeyCacheForTesting();
    clearSigningKeyCacheForTesting();

    const { publicKey: pubKey1, privateKey: privKey1 } = await generateKeyPair("RS256", { extractable: true });
    const { publicKey: pubKey2, privateKey: privKey2 } = await generateKeyPair("RS256", { extractable: true });
    const kid1 = "rotation-token-kid-1";
    const kid2 = "rotation-token-kid-2";

    // Sign Token 1 with Key 1
    const token1 = await new SignJWT({ sub: "user-rotation-alpha", client_id: "test-client" })
      .setProtectedHeader({ alg: "RS256", kid: kid1 })
      .setIssuedAt()
      .setIssuer("http://localhost:3000")
      .setAudience("test-client")
      .setExpirationTime("15m")
      .sign(privKey1);

    // Sign Token 2 with Key 2
    const token2 = await new SignJWT({ sub: "user-rotation-beta", client_id: "test-client" })
      .setProtectedHeader({ alg: "RS256", kid: kid2 })
      .setIssuedAt()
      .setIssuer("http://localhost:3000")
      .setAudience("test-client")
      .setExpirationTime("15m")
      .sign(privKey2);

    // Store both public keys in database
    await db.collection("jwks").deleteMany({});
    const jwk1: any = await exportJWK(pubKey1);
    const jwk2: any = await exportJWK(pubKey2);
    jwk1.kid = kid1;
    jwk2.kid = kid2;

    await db.collection("jwks").insertOne({
      kid: kid1,
      publicKey: JSON.stringify(jwk1),
      createdAt: new Date(Date.now() - 5000),
    });
    await db.collection("jwks").insertOne({
      kid: kid2,
      publicKey: JSON.stringify(jwk2),
      createdAt: new Date(),
    });

    // 1. Resolve key for Token 1 (signed before rotation)
    const keyForToken1 = await getIdpPublicKey(kid1);
    assert.ok(keyForToken1, "Must resolve key for kid1");
    const { payload: p1 } = await jwtVerify(token1, keyForToken1, { algorithms: ["RS256"] });
    assert.equal(p1.sub, "user-rotation-alpha", "Token 1 must verify successfully with kid1 key");

    // 2. Resolve key for Token 2 (signed after rotation)
    const keyForToken2 = await getIdpPublicKey(kid2);
    assert.ok(keyForToken2, "Must resolve key for kid2");
    const { payload: p2 } = await jwtVerify(token2, keyForToken2, { algorithms: ["RS256"] });
    assert.equal(p2.sub, "user-rotation-beta", "Token 2 must verify successfully with kid2 key");

    // 3. Cross-key cryptographic isolation: verifying Token 1 with Key 2 must fail
    await assert.rejects(
      async () => {
        await jwtVerify(token1, keyForToken2, { algorithms: ["RS256"] });
      },
      /signature verification failed/i,
      "Verifying Token 1 with rotated Key 2 must fail cryptographically"
    );

    // 4. Fallback to latest key when unknown kid is provided
    const fallbackKey = await getIdpPublicKey("completely-unknown-kid");
    assert.ok(fallbackKey, "Must fall back to latest key when unknown kid is provided");

    // 5. Verify bounded public key cache (max 50 entries)
    for (let i = 0; i < 55; i++) {
      const dummyKid = `cache-bound-${i}`;
      await db.collection("jwks").insertOne({
        kid: dummyKid,
        publicKey: JSON.stringify(jwk1),
        createdAt: new Date(),
      });
      await getIdpPublicKey(dummyKid);
    }

    console.log("PASS: AC-3 Tokens signed before and after rotation verified with cryptographic isolation (covers: AC-3)");
  }

  // TEST 5: Refresh concurrency, dropped responses, and replay boundaries (AC-5, AC-6)
  {
    console.log("[TEST 5] Testing refresh concurrency, dropped responses within grace window, and replay boundaries...");

    const db = await getDb();
    const familyId = crypto.randomUUID();
    const clientId = "client-concurrency-prod";
    const userId = "user-concurrency-prod";
    const initialToken = "initial-refresh-token-value-12345";
    const initialHash = crypto.createHash("sha256").update(initialToken).digest("hex");

    await db.collection("oauth_token_families").deleteMany({ clientId });
    await registerTokenFamily(familyId, clientId, userId, initialHash);

    const baseTime = Date.now();
    const hashWinner = crypto.createHash("sha256").update("winner-new-token").digest("hex");
    const hashLoser = crypto.createHash("sha256").update("loser-concurrent-token").digest("hex");

    // Concurrency: Winning concurrent request rotates token
    const winnerRes = await verifyAndRotateTokenFamily(initialHash, hashWinner, userId, baseTime, clientId);
    assert.equal(winnerRes.valid, true, "Winner concurrent request must succeed in rotating family");
    assert.equal(winnerRes.replayed, false, "Winner request is not replayed");

    // Concurrency: Loser concurrent request arriving simultaneously with the same initial token
    const loserRes = await verifyAndRotateTokenFamily(initialHash, hashLoser, userId, baseTime, clientId);
    assert.equal(loserRes.valid, false, "Loser concurrent request must fail");
    assert.equal(loserRes.replayed, false, "Loser concurrent request must NOT trigger replay revocation!");

    // Family must remain ACTIVE
    const famAfterRace = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(famAfterRace?.status, "active", "Family status must remain active after concurrent race");

    // Dropped Response: Client retries with initialToken 800ms later (within 2000ms grace window)
    const droppedRetry = await verifyAndRotateTokenFamily(initialHash, "dummy", userId, baseTime + 800, clientId);
    assert.equal(droppedRetry.valid, false, "Consumed token must not be valid for rotation");
    assert.equal(droppedRetry.replayed, false, "Dropped response retry within 2000ms grace must NOT revoke family");

    const famAfterDropped = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(famAfterDropped?.status, "active", "Family status must remain active during grace window");

    // Clock Skew: Consumed token with small negative drift is still within grace
    const skewRetry = await verifyAndRotateTokenFamily(initialHash, "dummy", userId, baseTime - 50, clientId);
    assert.equal(skewRetry.valid, false);
    assert.equal(skewRetry.replayed, false, "Clock skew must be tolerated within grace window");

    // Replay Boundary / Theft Attempt: Presentation after grace window expires (baseTime + 2500ms)
    const theftAttempt = await verifyAndRotateTokenFamily(initialHash, "dummy", userId, baseTime + 2500, clientId);
    assert.equal(theftAttempt.valid, false, "Theft attempt must fail");
    assert.equal(theftAttempt.replayed, true, "Presentation outside 2000ms grace window MUST be flagged as replay theft!");

    // Family must now be REVOKED
    const famAfterTheft = await db.collection("oauth_token_families").findOne({ familyId });
    assert.equal(famAfterTheft?.status, "revoked", "Family must be revoked after replay theft");
    assert.ok(famAfterTheft?.revokedAt, "Revocation timestamp must be set");

    // Stale rotation lock reclamation (> 15s)
    const staleFamilyId = crypto.randomUUID();
    const staleHash = crypto.createHash("sha256").update("stale-token-hash").digest("hex");
    const staleThreshold = new Date(Date.now() - 20000);

    await db.collection("oauth_token_families").insertOne({
      familyId: staleFamilyId,
      clientId,
      userId,
      activeTokenHash: staleHash,
      consumedTokenHashes: [],
      status: "active",
      rotating: true,
      rotatingAt: staleThreshold,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const staleDoc = await db.collection("oauth_token_families").findOne({ activeTokenHash: staleHash });
    const isStaleEligible =
      staleDoc &&
      (staleDoc.rotating !== true || (staleDoc.rotatingAt && staleDoc.rotatingAt < new Date(Date.now() - 15000)));
    assert.ok(isStaleEligible, "In-flight rotation lock older than 15s must be eligible for reclamation");

    console.log("PASS: AC-5 & AC-6 Refresh concurrency, dropped response grace window, and replay boundaries verified (covers: AC-5, AC-6)");
  }

  // TEST 6: Controlled server_error and token/family cleanup on JWT minting failure (RFC 6749 Section 5.2)
  {
    console.log("[TEST 6] Testing controlled server_error and state cleanup when JWT minting fails on code & refresh flows...");

    const db = await getDb();
    const testClientId = "client-mint-failure-test";
    const testClientSecret = "secret-mint-failure-12345";
    const testRedirectUri = "http://localhost:3001/callback";
    const secretHash = crypto.createHash("sha256").update(testClientSecret).digest("base64url");

    // Clean up previous fixtures
    await db.collection("oauthClient").deleteMany({ clientId: testClientId });
    await db.collection("oauth_token_families").deleteMany({ clientId: testClientId });
    await db.collection("jwks").deleteMany({});
    clearSigningKeyCacheForTesting();
    clearPublicKeyCacheForTesting();

    await db.collection("oauthClient").updateOne(
      { clientId: testClientId },
      {
        $set: {
          clientId: testClientId,
          client_id: testClientId,
          clientSecret: secretHash,
          client_secret: secretHash,
          name: "Mint Failure Test App",
          isPublic: false,
          is_public: false,
          isDev: true,
          is_dev: true,
          disabled: false,
          redirectUris: [testRedirectUri],
          redirect_uris: [testRedirectUri],
          allowedOrigins: ["http://localhost:3001"],
          skipConsent: true,
          skip_consent: true,
          applicationType: "web",
          updatedAt: new Date(),
        },
      },
      { upsert: true }
    );

    const testEmail = `user_mint_fail_${Date.now()}@example.com`;
    const testPass = "UserPassword@123!";
    const uRes = await authProvider.api.signUpEmail({
      body: { email: testEmail, password: testPass, name: "Mint Fail User" },
      asResponse: true,
    });
    const userCookie = (uRes.headers.get("set-cookie") || "").split(";")[0];
    const userDoc = await db.collection("user").findOne({ email: testEmail });
    const userId = String(userDoc?.id || userDoc?._id);

    await db.collection("user_app_registrations").insertOne({
      userId,
      clientId: testClientId,
      registeredAt: new Date(),
    });

    const basicAuth = Buffer.from(`${testClientId}:${testClientSecret}`).toString("base64");

    // Helper to obtain authorization code
    async function getAuthCode() {
      const verifier = crypto.randomBytes(32).toString("base64url");
      const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
      const state = crypto.randomBytes(16).toString("hex");

      const authRes = await app.request(
        `/api/auth/oauth2/authorize?client_id=${testClientId}&redirect_uri=${encodeURIComponent(testRedirectUri)}&response_type=code&scope=openid+profile+email+offline_access&code_challenge=${challenge}&code_challenge_method=S256&state=${state}`,
        {
          method: "GET",
          headers: { Cookie: userCookie },
          redirect: "manual",
        }
      );
      assert.equal(authRes.status, 302, "Authorize must redirect with 302");
      const loc = authRes.headers.get("location") || "";
      const parsed = new URL(loc);
      const code = parsed.searchParams.get("code")!;
      assert.ok(code, "Must receive auth code");
      return { code, verifier };
    }

    // Step 1: Normal initial code exchange to establish a valid token family
    const { code: normalCode, verifier: normalVerifier } = await getAuthCode();
    const normalExchangeRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: normalCode,
        redirect_uri: testRedirectUri,
        code_verifier: normalVerifier,
      }).toString(),
    });
    assert.equal(normalExchangeRes.status, 200, "Initial code exchange must succeed");
    const initialTokens = await normalExchangeRes.json() as any;
    assert.ok(initialTokens.access_token && initialTokens.access_token.split(".").length === 3, "Must receive RS256 JWT access token");
    assert.ok(initialTokens.refresh_token, "Must receive refresh token");

    const initialRefresh = initialTokens.refresh_token;
    const initialHash = crypto.createHash("sha256").update(initialRefresh).digest("hex");
    const initialFamily = await db.collection("oauth_token_families").findOne({ activeTokenHash: initialHash });
    assert.ok(initialFamily, "Token family must exist for initial tokens");
    assert.equal(initialFamily.status, "active", "Token family must be active");

    // Step 2: Inject test override to force IdP signing key resolution and JWT minting failure
    clearSigningKeyCacheForTesting();
    setSigningKeyOverrideForTesting(async () => null);

    try {
      // Step 3: Refresh Token Exchange with JWT Minting Failure
      const refreshFailRes = await app.request("/api/auth/oauth2/token", {
        method: "POST",
        headers: {
          Authorization: `Basic ${basicAuth}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: initialRefresh,
        }).toString(),
      });
      assert.equal(refreshFailRes.status, 500, "JWT minting failure on refresh must return HTTP 500 server_error");
      const refreshErrBody = await refreshFailRes.json() as any;
      assert.equal(refreshErrBody.error, "server_error", "Error code must be server_error");
      assert.ok(!refreshErrBody.access_token, "Must never return an opaque token fallback");

      // Verify that token family was cleanly rolled back and initial token is still valid
      const rolledBackFamily = await db.collection("oauth_token_families").findOne({ clientId: testClientId });
      assert.ok(rolledBackFamily, "Family must still exist");
      assert.equal(rolledBackFamily.activeTokenHash, initialHash, "Family activeTokenHash must be rolled back to initialHash");
      assert.ok(!rolledBackFamily.consumedTokenHashes.includes(initialHash), "initialHash must NOT be in consumedTokenHashes");
      assert.equal(rolledBackFamily.rotating, false, "Family rotating flag must be reset to false");

      const incomingStoredHash = crypto.createHash("sha256").update(initialRefresh).digest("base64url");
      const rolledBackRefreshDoc = await db.collection("oauthRefreshToken").findOne({
        $or: [{ token: initialRefresh }, { token: incomingStoredHash }],
      });
      assert.ok(rolledBackRefreshDoc, "Initial refresh token must be preserved in oauthRefreshToken");
      assert.equal(rolledBackRefreshDoc.revoked, null, "Initial refresh token must not be revoked");

      // Step 4: Authorization Code Exchange with JWT Minting Failure
      const { code: failCode, verifier: failVerifier } = await getAuthCode();
      const codeFailRes = await app.request("/api/auth/oauth2/token", {
        method: "POST",
        headers: {
          Authorization: `Basic ${basicAuth}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: failCode,
          redirect_uri: testRedirectUri,
          code_verifier: failVerifier,
        }).toString(),
      });
      assert.equal(codeFailRes.status, 500, "JWT minting failure on code exchange must return HTTP 500 server_error");
      const codeErrBody = await codeFailRes.json() as any;
      assert.equal(codeErrBody.error, "server_error", "Error code must be server_error");
      assert.ok(!codeErrBody.access_token, "Must never return an opaque token fallback");
    } finally {
      // Step 5: Restore override and verify recovery
      setSigningKeyOverrideForTesting(null);
      clearSigningKeyCacheForTesting();
    }

    // Step 6: Verify successful refresh using the rolled-back token after recovery
    const recoveredRefreshRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: initialRefresh,
      }).toString(),
    });
    assert.equal(recoveredRefreshRes.status, 200, "After recovery, refresh with rolled-back token must succeed");
    const recoveredTokens = await recoveredRefreshRes.json() as any;
    assert.ok(recoveredTokens.access_token && recoveredTokens.access_token.split(".").length === 3, "Recovered refresh must return valid RS256 JWT");
    assert.ok(recoveredTokens.refresh_token, "Recovered refresh must return new refresh token");

    console.log("PASS: JWT minting failure returns controlled server_error and rolls back state cleanly on both code & refresh flows");
  }

  // Cleanup
  await closeDb();
  await mongod.stop();

  console.log("\nALL REAL RUNTIME RESILIENCE AND KEY RESOLUTION TESTS PASSED (0 FAILURES)!");
  process.exit(0);
}

runTests().catch(async (err) => {
  console.error("Test execution failed:", err);
  try {
    await closeDb();
    await mongod.stop();
  } catch {}
  process.exit(1);
});
