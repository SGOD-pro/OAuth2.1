import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P3 OAuth Continuation Session Binding", () => {
  let suite: any;
  let db: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let app: any;
  let authProvider: any;
  let findActiveBrowserSet: any;
  let createOAuthTransaction: any;
  let bindOAuthTransactionSelection: any;
  const gatewaySecret = "g".repeat(32);
  const password = "Password123!@#Secure";
  const codeChallenge = crypto.createHash("sha256").update("cont_verifier_123456789012345678901234567890").digest("base64url");

  function hdrs(extra: Record<string, string> = {}) {
    return { "X-Gateway-Secret": gatewaySecret, "x-csrf-token": "test-csrf", Origin: "http://localhost:5174", ...extra };
  }

  function extractCookie(res: Response, name: string): string {
    for (const part of (res.headers.get("set-cookie") || "").split(/,(?=[^;]+=)/)) {
      const kv = part.trim().split(";")[0];
      if (kv.startsWith(`${name}=`)) return kv;
    }
    return "";
  }

  async function registerUser(email: string) {
    const res = await authProvider.api.signUpEmail({ body: { email, password, name: "User" } });
    assert.ok(res.user?.id);
    await db.collection("user").updateOne({ email }, { $set: { emailVerified: true } });
    return res.user.id as string;
  }

  async function loginAndGetEntry(email: string, rawBrowserProof?: string) {
    const cookieHeader = rawBrowserProof ? `swyra-browser=${rawBrowserProof}` : "";
    const res = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", ...(cookieHeader ? { Cookie: cookieHeader } : {}) }),
      body: JSON.stringify({ email, password }),
    });
    assert.equal(res.status, 200);
    const entryId = res.headers.get("x-browser-entry-id")!;
    const bc = extractCookie(res, "swyra-browser");
    const sessionCookie = extractCookie(res, "better-auth.session_token");
    const rawProof = bc ? bc.split("=")[1] : rawBrowserProof!;
    const setDoc = await findActiveBrowserSet(db, rawProof);
    const entry = setDoc?.entries.find((e: any) => e.entryId === entryId);
    return { entryId, rawProof, sessionCookie, sessionId: entry?.sessionId as string, setId: setDoc?.setId as string };
  }

  async function createClient(clientId: string, opts: { isPublic?: boolean; skipConsent?: boolean } = {}) {
    const isPublic = opts.isPublic ?? true;
    await db.collection("oauthClient").insertOne({
      id: clientId, clientId, name: clientId,
      redirectUris: ["https://app.example.com/cb", "http://localhost:5174/callback"],
      clientType: "public", accessPolicy: isPublic ? "open" : "private", isPublic, isDev: true,
      skipConsent: opts.skipConsent ?? false, tokenEndpointAuthMethod: "none",
      grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"], scopes: ["openid", "profile", "email"], credentialVersion: 1, createdAt: new Date(),
    });
    return { clientId };
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p3_continuation_binding");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName, BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000", FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret,
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
    });
    const mongoMod = await import("../../src/db/mongo");
    closeDb = mongoMod.closeDb;
    setTestDbOverride = mongoMod.setTestDbOverride;
    authProvider = (await import("../../src/utils/auth")).authProvider;
    app = (await import("../../src/app")).default;
    findActiveBrowserSet = (await import("../../src/identity/browser-session-registry")).findActiveBrowserSet;
    const txMod = await import("../../src/db/oauth-transactions");
    createOAuthTransaction = txMod.createOAuthTransaction;
    bindOAuthTransactionSelection = txMod.bindOAuthTransactionSelection;
    db = suite.client.db(suite.dbName);
    setTestDbOverride(db);
  });

  after(async () => {
    if (closeDb) await closeDb().catch(() => {});
    if (suite?.cleanup) await suite.cleanup().catch(() => {});
  });

  it("uses the selected subject for continuation policy checks despite conflicting ambient cookie", async () => {
    const emailA = `cont_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const emailB = `cont_b_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const userA = await registerUser(emailA);
    await registerUser(emailB);
    const { clientId } = await createClient("cont-private-client", { isPublic: false, skipConsent: true });

    // Only userA is authorized for the private client; ambient cookie belongs to userB
    await db.collection("user_app_registrations").insertOne({ userId: userA, clientId, registeredAt: new Date() });

    const sA = await loginAndGetEntry(emailA);
    const sB = await loginAndGetEntry(emailB, sA.rawProof);

    const tx = await createOAuthTransaction({
      transactionId: `tx_cont_${crypto.randomBytes(6).toString("hex")}`,
      clientId, redirectUri: "https://app.example.com/cb", state: "st_cont_a",
      codeChallenge, codeChallengeMethod: "S256", scope: "openid profile email",
    });

    await bindOAuthTransactionSelection({
      transactionId: tx.transactionId,
      expectedRevision: 0,
      browserSetId: sB.setId,
      entryId: sA.entryId,
      userId: userA,
      sessionId: sA.sessionId,
      sessionVersion: 1,
      tokenVersion: 1,
    });

    const res = await app.request("/api/auth/oauth2/continue", {
      method: "POST",
      headers: hdrs({
        "Content-Type": "application/json",
        Cookie: `swyra-browser=${sB.rawProof}; ${sB.sessionCookie}`,
      }),
      body: JSON.stringify({ transaction_id: tx.transactionId, client_id: clientId, selected: true }),
    });
    assert.notEqual(res.status, 403, "Continuation must evaluate private app access for selected userA, not ambient userB");
    assert.notEqual(res.status, 401, "Continuation must accept valid selected session despite ambient cookie");
    assert.notEqual(res.status, 500, "Continuation dispatch must not throw");
  });

  it("fails closed on /oauth2/continue when selected session is stale or revoked", async () => {
    const email = `cont_stale_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const userId = await registerUser(email);
    const { clientId } = await createClient("cont-stale-client", { isPublic: true, skipConsent: true });

    const s = await loginAndGetEntry(email);
    const tx = await createOAuthTransaction({
      transactionId: `tx_stale_${crypto.randomBytes(6).toString("hex")}`,
      clientId, redirectUri: "https://app.example.com/cb", state: "st_stale",
      codeChallenge, codeChallengeMethod: "S256", scope: "openid profile email",
    });

    await bindOAuthTransactionSelection({
      transactionId: tx.transactionId,
      expectedRevision: 0,
      browserSetId: s.setId,
      entryId: s.entryId,
      userId,
      sessionId: s.sessionId,
      sessionVersion: 1,
      tokenVersion: 1,
    });

    // Sign out the selected entry so the selection is stale/revoked
    const soRes = await app.request("/api/identity/accounts/sign-out", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${s.rawProof}` }),
      body: JSON.stringify({ entryId: s.entryId }),
    });
    assert.equal(soRes.status, 200);
    const nextProof = extractCookie(soRes, "swyra-browser");

    const contRes = await app.request("/api/auth/oauth2/continue", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `${nextProof}; ${s.sessionCookie}` }),
      body: JSON.stringify({ transaction_id: tx.transactionId, client_id: clientId, selected: true }),
    });
    assert.equal(contRes.status, 401);
    const errJson = await contRes.json();
    assert.equal(errJson.code, "ERR_SESSION_REVOKED");
  });

  it("preserves legacy /oauth2/continue behavior for transactions without a selection", async () => {
    const email = `cont_leg_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const userId = await registerUser(email);
    const { clientId } = await createClient("cont-legacy-client", { isPublic: false, skipConsent: true });

    const s = await loginAndGetEntry(email);
    const tx = await createOAuthTransaction({
      transactionId: `tx_leg_${crypto.randomBytes(6).toString("hex")}`,
      clientId, redirectUri: "https://app.example.com/cb", state: "st_leg",
      codeChallenge, codeChallengeMethod: "S256", scope: "openid profile email",
    });

    // Without private app membership, ambient session is checked and denied with 403
    const deniedRes = await app.request("/api/auth/oauth2/continue", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: s.sessionCookie }),
      body: JSON.stringify({ transaction_id: tx.transactionId, client_id: clientId }),
    });
    assert.equal(deniedRes.status, 403);

    // Grant membership and retry legacy continuation
    await db.collection("user_app_registrations").insertOne({ userId, clientId, registeredAt: new Date() });
    const okRes = await app.request("/api/auth/oauth2/continue", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: s.sessionCookie }),
      body: JSON.stringify({ transaction_id: tx.transactionId, client_id: clientId }),
    });
    assert.notEqual(okRes.status, 401);
    assert.notEqual(okRes.status, 403);
  });
});
