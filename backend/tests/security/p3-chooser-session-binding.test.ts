import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ObjectId } from "mongodb";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const workerPath = path.resolve(__dirname, "../fixtures/p3-external-worker.ts");

describe("P3 Chooser Session Binding, Freshness and Process Concurrency", () => {
  let suite: any;
  let db: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let app: any;
  let authProvider: any;
  let setTokenBarrierHookForTesting: any;
  let findActiveBrowserSet: any;
  let createOAuthTransaction: any;
  const gatewaySecret = "g".repeat(32);
  const password = "Password123!@#Secure";
  const codeVerifier = "test_code_verifier_123456789012345678901234567890";
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

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
    const rawProof = bc ? bc.split("=")[1] : rawBrowserProof!;
    const setDoc = await findActiveBrowserSet(db, rawProof);
    const entry = setDoc?.entries.find((e: any) => e.entryId === entryId);
    return { entryId, rawProof, sessionId: entry?.sessionId as string, setId: setDoc?.setId as string };
  }

  async function selectAccount(rawProof: string, transactionId: string, entryId: string, expectedRevision = 0) {
    return app.request("/api/identity/accounts/select", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${rawProof}` }),
      body: JSON.stringify({ transactionId, entryId, expectedRevision }),
    });
  }

  async function submitConsent(rawProof: string, transactionId: string, oauthQuery: string) {
    return app.request("/api/auth/oauth2/consent", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${rawProof}` }),
      body: JSON.stringify({ accept: true, scope: "openid profile email", transaction_id: transactionId, oauth_query: oauthQuery }),
    });
  }

  async function createClient(clientId: string, skipConsent = false) {
    await db.collection("oauthClient").insertOne({
      id: clientId, clientId, name: clientId,
      redirectUris: ["https://app.example.com/cb", "http://localhost:5174/callback"],
      clientType: "public", accessPolicy: "open", isPublic: true, isDev: true,
      skipConsent, tokenEndpointAuthMethod: "none", grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"], scopes: ["openid", "profile", "email"], credentialVersion: 1, createdAt: new Date(),
    });
    return { clientId };
  }

  function runExternalWorker(action: string, args: Record<string, any>) {
    const res = spawnSync(
      process.execPath,
      [path.resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs"), workerPath, action, JSON.stringify({ ...args, mongoUri: suite.uri, dbName: suite.dbName })],
      { encoding: "utf-8", timeout: 15000 }
    );
    assert.equal(res.status, 0, `External worker ${action} failed: ${res.stderr || res.stdout}`);
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p3_chooser_binding");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName, BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000", FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret, TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
    });
    const mongoMod = await import("../../src/db/mongo");
    closeDb = mongoMod.closeDb;
    setTestDbOverride = mongoMod.setTestDbOverride;
    authProvider = (await import("../../src/utils/auth")).authProvider;
    app = (await import("../../src/app")).default;
    setTokenBarrierHookForTesting = (await import("../../src/routes/auth-keys")).setTokenBarrierHookForTesting;
    findActiveBrowserSet = (await import("../../src/identity/browser-session-registry")).findActiveBrowserSet;
    createOAuthTransaction = (await import("../../src/db/oauth-transactions")).createOAuthTransaction;
    db = suite.client.db(suite.dbName);
    setTestDbOverride(db);
  });

  after(async () => {
    setTokenBarrierHookForTesting(null);
    if (closeDb) await closeDb().catch(() => {});
    if (suite?.cleanup) await suite.cleanup().catch(() => {});
  });

  it("enforces freshness against two sessions of the same user and rejects unproven freshness", async () => {
    const email = `multi_sess_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const userId = await registerUser(email);
    const { clientId } = await createClient("Freshness Verification Client", true);

    const s1 = await loginAndGetEntry(email);
    const s2 = await loginAndGetEntry(email);
    const s3 = await loginAndGetEntry(email);

    const now = Date.now();
    const oldCreated = new Date(now - 1200 * 1000);
    const freshCreated = new Date(now - 10 * 1000);

    const sessFilters = (sid: string) => [{ id: sid }, ...(ObjectId.isValid(sid) && sid.length === 24 ? [{ _id: new ObjectId(sid) }] : [])];
    await db.collection("session").updateOne({ $or: sessFilters(s1.sessionId) }, { $set: { createdAt: oldCreated, updatedAt: oldCreated } });
    await db.collection("session").updateOne({ $or: sessFilters(s2.sessionId) }, { $set: { createdAt: freshCreated, updatedAt: freshCreated } });
    await db.collection("session").updateOne({ $or: sessFilters(s3.sessionId) }, { $unset: { createdAt: "" } });

    const entryOldId = `ent_${crypto.randomBytes(6).toString("hex")}`;
    const entryFreshId = `ent_${crypto.randomBytes(6).toString("hex")}`;
    const entryUnprovenId = `ent_${crypto.randomBytes(6).toString("hex")}`;

    await db.collection("browser_session_sets").updateOne(
      { setId: s3.setId },
      {
        $push: {
          entries: {
            $each: [
              { entryId: entryOldId, userId, sessionId: s1.sessionId, sessionVersion: 1, status: "active", label: "user", addedAt: oldCreated, lastUsedAt: oldCreated, signedOutAt: null },
              { entryId: entryFreshId, userId, sessionId: s2.sessionId, sessionVersion: 1, status: "active", label: "user", addedAt: freshCreated, lastUsedAt: freshCreated, signedOutAt: null },
              { entryId: entryUnprovenId, userId, sessionId: s3.sessionId, sessionVersion: 1, status: "active", label: "user", addedAt: freshCreated, lastUsedAt: freshCreated, signedOutAt: null },
            ]
          }
        }
      }
    );

    const txMaxAge = await createOAuthTransaction({
      transactionId: `tx_ma_${crypto.randomBytes(6).toString("hex")}`,
      clientId, redirectUri: "https://app.example.com/cb", state: "st_ma", maxAge: 300,
      codeChallenge, codeChallengeMethod: "S256", scope: "openid profile email",
    });

    const selOld = await selectAccount(s3.rawProof, txMaxAge.transactionId, entryOldId, 0);
    assert.equal(selOld.status, 403, "Old session must fail max_age freshness check");
    const jsonOld = await selOld.json();
    assert.equal(jsonOld.code, "ERR_MAX_AGE_EXCEEDED");

    const selFresh = await selectAccount(s3.rawProof, txMaxAge.transactionId, entryFreshId, 0);
    assert.equal(selFresh.status, 200, "Fresh session of same user must pass max_age freshness check");

    const txPrompt = await createOAuthTransaction({
      transactionId: `tx_pr_${crypto.randomBytes(6).toString("hex")}`,
      clientId, redirectUri: "https://app.example.com/cb", state: "st_pr", prompt: "login",
      codeChallenge, codeChallengeMethod: "S256", scope: "openid profile email",
    });
    await db.collection("oauth_transactions").updateOne({ transactionId: txPrompt.transactionId }, { $set: { createdAt: new Date(now - 60 * 1000) } });

    const selPromptOld = await selectAccount(s3.rawProof, txPrompt.transactionId, entryOldId, 0);
    assert.equal(selPromptOld.status, 403, "Old session must fail prompt=login freshness check");
    const jsonPromptOld = await selPromptOld.json();
    assert.equal(jsonPromptOld.code, "ERR_PROMPT_LOGIN_REQUIRED");

    const selPromptFresh = await selectAccount(s3.rawProof, txPrompt.transactionId, entryFreshId, 0);
    assert.equal(selPromptFresh.status, 200, "Fresh session of same user must pass prompt=login freshness check");

    const txUnproven = await createOAuthTransaction({
      transactionId: `tx_un_${crypto.randomBytes(6).toString("hex")}`,
      clientId, redirectUri: "https://app.example.com/cb", state: "st_un", maxAge: 300,
      codeChallenge, codeChallengeMethod: "S256", scope: "openid profile email",
    });

    const selUnproven = await selectAccount(s3.rawProof, txUnproven.transactionId, entryUnprovenId, 0);
    assert.equal(selUnproven.status, 403, "Session without verifiable authTime must fail freshness without fallback");
    const jsonUnproven = await selUnproven.json();
    assert.equal(jsonUnproven.code, "ERR_MAX_AGE_EXCEEDED");
    assert.equal(selUnproven.status, 403, "Session without verifiable authTime must fail freshness without fallback");
  });

  it("invalidates pending issuance when separate process commits sign-out on shared MongoDB", async () => {
    const email = `sep_so_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await registerUser(email);
    const { clientId } = await createClient("Separate Process Signout Client", false);

    const s = await loginAndGetEntry(email);
    const tx = await createOAuthTransaction({
      transactionId: `tx_so_${crypto.randomBytes(6).toString("hex")}`,
      clientId, redirectUri: "https://app.example.com/cb", state: "st_so",
      codeChallenge, codeChallengeMethod: "S256", scope: "openid profile email",
    });

    const selRes = await selectAccount(s.rawProof, tx.transactionId, s.entryId, 0);
    assert.equal(selRes.status, 200);
    const selJson = await selRes.json();
    assert.equal(selJson.requiresConsent, true);

    const redirectUrl = new URL(selJson.redirectTo, "http://localhost");
    const signedOauthQuery = redirectUrl.searchParams.get("oauth_query") || redirectUrl.search.slice(1);

    let separateProcessExecuted = false;
    setTokenBarrierHookForTesting(async (stage: string) => {
      if (stage === "before_authorize_commit") {
        separateProcessExecuted = true;
        runExternalWorker("sign-out", { rawBrowserProof: s.rawProof, entryId: s.entryId });
      }
    });

    try {
      const consentRes = await submitConsent(s.rawProof, tx.transactionId, signedOauthQuery);
      assert.equal(separateProcessExecuted, true, "Separate worker must have executed concurrently");
      assert.equal(consentRes.status, 401, "Pending issuance must fail closed when separate process signed out");
      const errJson = await consentRes.json();
      assert.equal(errJson.code, "ERR_SESSION_REVOKED");
      const codeCount = await db.collection("oauthAuthorizationCode").countDocuments({ transactionId: tx.transactionId });
      assert.equal(codeCount, 0, "Authorization code must be purged and absent from store");
    } finally {
      setTokenBarrierHookForTesting(null);
    }
  });

  it("invalidates pending issuance when separate process commits transaction reselection", async () => {
    const emailA = `re_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const emailB = `re_b_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await registerUser(emailA);
    const userB = await registerUser(emailB);
    const { clientId } = await createClient("Separate Process Reselect Client", false);

    const sA = await loginAndGetEntry(emailA);
    const sB = await loginAndGetEntry(emailB, sA.rawProof);

    const tx = await createOAuthTransaction({
      transactionId: `tx_re_${crypto.randomBytes(6).toString("hex")}`,
      clientId, redirectUri: "https://app.example.com/cb", state: "st_re",
      codeChallenge, codeChallengeMethod: "S256", scope: "openid profile email",
    });

    const selA = await selectAccount(sB.rawProof, tx.transactionId, sA.entryId, 0);
    assert.equal(selA.status, 200);
    const selAJson = await selA.json();
    assert.equal(selAJson.requiresConsent, true);

    const redirectUrl = new URL(selAJson.redirectTo, "http://localhost");
    const signedOauthQuery = redirectUrl.searchParams.get("oauth_query") || redirectUrl.search.slice(1);

    let separateReselectExecuted = false;
    setTokenBarrierHookForTesting(async (stage: string) => {
      if (stage === "before_authorize_commit") {
        separateReselectExecuted = true;
        runExternalWorker("reselect", {
          transactionId: tx.transactionId,
          expectedRevision: 1,
          browserSetId: sB.setId,
          entryId: sB.entryId,
          userId: userB,
          sessionId: sB.sessionId,
        });
      }
    });

    try {
      const consentRes = await submitConsent(sB.rawProof, tx.transactionId, signedOauthQuery);
      assert.equal(separateReselectExecuted, true, "Separate worker must have executed reselection concurrently");
      assert.equal(consentRes.status, 401, "Consent code issuance must fail closed when reselection committed");
      const consentJson = await consentRes.json();
      assert.equal(consentJson.code, "ERR_SESSION_REVOKED");
    } finally {
      setTokenBarrierHookForTesting(null);
    }
  });
});
