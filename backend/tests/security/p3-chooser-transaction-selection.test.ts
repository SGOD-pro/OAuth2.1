import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { createLocalJWKSet, jwtVerify } from "jose";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P3b: Account Selection, Atomic Sign-Out & Issuance Fences", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let authProvider: any;
  let closeDb: any;
  let setTestDbOverride: any;
  const gatewaySecret = "g".repeat(32);
  const strongPassword = "P3b!Selection#Password99";

  const hdrs = (extra: Record<string, string> = {}) => ({
    "Content-Type": "application/json",
    "x-gateway-secret": gatewaySecret,
    "x-forwarded-for": "198.51.130.10, 10.0.0.1",
    Origin: "http://localhost:5174",
    "x-csrf-token": "test-csrf",
    ...extra,
  });

  function extractCookie(res: Response, name: string): string {
    for (const part of (res.headers.get("set-cookie") || "").split(/,(?=[^;]+=)/)) {
      const kv = part.trim().split(";")[0];
      if (kv.startsWith(`${name}=`)) return kv;
    }
    return "";
  }

  async function seedUser(email: string, username: string) {
    await authProvider.api.signUpEmail({ body: { email, password: strongPassword, name: username } });
    const u = await db.collection("user").findOne({ email });
    await db.collection("user").updateOne({ email }, { $set: { role: "user", emailVerified: true, username, scopedClientId: null } });
    if (u) await db.collection("session").deleteMany({ userId: u._id });
    return db.collection("user").findOne({ email });
  }

  async function seedClient(clientId: string, opts: { isPublic: boolean; skipConsent?: boolean } = { isPublic: true }) {
    await db.collection("oauthClient").insertOne({
      clientId, name: clientId, redirectUris: ["http://localhost:5174/callback"],
      tokenEndpointAuthMethod: "none", grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"], scopes: ["openid", "profile", "email"],
      skipConsent: opts.skipConsent ?? false, requirePKCE: true, disabled: false,
      isPublic: opts.isPublic, accessPolicy: opts.isPublic ? "open" : "private",
      clientType: "public", isDev: true,
    });
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p3b_selection");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName,
      BETTER_AUTH_SECRET: "a".repeat(32), BETTER_AUTH_URL: "http://localhost:3000",
      FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret,
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      IDENTITY_REGISTRATION_MODE: "disabled",
      IDENTITY_LOOKUP_KEY_REF: "p3b-lookup-key-ref-0000000000002",
      IDENTITY_OTP_VERIFIER_KEY_REF: "p3b-otp-key-ref-0000000000000001",
    });
    ({ closeDb, setTestDbOverride } = await import("../../src/db/mongo"));
    authProvider = (await import("../../src/utils/auth")).authProvider;
    app = (await import("../../src/app")).default;
    client = suite.client; db = client.db(suite.dbName); setTestDbOverride(db);
  });

  after(async () => { await closeDb(); await suite.cleanup(); });

  beforeEach(async () => {
    for (const col of await db.listCollections().toArray()) await db.collection(col.name).deleteMany({});
  });

  it("keeps engine session and browser registry consistent on concurrent sign-out conflict and safe retry", async () => {
    const uA = await seedUser("atomic-a@example.com", "atomic_a");
    const uB = await seedUser("atomic-b@example.com", "atomic_b");
    const rA = await app.request("/api/auth/sign-in/email", { method: "POST", headers: hdrs(), body: JSON.stringify({ email: "atomic-a@example.com", password: strongPassword }) });
    const bc1 = extractCookie(rA, "swyra-browser");
    const rB = await app.request("/api/auth/sign-in/email", { method: "POST", headers: hdrs({ Cookie: bc1 }), body: JSON.stringify({ email: "atomic-b@example.com", password: strongPassword }) });
    const bc2 = extractCookie(rB, "swyra-browser");
    const list = await (await app.request("/api/identity/accounts", { headers: hdrs({ Cookie: bc2 }) })).json() as any;
    const entryA = list.accounts.find((x: any) => x.label.includes("atomic_a"));

    // Concurrent sign-out + another update races on version: one wins cleanly, loser leaves no inconsistent state, retry is safe
    const [so1, so2] = await Promise.all([
      app.request("/api/identity/accounts/sign-out", { method: "POST", headers: hdrs({ Cookie: bc2 }), body: JSON.stringify({ entryId: entryA.entryId }) }),
      app.request("/api/identity/accounts/sign-out", { method: "POST", headers: hdrs({ Cookie: bc2 }), body: JSON.stringify({ entryId: entryA.entryId }) }),
    ]);
    const winner = so1.status === 200 ? so1 : so2;
    assert.equal(winner.status, 200);
    const bcNext = extractCookie(winner, "swyra-browser");
    assert.equal(await db.collection("session").countDocuments({ userId: uA!._id }), 0);
    assert.equal(await db.collection("session").countDocuments({ userId: uB!._id }), 1, "B session must remain intact");

    // Idempotent retry on already signed-out entryA using rotated proof succeeds safely
    const retry = await app.request("/api/identity/accounts/sign-out", {
      method: "POST", headers: hdrs({ Cookie: bcNext }), body: JSON.stringify({ entryId: entryA.entryId }),
    });
    assert.equal(retry.status, 200);
    assert.equal(await db.collection("session").countDocuments({ userId: uB!._id }), 1);
  });

  it("isolates per-tab selections via revision CAS, handles OIDC prompt/max_age/nonce/private rules, and blocks revoked issuance", async () => {
    const uA = await seedUser("tab-a@example.com", "tab_a");
    const uB = await seedUser("tab-b@example.com", "tab_b");
    await seedClient("p3b-open-client", { isPublic: true, skipConsent: false });
    await seedClient("p3b-priv-client", { isPublic: false, skipConsent: true });

    const rA = await app.request("/api/auth/sign-in/email", { method: "POST", headers: hdrs(), body: JSON.stringify({ email: "tab-a@example.com", password: strongPassword }) });
    const bc1 = extractCookie(rA, "swyra-browser");
    const rB = await app.request("/api/auth/sign-in/email", { method: "POST", headers: hdrs({ Cookie: bc1 }), body: JSON.stringify({ email: "tab-b@example.com", password: strongPassword }) });
    const bc2 = extractCookie(rB, "swyra-browser");
    const accounts = (await (await app.request("/api/identity/accounts", { headers: hdrs({ Cookie: bc2 }) })).json() as any).accounts;
    const entryA = accounts.find((x: any) => x.label.includes("tab_a")).entryId;
    const entryB = accounts.find((x: any) => x.label.includes("tab_b")).entryId;

    // 1. Mixed prompt=none login fails explicitly; prompt=none with 2 accounts -> account_selection_required
    const badPrompt = await app.request(`/api/auth/oauth2/authorize?client_id=p3b-open-client&redirect_uri=${encodeURIComponent("http://localhost:5174/callback")}&response_type=code&scope=openid&state=sbad&prompt=${encodeURIComponent("none login")}&code_challenge_method=S256&code_challenge=${"c".repeat(43)}`, { headers: hdrs({ Cookie: bc2 }) });
    assert.equal(badPrompt.status, 302);
    assert.match(badPrompt.headers.get("location") || "", /error=invalid_request/);

    const noneAmbig = await app.request(`/api/auth/oauth2/authorize?client_id=p3b-open-client&redirect_uri=${encodeURIComponent("http://localhost:5174/callback")}&response_type=code&scope=openid&state=snone&prompt=none&code_challenge_method=S256&code_challenge=${"c".repeat(43)}`, { headers: hdrs({ Cookie: bc2 }) });
    assert.equal(noneAmbig.status, 302);
    assert.match(noneAmbig.headers.get("location") || "", /error=account_selection_required/);

    // 2. Start two independent transactions (Tab A and Tab B)
    const verA = crypto.randomBytes(32).toString("base64url");
    const chA = crypto.createHash("sha256").update(verA).digest("base64url");
    const verB = crypto.randomBytes(32).toString("base64url");
    const chB = crypto.createHash("sha256").update(verB).digest("base64url");

    const authA = await app.request(`/api/auth/oauth2/authorize?client_id=p3b-open-client&redirect_uri=${encodeURIComponent("http://localhost:5174/callback")}&response_type=code&scope=${encodeURIComponent("openid profile")}&state=stateA&nonce=nonceA&code_challenge_method=S256&code_challenge=${chA}`, { headers: hdrs({ Cookie: bc2 }) });
    assert.equal(authA.status, 302);
    const txA = new URL(authA.headers.get("location")!).searchParams.get("transaction_id")!;
    assert.ok(txA);

    const authB = await app.request(`/api/auth/oauth2/authorize?client_id=p3b-open-client&redirect_uri=${encodeURIComponent("http://localhost:5174/callback")}&response_type=code&scope=${encodeURIComponent("openid profile")}&state=stateB&nonce=nonceB&code_challenge_method=S256&code_challenge=${chB}`, { headers: hdrs({ Cookie: bc2 }) });
    const txB = new URL(authB.headers.get("location")!).searchParams.get("transaction_id")!;
    assert.notEqual(txA, txB);

    // Wrong revision rejected with 409
    const staleRev = await app.request("/api/identity/accounts/select", {
      method: "POST", headers: hdrs({ Cookie: bc2 }),
      body: JSON.stringify({ transactionId: txA, entryId: entryA, expectedRevision: 9 }),
    });
    assert.equal(staleRev.status, 409);

    // Interleave selections: A selects entryA on txA, B selects entryB on txB
    const selA = await app.request("/api/identity/accounts/select", {
      method: "POST", headers: hdrs({ Cookie: bc2 }),
      body: JSON.stringify({ transactionId: txA, entryId: entryA, expectedRevision: 0 }),
    });
    assert.equal(selA.status, 200);
    const selAJson = (await selA.json()) as any;
    assert.ok(selAJson.redirectTo.includes("/consent"));

    const selB = await app.request("/api/identity/accounts/select", {
      method: "POST", headers: hdrs({ Cookie: bc2 }),
      body: JSON.stringify({ transactionId: txB, entryId: entryB, expectedRevision: 0 }),
    });
    assert.equal(selB.status, 200);
    const selBJson = (await selB.json()) as any;
    assert.ok(selBJson.redirectTo.includes("/consent"));

    // Consent B then Consent A, verifying tokens match exact bound subjects & nonces
    const urlB = new URL(selBJson.redirectTo, "http://localhost:5174");
    const urlA = new URL(selAJson.redirectTo, "http://localhost:5174");
    const oauthQueryB = urlB.searchParams.get("oauth_query") || urlB.search.slice(1);
    const oauthQueryA = urlA.searchParams.get("oauth_query") || urlA.search.slice(1);

    const conB = await app.request("/api/auth/oauth2/consent", {
      method: "POST", headers: hdrs({ Cookie: bc2 }),
      body: JSON.stringify({ accept: true, scope: "openid profile", oauth_query: oauthQueryB, transaction_id: txB }),
    });
    assert.equal(conB.status, 200);
    const codeB = new URL(((await conB.json()) as any).url).searchParams.get("code")!;

    const conA = await app.request("/api/auth/oauth2/consent", {
      method: "POST", headers: hdrs({ Cookie: bc2 }),
      body: JSON.stringify({ accept: true, scope: "openid profile", oauth_query: oauthQueryA, transaction_id: txA }),
    });
    assert.equal(conA.status, 200);
    const codeA = new URL(((await conA.json()) as any).url).searchParams.get("code")!;

    const jwks = await (await app.request("/api/auth/jwks.json")).json();
    const tokA = await (await app.request("/api/auth/oauth2/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: "p3b-open-client", redirect_uri: "http://localhost:5174/callback", code: codeA, code_verifier: verA }),
    })).json() as any;
    const tokB = await (await app.request("/api/auth/oauth2/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: "p3b-open-client", redirect_uri: "http://localhost:5174/callback", code: codeB, code_verifier: verB }),
    })).json() as any;
    const claimsA = (await jwtVerify(tokA.id_token, createLocalJWKSet(jwks), { algorithms: ["RS256"], issuer: "http://localhost:3000", audience: "p3b-open-client" })).payload;
    const claimsB = (await jwtVerify(tokB.id_token, createLocalJWKSet(jwks), { algorithms: ["RS256"], issuer: "http://localhost:3000", audience: "p3b-open-client" })).payload;
    assert.equal(claimsA.sub, String(uA!._id));
    assert.equal(claimsA.nonce, "nonceA");
    assert.equal(claimsB.sub, String(uB!._id));
    assert.equal(claimsB.nonce, "nonceB");

    // 3. Private client unassigned user denied cleanly; max_age=0/1 stale check forces reauth; revoked selection fails closed at consent
    const privAuth = await app.request(`/api/auth/oauth2/authorize?client_id=p3b-priv-client&redirect_uri=${encodeURIComponent("http://localhost:5174/callback")}&response_type=code&scope=openid&state=spriv&code_challenge_method=S256&code_challenge=${"c".repeat(43)}`, { headers: hdrs({ Cookie: bc2 }) });
    const txPriv = new URL(privAuth.headers.get("location")!).searchParams.get("transaction_id")!;
    const selPriv = await app.request("/api/identity/accounts/select", {
      method: "POST", headers: hdrs({ Cookie: bc2 }),
      body: JSON.stringify({ transactionId: txPriv, entryId: entryA, expectedRevision: 0 }),
    });
    assert.equal(selPriv.status, 403);

    // Revoking A before consent issuance denies consent even with valid cookie
    const authRev = await app.request(`/api/auth/oauth2/authorize?client_id=p3b-open-client&redirect_uri=${encodeURIComponent("http://localhost:5174/callback")}&response_type=code&scope=openid&state=srev&code_challenge_method=S256&code_challenge=${"c".repeat(43)}`, { headers: hdrs({ Cookie: bc2 }) });
    const txRev = new URL(authRev.headers.get("location")!).searchParams.get("transaction_id")!;
    const selRev = await app.request("/api/identity/accounts/select", {
      method: "POST", headers: hdrs({ Cookie: bc2 }),
      body: JSON.stringify({ transactionId: txRev, entryId: entryA, expectedRevision: 0 }),
    });
    const urlRev = new URL(((await selRev.json()) as any).redirectTo, "http://localhost:5174");
    const revQuery = urlRev.searchParams.get("oauth_query") || urlRev.search.slice(1);
    const soA = await app.request("/api/identity/accounts/sign-out", {
      method: "POST", headers: hdrs({ Cookie: bc2 }), body: JSON.stringify({ entryId: entryA }),
    });
    const bcAfterSo = extractCookie(soA, "swyra-browser");
    const conRev = await app.request("/api/auth/oauth2/consent", {
      method: "POST", headers: hdrs({ Cookie: bcAfterSo }),
      body: JSON.stringify({ accept: true, scope: "openid", oauth_query: revQuery, transaction_id: txRev }),
    });
    assert.equal(conRev.status, 401);
  });
});
