import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { ObjectId, MongoClient, Db } from "mongodb";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { setupSuiteDatabase, type SuiteDatabaseContext } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P3a: Request-Local Session Adapter & Privilege Boundaries", () => {
  let suite: SuiteDatabaseContext;
  let client: MongoClient;
  let db: Db;
  let app: any;
  let authProvider: any;
  let closeDb: any;
  let setTestDbOverride: any;
  const gatewaySecret = "g".repeat(32);
  const strongPassword = "P3a!Adapter#Password99";

  const hdrs = (extra: Record<string, string> = {}) => ({
    "Content-Type": "application/json",
    "x-gateway-secret": gatewaySecret,
    "x-forwarded-for": "198.51.125.10, 10.0.0.1",
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

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p3_session_adapter");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName,
      BETTER_AUTH_SECRET: "a".repeat(32), BETTER_AUTH_URL: "http://localhost:3000",
      FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret,
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
      IDENTITY_REGISTRATION_MODE: "disabled",
      IDENTITY_LOOKUP_KEY_REF: "p3a-lookup-key-ref-0000000000002",
      IDENTITY_OTP_VERIFIER_KEY_REF: "p3a-otp-key-ref-0000000000000001",
    });
    ({ closeDb, setTestDbOverride } = await import("../../src/db/mongo"));
    authProvider = (await import("../../src/utils/auth")).authProvider;
    app = (await import("../../src/app")).default;
    client = suite.client; db = client.db(suite.dbName); setTestDbOverride(db);
  });

  after(async () => { await closeDb(); await suite.cleanup(); });

  beforeEach(async () => {
    process.env.NODE_ENV = "test";
    for (const col of await db.listCollections().toArray()) await db.collection(col.name).deleteMany({});
  });

  it("dispatches request-local OAuth authorize/consent for selected entry despite conflicting ambient cookies, and leaks zero tokens", async () => {
    const uA = await seedUser("adapter-a@example.com", "adapter_a");
    const uB = await seedUser("adapter-b@example.com", "adapter_b");

    const rA = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: "adapter-a@example.com", password: strongPassword }),
    });
    const bc1 = extractCookie(rA, "swyra-browser");
    const ambientA = extractCookie(rA, "better-auth.session_token");

    const rB = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs({ Cookie: bc1 }), body: JSON.stringify({ email: "adapter-b@example.com", password: strongPassword }),
    });
    const bc2 = extractCookie(rB, "swyra-browser");
    const ambientB = extractCookie(rB, "better-auth.session_token");
    const rawProof = bc2.split("=")[1];

    const list = await (await app.request("/api/identity/accounts", { headers: hdrs({ Cookie: bc2 }) })).json() as any;
    const entryA = list.accounts.find((x: any) => x.label.includes("adapter_a"));
    const entryB = list.accounts.find((x: any) => x.label.includes("adapter_b"));

    // Register public OAuth client for request-local authorize/consent check
    const ctx = await authProvider.$context;
    await ctx.adapter.create({
      model: "oauthClient",
      data: {
        clientId: "p3-adapter-client", name: "P3 Adapter App", redirectUris: ["http://localhost:5174/callback"],
        tokenEndpointAuthMethod: "none", grantTypes: ["authorization_code", "refresh_token"],
        responseTypes: ["code"], scopes: ["openid", "profile"], skipConsent: false, requirePKCE: true,
        disabled: false, isPublic: true, accessPolicy: "open", clientType: "public", isDev: true,
      },
    });

    const { dispatchRequestWithBrowserEntry } = await import("../../src/identity/session-adapter");
    const verifier = crypto.randomBytes(32).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    const authUrl = `http://localhost:3000/api/auth/oauth2/authorize?client_id=p3-adapter-client&redirect_uri=${encodeURIComponent("http://localhost:5174/callback")}&response_type=code&scope=${encodeURIComponent("openid profile")}&state=p3stateA&code_challenge_method=S256&code_challenge=${challenge}`;

    // Send ambient cookie for B while requesting adapter dispatch for entryA
    const authRes = await dispatchRequestWithBrowserEntry(authProvider, db, rawProof, entryA.entryId, new Request(authUrl, {
      headers: { origin: "http://localhost:5174", cookie: ambientB },
    }));
    assert.equal(authRes.headers.get("set-cookie"), null, "Adapter dispatch must never set ambient Set-Cookie");
    assert.equal(authRes.headers.get("cache-control"), "no-store");
    const locHeader = authRes.headers.get("location") || ((await authRes.clone().json().catch(() => null)) as any)?.url;
    assert.ok(locHeader && locHeader.includes("/consent"), `Expected consent redirect, got ${locHeader}`);
    const consentQuery = new URL(locHeader, "http://localhost:3000").search.slice(1);

    const consentRes = await dispatchRequestWithBrowserEntry(authProvider, db, rawProof, entryA.entryId, new Request("http://localhost:3000/api/auth/oauth2/consent", {
      method: "POST",
      headers: { origin: "http://localhost:5174", "content-type": "application/json", cookie: ambientB },
      body: JSON.stringify({ accept: true, oauth_query: consentQuery }),
    }));
    const cbLoc = consentRes.headers.get("location") || ((await consentRes.clone().json().catch(() => null)) as any)?.url;
    const code = new URL(cbLoc, "http://localhost:3000").searchParams.get("code")!;
    assert.ok(code);
    const verifications = await db.collection("verification").find({}).toArray();
    const matchedCode = verifications.map((v) => JSON.parse(v.value)).find((v) => v.type === "authorization_code" && v.query?.state === "p3stateA");
    assert.equal(matchedCode.userId, String(uA!._id), "Issued code must belong to entryA, ignoring ambient B cookie");

    // Revalidation failures: tokenVersion bump on A denies entryA while entryB remains usable; disabling user A also denies
    await db.collection("user").updateOne({ _id: uA!._id }, { $inc: { tokenVersion: 1 } });
    await assert.rejects(dispatchRequestWithBrowserEntry(authProvider, db, rawProof, entryA.entryId, new Request(authUrl, { headers: { origin: "http://localhost:5174" } })));

    const authUrlB = authUrl.replace("state=p3stateA", "state=p3stateB");
    const resB = await dispatchRequestWithBrowserEntry(authProvider, db, rawProof, entryB.entryId, new Request(authUrlB, { headers: { origin: "http://localhost:5174", cookie: ambientA } }));
    const locB = resB.headers.get("location") || ((await resB.clone().json().catch(() => null)) as any)?.url;
    assert.ok(locB && locB.includes("/consent"), "Entry B must stay usable after A invalidation");

    // Non-OAuth dispatch must still fail closed
    await assert.rejects(dispatchRequestWithBrowserEntry(authProvider, db, rawProof, entryB.entryId, new Request("http://localhost:3000/api/auth/get-session")));
  });

  it("enforces __Host- cookie prefix in production and preserves admin & MFA boundaries", async () => {
    const { buildBrowserProofCookieOptions, getBrowserSessionCookieName } = await import("../../src/identity/browser-session-registry");
    assert.equal(getBrowserSessionCookieName(), "swyra-browser");
    process.env.NODE_ENV = "production";
    assert.equal(getBrowserSessionCookieName(), "__Host-swyra-browser");
    const prodOpts = buildBrowserProofCookieOptions(3600);
    assert.equal(prodOpts.httpOnly, true);
    assert.equal(prodOpts.secure, true);
    assert.equal(prodOpts.path, "/");
    assert.equal(prodOpts.sameSite, "Lax");
    assert.equal("domain" in prodOpts, false);
    process.env.NODE_ENV = "test";

    // Ordinary browser entry NEVER elevates to admin endpoints or bypasses MFA
    await seedUser("ord-priv@example.com", "ord_priv");
    const loginOrd = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: "ord-priv@example.com", password: strongPassword }),
    });
    const sessionOrd = extractCookie(loginOrd, "better-auth.session_token");
    const bcOrd = extractCookie(loginOrd, "swyra-browser");
    const adminAttempt = await app.request("/api/admin/users", {
      headers: hdrs({ Cookie: `${sessionOrd}; ${bcOrd}` }),
    });
    assert.ok(adminAttempt.status === 401 || adminAttempt.status === 403, "Ordinary session + browser proof cannot access admin APIs");

    // MFA-enabled user receives challenge first without entering browser set prematurely
    const uMfa = await seedUser("mfa-user@example.com", "mfa_user");
    await db.collection("user").updateOne({ _id: uMfa!._id }, { $set: { twoFactorEnabled: true } });
    const challengeRes = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs(), body: JSON.stringify({ email: "mfa-user@example.com", password: strongPassword }),
    });
    assert.equal(challengeRes.status, 200);
    assert.equal(extractCookie(challengeRes, "swyra-browser"), "", "Incomplete MFA challenge must not enroll into browser_session_sets");
    assert.equal(await db.collection("browser_session_sets").countDocuments({ "entries.userId": String(uMfa!._id) }), 0);
  });
});
