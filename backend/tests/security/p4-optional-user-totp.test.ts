import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

function generateTotpForOffset(base32Secret: string, stepOffset = 0): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of base32Secret.toUpperCase().replace(/=+$/, "")) {
    const val = alphabet.indexOf(c);
    if (val >= 0) bits += val.toString(2).padStart(5, "0");
  }
  const bytes = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30) + stepOffset));
  const hmac = crypto.createHmac("sha1", bytes).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}

describe("P4 Optional User TOTP (AC-11)", () => {
  let suite: any;
  let db: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let app: any;
  let authProvider: any;
  let findActiveBrowserSet: any;
  const gatewaySecret = "g".repeat(32);
  const password = "P4!UserTotp#Password99";

  function hdrs(extra: Record<string, string> = {}) {
    return { "X-Gateway-Secret": gatewaySecret, "x-csrf-token": "test-csrf", Origin: "http://localhost:5174", ...extra };
  }

  function extractCookie(res: Response, name: string): string {
    const setCookies: string[] = typeof (res.headers as any).getSetCookie === "function"
      ? (res.headers as any).getSetCookie()
      : (res.headers.get("set-cookie") || "").split(/,(?=[^;]+=)/);
    for (const part of setCookies) {
      const kv = part.trim().split(";")[0];
      if (kv.startsWith(`${name}=`)) return kv;
    }
    return "";
  }

  async function seedUser(email: string) {
    const res = await authProvider.api.signUpEmail({ body: { email, password, name: email.split("@")[0] } });
    assert.ok(res.user?.id);
    await db.collection("user").updateOne({ email }, { $set: { role: "user", emailVerified: true, twoFactorEnabled: false } });
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
    return { entryId, rawProof, sessionCookie, setId: setDoc?.setId as string };
  }

  async function issueContext(proof: string, entryId: string): Promise<string> {
    const res = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}` }),
      body: JSON.stringify({ entryId, purpose: "owner_dashboard" }),
    });
    assert.equal(res.status, 201);
    return (await res.json()).contextHandle;
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p4_optional_user_totp");
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
    db = suite.client.db(suite.dbName);
    setTestDbOverride(db);
  });

  after(async () => {
    if (closeDb) await closeDb().catch(() => {});
    if (suite?.cleanup) await suite.cleanup().catch(() => {});
  });

  it("enforces context isolation, pending/enrolled guards, 10-way replay, login 2FA attachment, and full disable revocation", async () => {
    const emailA = `totp_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const emailB = `totp_b_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const userA = await seedUser(emailA);
    const userB = await seedUser(emailB);

    const sAPre = await loginAndGetEntry(emailA);
    const sA = await loginAndGetEntry(emailA, sAPre.rawProof);
    const sB = await loginAndGetEntry(emailB, sA.rawProof);
    const proof = sB.rawProof;
    const ctxA = await issueContext(proof, sA.entryId);

    // Enable TOTP for A while B is ambient Better Auth session
    const enrRes = await app.request("/api/identity/totp/enable", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}; ${sB.sessionCookie}`, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ password }),
    });
    assert.equal(enrRes.status, 200);
    const { totpURI, backupCodes } = await enrRes.json();
    assert.ok(totpURI && Array.isArray(backupCodes) && backupCodes.length > 0);
    const secret = new URL(totpURI).searchParams.get("secret")!;

    // Calling disable while enrollment is pending must fail with 400 and leave TOTP disabled
    const pendDisRes = await app.request("/api/identity/totp/disable", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}`, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ password, code: generateTotpForOffset(secret, -1) }),
    });
    assert.equal(pendDisRes.status, 400);
    assert.equal((await db.collection("user").findOne({ email: emailA }))?.twoFactorEnabled, false);

    // Invalid TOTP guess must not pre-lock the valid code
    const badVerRes = await app.request("/api/identity/totp/verify", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}`, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ code: "000000" }),
    });
    assert.equal(badVerRes.status, 401);

    // 10 parallel verification submissions for step -1 -> exactly 1 succeeds (200), 9 fail with 409
    const enrollCode = generateTotpForOffset(secret, -1);
    const verResults = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        app.request("/api/identity/totp/verify", {
          method: "POST",
          headers: hdrs({
            "Content-Type": "application/json",
            "x-forwarded-for": `198.51.100.${50 + i}, 10.0.0.1`,
            Cookie: `swyra-browser=${proof}; ${sB.sessionCookie}`,
            "X-Identity-Context": ctxA,
          }),
          body: JSON.stringify({ code: enrollCode }),
        })
      )
    );
    assert.equal(verResults.filter((r) => r.status === 200).length, 1);
    assert.equal(verResults.filter((r) => r.status === 409).length, 9);

    // Re-calling enable when already enrolled must return 409 and preserve secret
    const ctxAAfterEnroll = await issueContext(proof, sA.entryId);
    const reEnrRes = await app.request("/api/identity/totp/enable", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}`, "X-Identity-Context": ctxAAfterEnroll }),
      body: JSON.stringify({ password }),
    });
    assert.equal(reEnrRes.status, 409);

    // Verify only A changed, role remains "user", B stays intact, and pre-enrollment session was revoked
    const userADoc = await db.collection("user").findOne({ email: emailA });
    const userBDoc = await db.collection("user").findOne({ email: emailB });
    assert.equal(userADoc?.twoFactorEnabled, true);
    assert.equal(userADoc?.role, "user");
    assert.equal(userBDoc?.twoFactorEnabled, false);
    const preSessExists = await db.collection("session").findOne({ token: decodeURIComponent(sAPre.sessionCookie.split("=")[1]).split(".")[0] });
    assert.equal(preSessExists, null);

    // Admin routes still deny ordinary user with TOTP
    const adminRes = await app.request("/api/admin/stats", { headers: hdrs({ Cookie: sA.sessionCookie }) });
    assert.ok(adminRes.status === 401 || adminRes.status === 403);

    // Login challenge for enrolled A: password-only returns twoFactorRedirect without attaching to registry
    const chalRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}` }),
      body: JSON.stringify({ email: emailA, password }),
    });
    assert.equal(chalRes.status, 200);
    const chalJson = await chalRes.json();
    assert.equal(chalJson.twoFactorRedirect, true);
    assert.equal(chalRes.headers.get("x-browser-entry-id"), null);
    const twoFactorCookie = extractCookie(chalRes, "better-auth.two_factor");
    assert.ok(twoFactorCookie, "two_factor challenge cookie must be set");

    // Replaying enrollCode (step -1) on login verify-totp must be rejected (409)
    const replayLoginRes = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}; ${sB.sessionCookie}; ${twoFactorCookie}` }),
      body: JSON.stringify({ code: enrollCode }),
    });
    assert.equal(replayLoginRes.status, 409);

    // Completing login 2FA with step 0 even while B's session_token is ambient must complete A and attach to registry
    const loginCode = generateTotpForOffset(secret, 0);
    const compLoginRes = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}; ${sB.sessionCookie}; ${twoFactorCookie}` }),
      body: JSON.stringify({ code: loginCode }),
    });
    assert.equal(compLoginRes.status, 200);
    const completedEntryId = compLoginRes.headers.get("x-browser-entry-id");
    assert.ok(completedEntryId, "completed login 2FA must attach ordinary user to browser_session_sets");
    const rotatedBc = extractCookie(compLoginRes, "swyra-browser");
    const activeProof = rotatedBc ? rotatedBc.split("=")[1] : proof;

    // Seed ObjectId-keyed oauthRefreshToken, oauthAccessToken, and oauth_token_families for A
    const oidA = ObjectId.isValid(userA) && userA.length === 24 ? new ObjectId(userA) : userA;
    await db.collection("oauthRefreshToken").insertOne({ userId: oidA, token: "rt_test_a", clientId: "c1" });
    await db.collection("oauthAccessToken").insertOne({ userId: oidA, token: "at_test_a", clientId: "c1" });
    await db.collection("oauth_token_families").insertOne({ familyId: "fam_a", userId: oidA, clientId: "c1", status: "active" });

    // Wrong password on disable returns 401 and does not consume step +1
    const ctxA2 = await issueContext(activeProof, completedEntryId!);
    const disableCode = generateTotpForOffset(secret, 1);
    const wrongPassDis = await app.request("/api/identity/totp/disable", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${activeProof}`, "X-Identity-Context": ctxA2 }),
      body: JSON.stringify({ password: "WrongPassword!99", code: disableCode }),
    });
    assert.equal(wrongPassDis.status, 401);

    // Replaying loginCode (step 0) on disable must be rejected with 409
    const replayDis = await app.request("/api/identity/totp/disable", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${activeProof}`, "X-Identity-Context": ctxA2 }),
      body: JSON.stringify({ password, code: loginCode }),
    });
    assert.equal(replayDis.status, 409);

    // Valid password + fresh step +1 disables TOTP, preserves current rotated session, revokes other A sessions & OAuth tokens/families
    const disRes = await app.request("/api/identity/totp/disable", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${activeProof}`, "X-Identity-Context": ctxA2 }),
      body: JSON.stringify({ password, code: disableCode }),
    });
    assert.equal(disRes.status, 200);
    assert.equal((await db.collection("user").findOne({ email: emailA }))?.twoFactorEnabled, false);
    assert.equal(await db.collection("oauthRefreshToken").countDocuments({ userId: oidA }), 0);
    assert.equal(await db.collection("oauthAccessToken").countDocuments({ userId: oidA }), 0);
    assert.equal((await db.collection("oauth_token_families").findOne({ familyId: "fam_a" }))?.status, "revoked");

    // Current session in browser_session_sets survived disable and can mint a fresh context!
    const ctxA3 = await issueContext(activeProof, completedEntryId!);
    const meRes = await app.request("/api/identity/contexts/me", {
      headers: hdrs({ Cookie: `swyra-browser=${activeProof}`, "X-Identity-Context": ctxA3 }),
    });
    assert.equal(meRes.status, 200);
    const meJson = await meRes.json();
    assert.equal(meJson.userId, userA);
    assert.equal(meJson.totpEnabled, false);

    // Account B's session and context remain completely intact
    const ctxB = await issueContext(activeProof, sB.entryId);
    const meBRes = await app.request("/api/identity/contexts/me", {
      headers: hdrs({ Cookie: `swyra-browser=${activeProof}`, "X-Identity-Context": ctxB }),
    });
    assert.equal(meBRes.status, 200);
  });

  it("denies promoted app-admins from mutating TOTP via ordinary owner routes", async () => {
    const emailAdmin = `totp_promoted_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await seedUser(emailAdmin);
    const sAdmin = await loginAndGetEntry(emailAdmin);
    await db.collection("user").updateOne({ email: emailAdmin }, { $set: { role: "app-admin" } });
    const ctx = await issueContext(sAdmin.rawProof, sAdmin.entryId);
    const res = await app.request("/api/identity/totp/enable", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${sAdmin.rawProof}`, "X-Identity-Context": ctx }),
      body: JSON.stringify({ password }),
    });
    assert.equal(res.status, 403);
  });
});
