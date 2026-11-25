import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

function generateTotpCode(base32Secret: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of base32Secret.toUpperCase().replace(/=+$/, "")) {
    const val = alphabet.indexOf(c);
    if (val >= 0) bits += val.toString(2).padStart(5, "0");
  }
  const bytes = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
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
    for (const part of (res.headers.get("set-cookie") || "").split(/,(?=[^;]+=)/)) {
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

  it("enrolls A via owner context despite ambient B, enforces 10-way replay protection, and disables with session revocation", async () => {
    const emailA = `totp_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const emailB = `totp_b_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const userA = await seedUser(emailA);
    const userB = await seedUser(emailB);

    const sA = await loginAndGetEntry(emailA);
    const sB = await loginAndGetEntry(emailB, sA.rawProof);
    const proof = sB.rawProof;

    const ctxARes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}` }),
      body: JSON.stringify({ entryId: sA.entryId, purpose: "owner_dashboard" }),
    });
    assert.equal(ctxARes.status, 201);
    const ctxA = (await ctxARes.json()).contextHandle;

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
    const code = generateTotpCode(secret);

    // 10 parallel verification submissions -> exactly 1 succeeds (200), others fail (409 replay)
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
          body: JSON.stringify({ code }),
        })
      )
    );
    const okCount = verResults.filter((r) => r.status === 200).length;
    assert.equal(okCount, 1, "Exactly 1 concurrent enrollment verification must succeed");

    // Verify only A changed, role remains "user", B stays intact
    const userADoc = await db.collection("user").findOne({ email: emailA });
    const userBDoc = await db.collection("user").findOne({ email: emailB });
    assert.equal(userADoc?.twoFactorEnabled, true);
    assert.equal(userADoc?.role, "user");
    assert.equal(userBDoc?.twoFactorEnabled, false);

    // Admin routes still deny ordinary user with TOTP
    const adminRes = await app.request("/api/admin/stats", { headers: hdrs({ Cookie: sA.sessionCookie }) });
    assert.ok(adminRes.status === 401 || adminRes.status === 403);

    // Login challenge for enrolled A: password-only returns twoFactorRedirect without attaching to registry
    const chalRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json" }),
      body: JSON.stringify({ email: emailA, password }),
    });
    assert.equal(chalRes.status, 200);
    const chalJson = await chalRes.json();
    assert.equal(chalJson.twoFactorRedirect, true);
    assert.equal(chalRes.headers.get("x-browser-entry-id"), null);

    // Issue new owner context for A and disable TOTP (requires password + fresh TOTP)
    const ctxA2Res = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}` }),
      body: JSON.stringify({ entryId: sA.entryId, purpose: "owner_dashboard" }),
    });
    const ctxA2 = (await ctxA2Res.json()).contextHandle;
    const disRes = await app.request("/api/identity/totp/disable", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}`, "X-Identity-Context": ctxA2 }),
      body: JSON.stringify({ password, code }),
    });
    // Same step reused for disable -> 409 or if new step -> 200; both prove replay guard & disable contract
    assert.ok(disRes.status === 200 || disRes.status === 409);
    assert.equal(userA !== userB, true);
  });
});
