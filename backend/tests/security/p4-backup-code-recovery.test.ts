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

describe("P4 Backup-Code Recovery & Role Restoration", () => {
  let suite: any;
  let db: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let app: any;
  let authProvider: any;
  const gatewaySecret = "g".repeat(32);
  const password = "P4!Recovery#Password99";

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

  async function seedEnrolledAdmin(email: string, role: "admin" | "app-admin", scopedClientId: string | null = null) {
    const res = await authProvider.api.signUpEmail({ body: { email, password, name: role } });
    assert.ok(res.user?.id);
    await db.collection("user").updateOne({ email }, { $set: { role, scopedClientId, emailVerified: true } });

    const r = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json" }), body: JSON.stringify({ email, password }),
    });
    const c1 = extractCookie(r, "better-auth.session_token");
    const enr = await app.request("/api/auth/two-factor/enable", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: c1 }), body: JSON.stringify({ password }),
    });
    const { totpURI, backupCodes } = await enr.json();
    const code = generateTotpCode(new URL(totpURI).searchParams.get("secret")!);
    const ver = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: c1 }), body: JSON.stringify({ code }),
    });
    const mfaCookie = extractCookie(ver, "better-auth.session_token") || c1;
    return { mfaCookie, backupCodes: backupCodes as string[] };
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p4_backup_recovery");
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
    db = suite.client.db(suite.dbName);
    setTestDbOverride(db);
    await db.collection("oauthClient").insertMany([
      { id: "rec-a", clientId: "rec-a", name: "Rec A", redirectUris: ["https://a.example.com/cb"], clientType: "public", accessPolicy: "open", isPublic: true },
      { id: "rec-b", clientId: "rec-b", name: "Rec B", redirectUris: ["https://b.example.com/cb"], clientType: "public", accessPolicy: "open", isPublic: true },
    ]);
  });

  after(async () => {
    if (closeDb) await closeDb().catch(() => {});
    if (suite?.cleanup) await suite.cleanup().catch(() => {});
  });

  it("consumes backup code once, invalidates old elevated sessions, enforces setup-only, and restores exact role and scope", async () => {
    const email = `rec_aa_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const { mfaCookie: oldCookie, backupCodes } = await seedEnrolledAdmin(email, "app-admin", "rec-a");
    assert.ok(backupCodes.length > 0);

    // Concurrent recovery submissions with the same backup code: at most 1 succeeds
    const [r1, r2] = await Promise.all([
      app.request("/api/identity/recovery/backup-code", {
        method: "POST", headers: hdrs({ "Content-Type": "application/json" }),
        body: JSON.stringify({ email, password, backupCode: backupCodes[0] }),
      }),
      app.request("/api/identity/recovery/backup-code", {
        method: "POST", headers: hdrs({ "Content-Type": "application/json" }),
        body: JSON.stringify({ email, password, backupCode: backupCodes[0] }),
      }),
    ]);
    const winner = r1.status === 200 ? r1 : r2;
    const loser = r1.status === 200 ? r2 : r1;
    assert.equal(winner.status, 200);
    assert.equal(loser.status, 401);
    const recoveryCookie = extractCookie(winner, "better-auth.session_token");

    // Old elevated session is invalidated
    const oldRes = await app.request("/api/admin/clients/rec-a/users", { headers: hdrs({ Cookie: oldCookie }) });
    assert.equal(oldRes.status, 401);

    // Recovery session has setup-only authority (cannot perform privileged actions)
    const privRes = await app.request("/api/admin/clients/rec-a/users", { headers: hdrs({ Cookie: recoveryCookie }) });
    assert.equal(privRes.status, 403);
    assert.equal((await privRes.json()).code, "ERR_MFA_ENROLLMENT_REQUIRED");

    // Fresh TOTP enrollment and verification restores app-admin for rec-a, preserving scope (rec-b denied)
    const enr2 = await app.request("/api/auth/two-factor/enable", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: recoveryCookie }), body: JSON.stringify({ password }),
    });
    assert.equal(enr2.status, 200);
    const { totpURI } = await enr2.json();
    const ver2 = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: recoveryCookie }),
      body: JSON.stringify({ code: generateTotpCode(new URL(totpURI).searchParams.get("secret")!) }),
    });
    assert.equal(ver2.status, 200);
    const restoredCookie = extractCookie(ver2, "better-auth.session_token") || recoveryCookie;

    const okA = await app.request("/api/admin/clients/rec-a/users", { headers: hdrs({ Cookie: restoredCookie }) });
    assert.equal(okA.status, 200);
    const deniedB = await app.request("/api/admin/clients/rec-b/users", { headers: hdrs({ Cookie: restoredCookie }) });
    assert.equal(deniedB.status, 403);
  });

  it("rate-limits excessive backup-code recovery attempts", async () => {
    const email = `rec_rl_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await seedEnrolledAdmin(email, "admin");
    let lastStatus = 0;
    for (let i = 0; i < 6; i++) {
      const r = await app.request("/api/identity/recovery/backup-code", {
        method: "POST", headers: hdrs({ "Content-Type": "application/json" }),
        body: JSON.stringify({ email, password, backupCode: "INVALID-CODE" }),
      });
      lastStatus = r.status;
    }
    assert.equal(lastStatus, 429);
  });

  it("preserves backup code on failed commit and restores platform admin after fresh TOTP", async () => {
    const { setRecoveryCommitHookForTesting } = await import("../../src/routes/identity-recovery");
    const email = `rec_sup_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const { backupCodes } = await seedEnrolledAdmin(email, "admin");

    // Simulate commit failure inside transaction -> backup code must be preserved
    setRecoveryCommitHookForTesting(() => { throw new Error("Simulated commit failure"); });
    try {
      const failRes = await app.request("/api/identity/recovery/backup-code", {
        method: "POST", headers: hdrs({ "Content-Type": "application/json", "x-forwarded-for": "198.51.100.77, 10.0.0.1" }),
        body: JSON.stringify({ email, password, backupCode: backupCodes[0] }),
      });
      assert.equal(failRes.status, 500);
    } finally {
      setRecoveryCommitHookForTesting(null);
    }

    // Retry with the same backup code succeeds
    const okRes = await app.request("/api/identity/recovery/backup-code", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", "x-forwarded-for": "198.51.100.77, 10.0.0.1" }),
      body: JSON.stringify({ email, password, backupCode: backupCodes[0] }),
    });
    assert.equal(okRes.status, 200);
    const recoveryCookie = extractCookie(okRes, "better-auth.session_token");

    // Setup-only until fresh TOTP
    const statsBefore = await app.request("/api/admin/stats", { headers: hdrs({ Cookie: recoveryCookie }) });
    assert.equal(statsBefore.status, 403);

    const enr = await app.request("/api/auth/two-factor/enable", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: recoveryCookie }), body: JSON.stringify({ password }),
    });
    const { totpURI } = await enr.json();
    const ver = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: recoveryCookie }),
      body: JSON.stringify({ code: generateTotpCode(new URL(totpURI).searchParams.get("secret")!) }),
    });
    assert.equal(ver.status, 200);
    const restoredCookie = extractCookie(ver, "better-auth.session_token") || recoveryCookie;
    const statsAfter = await app.request("/api/admin/stats", { headers: hdrs({ Cookie: restoredCookie }) });
    assert.equal(statsAfter.status, 200);
  });
});
