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

describe("P4 Admin TOTP Enrollment, Setup-Only Authority & Step-Up", () => {
  let suite: any;
  let db: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let app: any;
  let authProvider: any;
  const gatewaySecret = "g".repeat(32);
  const password = "P4!Admin#Password99";

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

  async function seedAdmin(email: string, role: "admin" | "app-admin", scopedClientId: string | null = null) {
    const res = await authProvider.api.signUpEmail({ body: { email, password, name: role } });
    assert.ok(res.user?.id);
    await db.collection("user").updateOne(
      { email },
      { $set: { role, scopedClientId, emailVerified: true, twoFactorEnabled: false } }
    );
    return res.user.id as string;
  }

  async function signIn(email: string) {
    const res = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json" }),
      body: JSON.stringify({ email, password }),
    });
    assert.equal(res.status, 200);
    return extractCookie(res, "better-auth.session_token");
  }

  async function enrollAndVerifyTotp(cookie: string) {
    const enr = await app.request("/api/auth/two-factor/enable", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: cookie }),
      body: JSON.stringify({ password }),
    });
    assert.equal(enr.status, 200);
    const { totpURI } = await enr.json();
    const secret = new URL(totpURI).searchParams.get("secret")!;
    const code = generateTotpCode(secret);
    const ver = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: cookie }),
      body: JSON.stringify({ code }),
    });
    assert.equal(ver.status, 200);
    return extractCookie(ver, "better-auth.session_token") || cookie;
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p4_admin_mfa");
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
  });

  after(async () => {
    if (closeDb) await closeDb().catch(() => {});
    if (suite?.cleanup) await suite.cleanup().catch(() => {});
  });

  it("enforces setup-only authority, TOTP enrollment, and recent MFA step-up for platform admin", async () => {
    const email = `p4_super_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const userId = await seedAdmin(email, "admin");
    const setupCookie = await signIn(email);

    // Unenrolled admin has setup-only authority: /api/admin/me allowed, /api/admin/stats denied
    const meRes = await app.request("/api/admin/me", { headers: hdrs({ Cookie: setupCookie }) });
    assert.equal(meRes.status, 200);
    const statsBefore = await app.request("/api/admin/stats", { headers: hdrs({ Cookie: setupCookie }) });
    assert.equal(statsBefore.status, 403);
    assert.equal((await statsBefore.json()).code, "ERR_MFA_ENROLLMENT_REQUIRED");

    // Enroll and verify TOTP
    const mfaCookie = await enrollAndVerifyTotp(setupCookie);
    const statsAfter = await app.request("/api/admin/stats", { headers: hdrs({ Cookie: mfaCookie }) });
    assert.equal(statsAfter.status, 200);

    // Just inside 5-minute window (4m30s ago) succeeds on sensitive route
    const inside5m = new Date(Date.now() - (4 * 60 + 30) * 1000);
    await db.collection("session").updateMany({}, { $set: { mfaVerifiedAt: inside5m, createdAt: inside5m } });
    const okDelete = await app.request("/api/admin/clients/nonexistent-id", {
      method: "DELETE",
      headers: hdrs({ Cookie: mfaCookie }),
    });
    assert.notEqual(okDelete.status, 403);

    // Just outside 5-minute window (5m10s ago) fails step-up on sensitive admin routes
    const outside5m = new Date(Date.now() - (5 * 60 + 10) * 1000);
    await db.collection("session").updateMany({}, { $set: { mfaVerifiedAt: outside5m, createdAt: outside5m } });
    const staleDelete = await app.request("/api/admin/clients/nonexistent-id", {
      method: "DELETE",
      headers: hdrs({ Cookie: mfaCookie }),
    });
    assert.equal(staleDelete.status, 403);
    const staleBody = await staleDelete.json();
    assert.equal(staleBody.code, "ERR_MFA_STEP_UP_REQUIRED");
    assert.match(staleBody.message, /< 5 minutes/);
  });

  it("enforces setup-only authority, TOTP enrollment, and preserves app-admin assignment checks", async () => {
    const email = `p4_app_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await seedAdmin(email, "app-admin", "app-a");
    await db.collection("oauthClient").insertMany([
      { id: "app-a", clientId: "app-a", name: "App A", redirectUris: ["https://a.example.com/cb"], clientType: "public", accessPolicy: "open", isPublic: true },
      { id: "app-b", clientId: "app-b", name: "App B", redirectUris: ["https://b.example.com/cb"], clientType: "public", accessPolicy: "open", isPublic: true },
    ]);

    const setupCookie = await signIn(email);
    const deniedBefore = await app.request("/api/admin/clients/app-a/users", { headers: hdrs({ Cookie: setupCookie }) });
    assert.equal(deniedBefore.status, 403);
    assert.equal((await deniedBefore.json()).code, "ERR_MFA_ENROLLMENT_REQUIRED");

    const mfaCookie = await enrollAndVerifyTotp(setupCookie);
    const allowedA = await app.request("/api/admin/clients/app-a/users", { headers: hdrs({ Cookie: mfaCookie }) });
    assert.equal(allowedA.status, 200);

    // App-admin assignment boundary preserved for unassigned app-b
    const deniedB = await app.request("/api/admin/clients/app-b/users", { headers: hdrs({ Cookie: mfaCookie }) });
    assert.equal(deniedB.status, 403);

    // Just inside 5-minute window (4m30s ago) succeeds on sensitive app-admin mutation
    const inside5m = new Date(Date.now() - (4 * 60 + 30) * 1000);
    await db.collection("session").updateMany({}, { $set: { mfaVerifiedAt: inside5m, createdAt: inside5m } });
    const okAppDelete = await app.request("/api/admin/clients/app-a/users/nonexistent-user", {
      method: "DELETE",
      headers: hdrs({ Cookie: mfaCookie }),
    });
    assert.notEqual(okAppDelete.status, 403);

    // Just outside 5-minute window (5m10s ago) fails step-up for app-admin
    const outside5m = new Date(Date.now() - (5 * 60 + 10) * 1000);
    await db.collection("session").updateMany({}, { $set: { mfaVerifiedAt: outside5m, createdAt: outside5m } });
    const staleAppDelete = await app.request("/api/admin/clients/app-a/users/nonexistent-user", {
      method: "DELETE",
      headers: hdrs({ Cookie: mfaCookie }),
    });
    assert.equal(staleAppDelete.status, 403);
    const staleAppBody = await staleAppDelete.json();
    assert.equal(staleAppBody.code, "ERR_MFA_STEP_UP_REQUIRED");
    assert.match(staleAppBody.message, /< 5 minutes/);
  });
});
