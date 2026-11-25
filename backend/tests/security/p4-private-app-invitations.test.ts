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

describe("P4 Verified Private-App Invitations", () => {
  let suite: any;
  let db: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let app: any;
  let authProvider: any;
  let getLocalInviteMailSink: any;
  let clearLocalInviteMailSink: any;
  const gatewaySecret = "g".repeat(32);
  const password = "P4!Invite#Password99";

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

  async function seedUser(email: string, role: "user" | "admin" | "app-admin" = "user", opts: { scopedClientId?: string | null; emailVerified?: boolean } = {}) {
    const res = await authProvider.api.signUpEmail({ body: { email, password, name: email.split("@")[0] } });
    assert.ok(res.user?.id);
    await db.collection("user").updateOne(
      { email },
      { $set: { role, scopedClientId: opts.scopedClientId ?? null, emailVerified: opts.emailVerified ?? true, twoFactorEnabled: false } }
    );
    return res.user.id as string;
  }

  async function signInWithMfa(email: string) {
    const r = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json" }), body: JSON.stringify({ email, password }),
    });
    assert.equal(r.status, 200);
    const c1 = extractCookie(r, "better-auth.session_token");
    const enr = await app.request("/api/auth/two-factor/enable", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: c1 }), body: JSON.stringify({ password }),
    });
    const { totpURI } = await enr.json();
    const code = generateTotpCode(new URL(totpURI).searchParams.get("secret")!);
    const ver = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: c1 }), body: JSON.stringify({ code }),
    });
    return extractCookie(ver, "better-auth.session_token") || c1;
  }

  async function signIn(email: string) {
    const r = await app.request("/api/auth/sign-in/email", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json" }), body: JSON.stringify({ email, password }),
    });
    assert.equal(r.status, 200);
    return extractCookie(r, "better-auth.session_token");
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p4_invitations");
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
    const invMod = await import("../../src/identity/app-invitations");
    getLocalInviteMailSink = invMod.getLocalInviteMailSink;
    clearLocalInviteMailSink = invMod.clearLocalInviteMailSink;
    db = suite.client.db(suite.dbName);
    setTestDbOverride(db);
    await db.collection("oauthClient").insertMany([
      { id: "priv-a", clientId: "priv-a", name: "Private A", redirectUris: ["https://a.example.com/cb"], clientType: "confidential", accessPolicy: "private", isPublic: false },
      { id: "priv-b", clientId: "priv-b", name: "Private B", redirectUris: ["https://b.example.com/cb"], clientType: "confidential", accessPolicy: "private", isPublic: false },
    ]);
  });

  after(async () => {
    if (closeDb) await closeDb().catch(() => {});
    if (suite?.cleanup) await suite.cleanup().catch(() => {});
  });

  it("enforces inviter role ceilings, mailbox proof, single-use concurrent claim, and role separation", async () => {
    clearLocalInviteMailSink();
    const superEmail = `sup_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const appAdminEmail = `aa_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const targetEmail = `u_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const wrongEmail = `w_${crypto.randomBytes(4).toString("hex")}@example.com`;

    await seedUser(superEmail, "admin");
    await seedUser(appAdminEmail, "app-admin", { scopedClientId: "priv-a" });
    const targetUserId = await seedUser(targetEmail, "user", { emailVerified: false });
    await seedUser(wrongEmail, "user", { emailVerified: true });

    const superCookie = await signInWithMfa(superEmail);
    const appAdminCookie = await signInWithMfa(appAdminEmail);

    // Super-admin cannot issue admin/super-admin invites
    const badRole = await app.request("/api/admin/clients/priv-a/invitations", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: superCookie }),
      body: JSON.stringify({ email: targetEmail, roleCeiling: "admin" }),
    });
    assert.equal(badRole.status, 400);

    // App-admin cannot issue app-admin invites or invites for priv-b
    const aaEsc = await app.request("/api/admin/clients/priv-a/invitations", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: appAdminCookie }),
      body: JSON.stringify({ email: targetEmail, roleCeiling: "app-admin" }),
    });
    assert.equal(aaEsc.status, 403);
    const aaScope = await app.request("/api/admin/clients/priv-b/invitations", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: appAdminCookie }),
      body: JSON.stringify({ email: targetEmail, roleCeiling: "user" }),
    });
    assert.equal(aaScope.status, 403);

    // App-admin issues ordinary user invite for priv-a
    const issUser = await app.request("/api/admin/clients/priv-a/invitations", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: appAdminCookie }),
      body: JSON.stringify({ email: targetEmail, roleCeiling: "user" }),
    });
    assert.equal(issUser.status, 201);
    const mailUser = getLocalInviteMailSink().find((m: any) => m.to === targetEmail && m.roleCeiling === "user");
    assert.ok(mailUser?.rawToken);

    // Unverified mailbox and wrong mailbox cannot claim
    const unverifiedCookie = await signIn(targetEmail);
    const unvRes = await app.request("/api/identity/invitations/claim", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: unverifiedCookie }),
      body: JSON.stringify({ token: mailUser.rawToken }),
    });
    assert.equal(unvRes.status, 403);
    const wrongCookie = await signIn(wrongEmail);
    const wrongRes = await app.request("/api/identity/invitations/claim", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: wrongCookie }),
      body: JSON.stringify({ token: mailUser.rawToken }),
    });
    assert.equal(wrongRes.status, 403);

    // Verify mailbox, then concurrent claim: exactly 1 winner
    await db.collection("user").updateOne({ email: targetEmail }, { $set: { emailVerified: true } });
    const [c1, c2] = await Promise.all([
      app.request("/api/identity/invitations/claim", { method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: unverifiedCookie }), body: JSON.stringify({ token: mailUser.rawToken }) }),
      app.request("/api/identity/invitations/claim", { method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: unverifiedCookie }), body: JSON.stringify({ token: mailUser.rawToken }) }),
    ]);
    const statuses = [c1.status, c2.status].sort();
    assert.deepEqual(statuses, [200, 409]);

    const reg = await db.collection("user_app_registrations").findOne({ userId: targetUserId, clientId: "priv-a" });
    assert.ok(reg);
    const userAfterOrd = await db.collection("user").findOne({ email: targetEmail });
    assert.equal(userAfterOrd?.role, "user", "Ordinary invite must not elevate role");

    // Super-admin issues explicit app-admin invite for priv-b
    const issAA = await app.request("/api/admin/clients/priv-b/invitations", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: superCookie }),
      body: JSON.stringify({ email: targetEmail, roleCeiling: "app-admin" }),
    });
    assert.equal(issAA.status, 201);
    const mailAA = getLocalInviteMailSink().find((m: any) => m.clientId === "priv-b" && m.roleCeiling === "app-admin");
    const claimAA = await app.request("/api/identity/invitations/claim", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: unverifiedCookie }),
      body: JSON.stringify({ token: mailAA.rawToken }),
    });
    assert.equal(claimAA.status, 200);
    const userAfterAA = await db.collection("user").findOne({ email: targetEmail });
    assert.equal(userAfterAA?.role, "app-admin");
    assert.equal(userAfterAA?.scopedClientId, "priv-b");
  });

  it("rejects revoked and expired invitations", async () => {
    clearLocalInviteMailSink();
    const superEmail = `sup2_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const targetEmail = `u2_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await seedUser(superEmail, "admin");
    await seedUser(targetEmail, "user", { emailVerified: true });
    const superCookie = await signInWithMfa(superEmail);
    const userCookie = await signIn(targetEmail);

    const iss1 = await app.request("/api/admin/clients/priv-a/invitations", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: superCookie }),
      body: JSON.stringify({ email: targetEmail, roleCeiling: "user" }),
    });
    const { inviteId } = await iss1.json();
    const tok1 = getLocalInviteMailSink()[0].rawToken;

    const rev = await app.request(`/api/admin/clients/priv-a/invitations/${inviteId}`, {
      method: "DELETE", headers: hdrs({ Cookie: superCookie }),
    });
    assert.equal(rev.status, 200);
    const claimRev = await app.request("/api/identity/invitations/claim", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: userCookie }),
      body: JSON.stringify({ token: tok1 }),
    });
    assert.equal(claimRev.status, 409);

    // Expired invite
    await app.request("/api/admin/clients/priv-a/invitations", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: superCookie }),
      body: JSON.stringify({ email: targetEmail, roleCeiling: "user", ttlSeconds: -10 }),
    });
    const tok2 = getLocalInviteMailSink()[1].rawToken;
    const claimExp = await app.request("/api/identity/invitations/claim", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: userCookie }),
      body: JSON.stringify({ token: tok2 }),
    });
    assert.equal(claimExp.status, 409);
  });

  it("rolls back failed grant so invite stays retryable, preserves privileged roles, and requires TOTP for app-admin access", async () => {
    clearLocalInviteMailSink();
    const { claimPrivateAppInvitation } = await import("../../src/identity/app-invitations");
    const superEmail = `sup3_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const userEmail = `rb_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await seedUser(superEmail, "admin");
    const userId = await seedUser(userEmail, "user", { emailVerified: true });
    const superCookie = await signInWithMfa(superEmail);
    const userCookie = await signIn(userEmail);

    const iss = await app.request("/api/admin/clients/priv-b/invitations", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: superCookie }),
      body: JSON.stringify({ email: userEmail, roleCeiling: "app-admin" }),
    });
    assert.equal(iss.status, 201);
    const { inviteId } = await iss.json();
    const rawToken = getLocalInviteMailSink()[0].rawToken;

    // Simulate grant failure inside transaction -> invite must roll back to pending
    await assert.rejects(
      () => claimPrivateAppInvitation({
        database: db,
        rawToken,
        userId,
        userEmail,
        emailVerified: true,
        onBeforeGrantForTesting: () => { throw new Error("Simulated grant failure"); },
      }),
      /Simulated grant failure/
    );
    const afterFail = await db.collection("app_invitations").findOne({ inviteId });
    assert.equal(afterFail?.status, "pending", "Failed grant must roll back invite to pending");

    // Retry succeeds and grants app-admin, but admin access still requires completed TOTP
    const retryRes = await app.request("/api/identity/invitations/claim", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: userCookie }),
      body: JSON.stringify({ token: rawToken }),
    });
    assert.equal(retryRes.status, 200);
    const adminCheck = await app.request("/api/admin/clients/priv-b/users", { headers: hdrs({ Cookie: userCookie }) });
    assert.equal(adminCheck.status, 403);
    assert.equal((await adminCheck.json()).code, "ERR_MFA_ENROLLMENT_REQUIRED");

    // Existing platform super-admin claiming app-admin invite preserves role: "admin"
    const issSuper = await app.request("/api/admin/clients/priv-b/invitations", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: superCookie }),
      body: JSON.stringify({ email: superEmail, roleCeiling: "app-admin" }),
    });
    assert.equal(issSuper.status, 201);
    const superTok = getLocalInviteMailSink()[1].rawToken;
    const superClaim = await app.request("/api/identity/invitations/claim", {
      method: "POST", headers: hdrs({ "Content-Type": "application/json", Cookie: superCookie }),
      body: JSON.stringify({ token: superTok }),
    });
    assert.equal(superClaim.status, 200);
    const superDoc = await db.collection("user").findOne({ email: superEmail });
    assert.equal(superDoc?.role, "admin", "Existing platform admin role must be preserved");
  });
});
