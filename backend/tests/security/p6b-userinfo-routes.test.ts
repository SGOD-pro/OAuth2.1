import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import { InMemoryProfileCollection, writeProtectedProfile } from "../../src/identity/protected-profile-store";

process.env.NODE_ENV = process.env.NODE_ENV || "test";
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/local_di_unused";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);

const { createOAuthUserInfoHandler } = await import("../../src/routes/auth-userinfo");

function makeUserInfoDb(userDoc: any, scopeStr: string) {
  return {
    collection(name: string) {
      if (name === "user") {
        return { async findOne() { return userDoc; } };
      }
      if (name === "oauthAccessToken") {
        return {
          async findOne() {
            return { clientId: "client-1", scopes: scopeStr, createdAt: new Date(), tokenVersion: 1 };
          },
        };
      }
      return { async findOne() { return null; } };
    },
  };
}

describe("P6b UserInfo Protected Profile Integration (Local DI)", () => {
  it("returns protected email/name over stale legacy values and decrypts only authorized scope fields", async () => {
    const userId = new ObjectId().toHexString();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    await writeProtectedProfile({
      store,
      provider,
      accountId: userId,
      name: "Protected Alice",
      email: "protected.alice@example.com",
    });

    const unwrapCalls: string[] = [];
    const spyingProvider = {
      wrapDataKey: provider.wrapDataKey.bind(provider),
      denyAccess: provider.denyAccess.bind(provider),
      scheduleDestruction: provider.scheduleDestruction.bind(provider),
      getKeyState: provider.getKeyState.bind(provider),
      async unwrapDataKey(accountId: string, keyRef: string, wrappedKey: string) {
        unwrapCalls.push(keyRef);
        return provider.unwrapDataKey(accountId, keyRef, wrappedKey);
      },
    };

    const userDoc = {
      _id: new ObjectId(userId),
      id: userId,
      name: "Stale Plaintext Name",
      email: "stale@example.com",
      emailVerified: true,
      tokenVersion: 1,
      shareEmail: true,
      shareProfile: true,
    };

    // 1. scope = "openid profile" -> decrypts ONLY 1 field (name), omits email
    const makeApp = (scopeStr: string, opts?: { shareEmail?: boolean; shareProfile?: boolean; protectedOn?: boolean }) => {
      const app = new Hono();
      const doc = { ...userDoc, shareEmail: opts?.shareEmail ?? true, shareProfile: opts?.shareProfile ?? true };
      const handler = createOAuthUserInfoHandler({
        getDb: async () => makeUserInfoDb(doc, scopeStr),
        authHandler: async () =>
          new Response(
            JSON.stringify({ sub: userId, client_id: "client-1", name: "Stale Token Name", email: "stale.tok@example.com", email_verified: true }),
            { status: 200, headers: { "content-type": "application/json" } }
          ),
        resolveClient: async () => ({ clientId: "client-1", disabled: false, isAmbiguous: false }),
        checkPrivateAccess: async () => true,
        resolveRole: async () => ({ role: "user", scopedClientId: null }),
        ...(opts?.protectedOn === false ? {} : { protectedProfileStore: store, accountKeyProvider: spyingProvider, migrationMode: "strict" as const }),
      });
      app.get("/userinfo", handler);
      return app;
    };

    unwrapCalls.length = 0;
    const profileOnly = await makeApp("openid profile").request("/userinfo", { headers: { Authorization: "Bearer tok-1" } });
    assert.equal(profileOnly.status, 200);
    const pBody = await profileOnly.json();
    assert.equal(pBody.name, "Protected Alice");
    assert.equal(pBody.email, undefined);
    assert.equal(unwrapCalls.length, 1, "Must decrypt only the authorized profile field");

    // 2. scope = "openid" (or shareEmail=false & shareProfile=false) -> 0 decrypts
    unwrapCalls.length = 0;
    const openidOnly = await makeApp("openid").request("/userinfo", { headers: { Authorization: "Bearer tok-1" } });
    assert.equal(openidOnly.status, 200);
    const oBody = await openidOnly.json();
    assert.equal(oBody.name, undefined);
    assert.equal(oBody.email, undefined);
    assert.equal(unwrapCalls.length, 0, "Must not decrypt when neither email nor profile is authorized");

    // 3. scope = "openid profile email" with shareEmail=false -> decrypts ONLY name, email stays absent
    unwrapCalls.length = 0;
    const privacyBlocked = await makeApp("openid profile email", { shareEmail: false }).request("/userinfo", {
      headers: { Authorization: "Bearer tok-1" },
    });
    assert.equal(privacyBlocked.status, 200);
    const pbBody = await privacyBlocked.json();
    assert.equal(pbBody.name, "Protected Alice");
    assert.equal(pbBody.email, undefined);
    assert.equal(unwrapCalls.length, 1, "Privacy-suppressed email must not be decrypted");

    // 4. Feature off preserves legacy contract
    const featureOff = await makeApp("openid profile email", { protectedOn: false }).request("/userinfo", {
      headers: { Authorization: "Bearer tok-1" },
    });
    assert.equal(featureOff.status, 200);
    const foBody = await featureOff.json();
    assert.equal(foBody.name, "Stale Token Name");
    assert.equal(foBody.email, "stale.tok@example.com");
  });

  it("fails closed without plaintext fallback when protected read fails on UserInfo", async () => {
    const userId = new ObjectId().toHexString();
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const written = await writeProtectedProfile({
      store,
      provider,
      accountId: userId,
      name: "Protected Alice",
      email: "protected.alice@example.com",
    });
    await provider.denyAccess(userId, written.nameEnvelope.keyRef, "owner_revoked");

    const userDoc = {
      _id: new ObjectId(userId),
      id: userId,
      name: "Stale Plaintext Name",
      email: "stale@example.com",
      emailVerified: true,
      tokenVersion: 1,
    };

    const app = new Hono();
    app.get(
      "/userinfo",
      createOAuthUserInfoHandler({
        getDb: async () => makeUserInfoDb(userDoc, "openid profile email"),
        authHandler: async () =>
          new Response(JSON.stringify({ sub: userId, client_id: "client-1", name: "Stale Name", email: "stale@example.com" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        resolveClient: async () => ({ clientId: "client-1", disabled: false, isAmbiguous: false }),
        checkPrivateAccess: async () => true,
        resolveRole: async () => ({ role: "user", scopedClientId: null }),
        protectedProfileStore: store,
        accountKeyProvider: provider,
        migrationMode: "compat",
      })
    );

    const res = await app.request("/userinfo", { headers: { Authorization: "Bearer tok-1" } });
    assert.ok(res.status === 401 || res.status === 403, `Expected fail-closed 401/403, got ${res.status}`);
    const bodyText = JSON.stringify(await res.json());
    assert.equal(bodyText.includes("Stale Plaintext Name"), false);
    assert.equal(bodyText.includes("stale@example.com"), false);
  });
});
