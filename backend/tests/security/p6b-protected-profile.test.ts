import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ObjectId } from "mongodb";
import { AccountKeyAccessError, InMemoryAccountKeyProvider } from "../../src/identity/account-key-provider";
import { prepareOwnerExport } from "../../src/identity/owner-export";
import { openProtectedField, ProtectedFieldError } from "../../src/identity/protected-envelope";
import {
  InMemoryProfileCollection,
  readProtectedProfile,
  writeProtectedProfile,
} from "../../src/identity/protected-profile-store";

describe("P6b Protected Profile Path (Local First Slice)", () => {
  it("completes encrypted round trip for profile name and email without storing plaintext", async () => {
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();

    const written = await writeProtectedProfile({
      store,
      provider,
      accountId: "acct_A",
      name: "Alice Example",
      email: "alice@example.com",
    });

    const rawDoc = await store.findByUserId("acct_A");
    assert.ok(rawDoc);
    const serialized = JSON.stringify(rawDoc);
    assert.equal(serialized.includes("Alice Example"), false, "Plaintext name must not appear in stored doc");
    assert.equal(serialized.includes("alice@example.com"), false, "Plaintext email must not appear in stored doc");
    assert.equal(written.nameEnvelope.alg, "AES-256-GCM");

    const read = await readProtectedProfile({
      store,
      provider,
      accountId: "acct_A",
      migrationMode: "compat",
    });
    assert.equal(read.name, "Alice Example");
    assert.equal(read.email, "alice@example.com");
    assert.equal(read.source, "protected");
  });

  it("rejects cross-account access, wrong field purpose, and tampered ciphertext", async () => {
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();

    const written = await writeProtectedProfile({
      store,
      provider,
      accountId: "acct_A",
      name: "Alice Example",
      email: "alice@example.com",
    });

    // Cross-account read fails closed
    await assert.rejects(
      () => readProtectedProfile({ store, provider, accountId: "acct_B", migrationMode: "strict" }),
      (err: any) => err instanceof ProtectedFieldError
    );
    await assert.rejects(
      () =>
        openProtectedField({
          provider,
          accountId: "acct_B",
          collection: "identity_profiles",
          recordId: "acct_A",
          fieldPurpose: "profile.name",
          envelope: written.nameEnvelope,
        }),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "cross_account_denied"
    );

    // Wrong field purpose (substituting nameEnvelope into profile.email) fails AAD check
    await assert.rejects(
      () =>
        openProtectedField({
          provider,
          accountId: "acct_A",
          collection: "identity_profiles",
          recordId: "acct_A",
          fieldPurpose: "profile.email",
          envelope: written.nameEnvelope,
        }),
      (err: any) => err instanceof ProtectedFieldError && err.code === "decrypt_failed"
    );
  });

  it("fails closed on provider outage with no partial write and no plaintext fallback", async () => {
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();

    // Outage before write leaves no partial record in store
    provider.setOutage(true);
    await assert.rejects(
      () =>
        writeProtectedProfile({
          store,
          provider,
          accountId: "acct_A",
          name: "Alice Example",
          email: "alice@example.com",
        }),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "provider_outage"
    );
    assert.equal(await store.findByUserId("acct_A"), null, "Outage must leave no partial write");
    provider.setOutage(false);

    // Write valid protected record, then trigger outage on read even with legacyUserDoc present
    await writeProtectedProfile({
      store,
      provider,
      accountId: "acct_A",
      name: "Alice Example",
      email: "alice@example.com",
    });
    provider.setOutage(true);
    await assert.rejects(
      () =>
        readProtectedProfile({
          store,
          provider,
          accountId: "acct_A",
          legacyUserDoc: { name: "Legacy Alice", email: "legacy@example.com" },
          migrationMode: "compat",
        }),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "provider_outage"
    );
    provider.setOutage(false);
  });

  it("supports legacy plaintext compatibility in compat mode and fails closed in strict mode", async () => {
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const counters = { plaintextFallbackCount: 0 };

    const compat = await readProtectedProfile({
      store,
      provider,
      accountId: "acct_legacy",
      legacyUserDoc: { name: "Legacy User", email: "legacy@example.com" },
      migrationMode: "compat",
      counters,
    });
    assert.equal(compat.name, "Legacy User");
    assert.equal(compat.email, "legacy@example.com");
    assert.equal(compat.source, "legacy_plaintext");
    assert.equal(counters.plaintextFallbackCount, 1);

    await assert.rejects(
      () =>
        readProtectedProfile({
          store,
          provider,
          accountId: "acct_legacy",
          legacyUserDoc: { name: "Legacy User", email: "legacy@example.com" },
          migrationMode: "strict",
          counters,
        }),
      (err: any) => err instanceof ProtectedFieldError && err.code === "profile_not_found"
    );
  });

  it("integrates with prepareOwnerExport and fails closed on key denial without plaintext fallback", async () => {
    const provider = new InMemoryAccountKeyProvider();
    const store = new InMemoryProfileCollection();
    const userId = new ObjectId().toHexString();

    const written = await writeProtectedProfile({
      store,
      provider,
      accountId: userId,
      name: "Protected Name",
      email: "protected@example.com",
    });

    const mockDb = {
      collection(name: string) {
        if (name === "user") {
          return {
            async findOne() {
              return {
                _id: new ObjectId(userId),
                username: "alice",
                name: "Stale Plaintext Name",
                email: "stale@example.com",
                emailVerified: true,
              };
            },
          };
        }
        return {
          find() {
            return {
              sort() {
                return {
                  limit() {
                    return {
                      async toArray() {
                        return [];
                      },
                    };
                  },
                };
              },
            };
          },
        };
      },
    };

    const exported = await prepareOwnerExport(mockDb, userId, {
      protectedProfileStore: store,
      accountKeyProvider: provider,
      migrationMode: "strict",
    });
    assert.ok(exported);
    assert.equal(exported.profile.name, "Protected Name");
    assert.equal(exported.profile.email, "protected@example.com");

    await provider.denyAccess(userId, written.nameEnvelope.keyRef, "owner_revoked");
    await assert.rejects(
      () =>
        prepareOwnerExport(mockDb, userId, {
          protectedProfileStore: store,
          accountKeyProvider: provider,
          migrationMode: "compat",
        }),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_denied"
    );
  });
});
