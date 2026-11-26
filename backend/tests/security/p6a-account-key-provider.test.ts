import assert from "node:assert/strict";
import crypto from "node:crypto";
import { describe, it } from "node:test";
import {
  AccountKeyAccessError,
  InMemoryAccountKeyProvider,
} from "../../src/identity/account-key-provider";

describe("P6a Account-Key Backend Proof (Disposable Local Adapter)", () => {
  it("enforces cross-account denial, outage fail-closed, monotonic denial over snapshot restore, and separate destruction states", async () => {
    const provider = new InMemoryAccountKeyProvider();
    const dekA = crypto.randomBytes(32);
    const dekB = crypto.randomBytes(32);

    const wrappedA = await provider.wrapDataKey("acct_A", dekA);
    const wrappedB = await provider.wrapDataKey("acct_B", dekB);
    assert.equal(wrappedA.state, "active");
    assert.equal(wrappedB.state, "active");

    // Snapshot of A's active metadata before denial
    const oldSnapshotA = { accountId: "acct_A", keyRef: wrappedA.keyRef, wrappedKey: wrappedA.wrappedKey };

    // 1. Cross-account unwrap denial
    await assert.rejects(
      () => provider.unwrapDataKey("acct_B", wrappedA.keyRef, wrappedA.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "cross_account_denied"
    );

    // 2. Provider outage fails closed
    provider.setOutage(true);
    await assert.rejects(
      () => provider.unwrapDataKey("acct_A", wrappedA.keyRef, wrappedA.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "provider_outage"
    );
    provider.setOutage(false);

    // 3. Temporary denial for A; B continues working; old snapshot for A cannot override denial
    const denyRes = await provider.denyAccess("acct_A", wrappedA.keyRef, "owner_revoked");
    assert.equal(denyRes.state, "denied");
    await assert.rejects(
      () => provider.unwrapDataKey(oldSnapshotA.accountId, oldSnapshotA.keyRef, oldSnapshotA.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_denied"
    );
    const unwrappedB = await provider.unwrapDataKey("acct_B", wrappedB.keyRef, wrappedB.wrappedKey);
    assert.deepEqual(unwrappedB, dekB);

    // 4. Scheduled destruction is distinct from denied and idempotent
    const sched1 = await provider.scheduleDestruction("acct_A", wrappedA.keyRef);
    assert.equal(sched1.state, "scheduled_destruction");
    assert.equal(sched1.idempotent, false);
    const sched2 = await provider.scheduleDestruction("acct_A", wrappedA.keyRef);
    assert.equal(sched2.state, "scheduled_destruction");
    assert.equal(sched2.idempotent, true);

    await assert.rejects(
      () => provider.unwrapDataKey("acct_A", wrappedA.keyRef, wrappedA.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_scheduled_destruction"
    );

    // 5. Completed destruction is distinct and idempotent
    provider.completeDestructionForTest("acct_A", wrappedA.keyRef);
    const sched3 = await provider.scheduleDestruction("acct_A", wrappedA.keyRef);
    assert.equal(sched3.state, "destroyed");
    assert.equal(sched3.idempotent, true);
    await assert.rejects(
      () => provider.unwrapDataKey("acct_A", wrappedA.keyRef, wrappedA.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_destroyed"
    );
  });
});
