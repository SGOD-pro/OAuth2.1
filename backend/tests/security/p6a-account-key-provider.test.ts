import assert from "node:assert/strict";
import crypto from "node:crypto";
import { describe, it } from "node:test";
import {
  AccountKeyAccessError,
  InMemoryAccountKeyProvider,
} from "../../src/identity/account-key-provider";

describe("P6a Account-Key Backend Proof (Disposable Local Adapter)", () => {
  it("enforces per-reference scope, monotonic state transitions, same-process snapshot denial, and separate destruction states", async () => {
    const provider = new InMemoryAccountKeyProvider();
    const dekA1 = crypto.randomBytes(32);
    const dekA2 = crypto.randomBytes(32);
    const dekB = crypto.randomBytes(32);

    const wrappedA1 = await provider.wrapDataKey("acct_A", dekA1);
    const wrappedA2 = await provider.wrapDataKey("acct_A", dekA2);
    const wrappedB = await provider.wrapDataKey("acct_B", dekB);
    assert.equal(wrappedA1.state, "active");
    assert.equal(wrappedA2.state, "active");
    assert.equal(wrappedB.state, "active");

    const stateA1Init = await provider.getKeyState("acct_A", wrappedA1.keyRef);
    const stateA2Init = await provider.getKeyState("acct_A", wrappedA2.keyRef);
    assert.ok(stateA2Init.monotonicSeq > stateA1Init.monotonicSeq);

    // Same-process stale-metadata snapshot of A1 before denial
    // (restart and independent restore-ledger proof remain open)
    const oldSnapshotA1 = {
      accountId: "acct_A",
      keyRef: wrappedA1.keyRef,
      wrappedKey: wrappedA1.wrappedKey,
    };

    // 1. Cross-account unwrap denial
    await assert.rejects(
      () => provider.unwrapDataKey("acct_B", wrappedA1.keyRef, wrappedA1.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "cross_account_denied"
    );

    // 2. Provider outage fails closed
    provider.setOutage(true);
    await assert.rejects(
      () => provider.unwrapDataKey("acct_A", wrappedA1.keyRef, wrappedA1.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "provider_outage"
    );
    provider.setOutage(false);

    // 3. Per-reference denial on A1: A1 is denied (including same-process stale snapshot),
    // while A2 and B remain active until explicitly denied (P6b must iterate all historical refs).
    const denyRes = await provider.denyAccess("acct_A", wrappedA1.keyRef, "owner_revoked");
    assert.equal(denyRes.state, "denied");
    assert.ok(denyRes.monotonicSeq > stateA2Init.monotonicSeq);

    await assert.rejects(
      () => provider.unwrapDataKey(oldSnapshotA1.accountId, oldSnapshotA1.keyRef, oldSnapshotA1.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_denied"
    );
    assert.deepEqual(
      await provider.unwrapDataKey("acct_A", wrappedA2.keyRef, wrappedA2.wrappedKey),
      dekA2
    );
    assert.deepEqual(
      await provider.unwrapDataKey("acct_B", wrappedB.keyRef, wrappedB.wrappedKey),
      dekB
    );

    // 4. Scheduled destruction is distinct from denied, advances monotonicSeq, and is idempotent
    const sched1 = await provider.scheduleDestruction("acct_A", wrappedA1.keyRef);
    assert.equal(sched1.state, "scheduled_destruction");
    assert.equal(sched1.idempotent, false);
    const stateAfterSched1 = await provider.getKeyState("acct_A", wrappedA1.keyRef);
    assert.ok(stateAfterSched1.monotonicSeq > denyRes.monotonicSeq);

    const sched2 = await provider.scheduleDestruction("acct_A", wrappedA1.keyRef);
    assert.equal(sched2.state, "scheduled_destruction");
    assert.equal(sched2.idempotent, true);
    const stateAfterSched2 = await provider.getKeyState("acct_A", wrappedA1.keyRef);
    assert.equal(stateAfterSched2.monotonicSeq, stateAfterSched1.monotonicSeq);

    await assert.rejects(
      () => provider.unwrapDataKey("acct_A", wrappedA1.keyRef, wrappedA1.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_scheduled_destruction"
    );

    // 5. Completed destruction is distinct, advances monotonicSeq, and is idempotent
    provider.completeDestructionForTest("acct_A", wrappedA1.keyRef);
    const stateAfterDestroy = await provider.getKeyState("acct_A", wrappedA1.keyRef);
    assert.equal(stateAfterDestroy.state, "destroyed");
    assert.ok(stateAfterDestroy.monotonicSeq > stateAfterSched2.monotonicSeq);

    const sched3 = await provider.scheduleDestruction("acct_A", wrappedA1.keyRef);
    assert.equal(sched3.state, "destroyed");
    assert.equal(sched3.idempotent, true);
    await assert.rejects(
      () => provider.unwrapDataKey("acct_A", wrappedA1.keyRef, wrappedA1.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_destroyed"
    );
  });
});
