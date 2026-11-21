import assert from "node:assert/strict";
import { p0Fixture } from "../fixtures/p0-engine";

const fixture = await p0Fixture();
const { db, proof, complete } = fixture;
let passed = 0;
async function check(name: string, work: () => Promise<void>) {
  await work();
  passed++;
  console.log(`[PASS] ${name}`);
}
try {
  for (const at of ["user", "credential"] as const) {
    await check(`${at} failure rolls back proof, identity and credentials`, async () => {
      await proof(at, `${at}@example.test`);
      fixture.fail(at);
      await assert.rejects(complete(at, at), /injected/);
      fixture.fail(null);
      assert.equal(await db.collection("user").countDocuments(), 0);
      assert.equal(await db.collection("account").countDocuments(), 0);
      assert.equal(await db.collection("session").countDocuments(), 0);
      assert.equal(await db.collection("p0Proof").countDocuments({ digest: at }), 1);
    });
  }
  await check("credential storage rejection rolls back identity and proof", async () => {
    await proof("storage", "storage@example.test");
    await db.command({ collMod: "account", validator: {
      $jsonSchema: { required: ["p0NeverPresent"] },
    } });
    try {
      await assert.rejects(complete("storage", "storage"), error =>
        (error as { code?: number }).code === 121);
    } finally {
      await db.command({ collMod: "account", validator: {} });
    }
    assert.equal(await db.collection("user").countDocuments(), 0);
    assert.equal(await db.collection("account").countDocuments(), 0);
    assert.equal(await db.collection("p0Proof").countDocuments({ digest: "storage" }), 1);
  });
  await check("nested transaction context is rejected", async () => {
    await assert.rejects(fixture.boundary.run(fixture.engine, async () =>
      fixture.boundary.run(fixture.engine, async () => null)), /Nested/);
  });
  await check("expired or absent proof creates no identity", async () => {
    await proof("expired", "expired@example.test", true);
    await assert.rejects(complete("expired", "expired"), /Proof unavailable/);
    await assert.rejects(complete("missing", "missing"), /Proof unavailable/);
    assert.equal(await db.collection("user").countDocuments(), 0);
  });
  await check("concurrent proof consumption has one committed winner; replay denied", async () => {
    await proof("race", "race@example.test");
    const results = await Promise.allSettled([complete("race", "race_a"), complete("race", "race_b")]);
    assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
    assert.equal(await db.collection("user").countDocuments(), 1);
    assert.equal(await db.collection("account").countDocuments(), 1);
    assert.equal(await db.collection("p0Proof").countDocuments({ digest: "race" }), 0);
    await assert.rejects(complete("race", "replayed"), /Proof unavailable/);
  });
  for (const kind of ["email", "username"] as const) {
    await check(`concurrent unique ${kind} collision leaves no partial identity or consumed losing proof`, async () => {
      const baseline = await db.collection("user").countDocuments();
      await proof(`${kind}_a`, `${kind}_a@example.test`);
      await proof(`${kind}_b`, kind === "email" ? `${kind}_a@example.test` : `${kind}_b@example.test`);
      const results = await Promise.allSettled([
        complete(`${kind}_a`, `${kind}_a`),
        complete(`${kind}_b`, kind === "username" ? `${kind}_a` : `${kind}_b`),
      ]);
      assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
      assert.equal(await db.collection("user").countDocuments(), baseline + 1);
      assert.equal(await db.collection("account").countDocuments(), baseline + 1);
      assert.equal(await db.collection("p0Proof").countDocuments({ digest: { $in: [`${kind}_a`, `${kind}_b`] } }), 1);
    });
  }
  await check("transaction boundary rejects the ambient production engine", async () => {
    const { authProvider } = await import("../../src/utils/auth");
    await assert.rejects(fixture.boundary.run(authProvider, async () => null), /transaction-enabled/);
  });
  await check("real engine verifies committed credential", async () => {
    const user = await db.collection("user").findOne({ email: "race@example.test" });
    const login = await fixture.engine.api.signInEmail({ body: {
      email: user!.email, password: "P0-Disposable-Password!123",
    } });
    assert.equal(login.user.id, user!._id.toString());
  });
  console.log(`P0 transactions: ${passed} passed, 0 failed, 0 skipped (one process, real Mongo replica set)`);
} finally {
  await fixture.close();
}
