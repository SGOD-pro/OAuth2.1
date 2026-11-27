import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { AccountKeyAccessError } from "../../src/identity/account-key-provider";
import { AwsKmsAccountKeyProvider, type AwsKmsClient } from "../../src/identity/aws-kms-account-key-provider";
import {
  runP6aSandboxStart,
  runP6aSandboxResume,
  type P6aAwsClients,
} from "../../src/identity/p6a-sandbox-runner";

interface MockKmsKey {
  keyId: string;
  arn: string;
  state: "Enabled" | "Disabled" | "PendingDeletion";
  tags: Record<string, string>;
}

function createMockAwsEnv(opts?: {
  accountId?: string;
  callerArn?: string;
  failOnAction?: string;
}) {
  const accountId = opts?.accountId ?? "111122223333";
  const callerArn = opts?.callerArn ?? `arn:aws:sts::${accountId}:assumed-role/swyra-p6a-sandbox-role/session1`;
  const keys = new Map<string, MockKmsKey>();
  const aliases = new Map<string, string>();
  const cloudTrailEvents: Array<{ EventId: string; EventName: string; KeyArn: string }> = [];
  let keyCounter = 0;
  let eventCounter = 0;

  const findKey = (keyIdOrArn: string): MockKmsKey | undefined => {
    for (const k of keys.values()) {
      if (k.keyId === keyIdOrArn || k.arn === keyIdOrArn) return k;
    }
    return undefined;
  };

  const makeErr = (name: string, message: string) => {
    const err = new Error(message) as Error & { name: string };
    err.name = name;
    return err;
  };

  const maybeFail = (action: string) => {
    if (opts?.failOnAction === action) {
      throw makeErr("AccessDeniedException", `Denied ${action}`);
    }
  };

  const kms: AwsKmsClient & {
    createKey: (input: { Tags?: Array<{ TagKey: string; TagValue: string }>; MultiRegion?: boolean }) => Promise<{ KeyMetadata: { KeyId: string; Arn: string } }>;
    createAlias: (input: { AliasName: string; TargetKeyId: string }) => Promise<void>;
    deleteAlias: (input: { AliasName: string }) => Promise<void>;
    listAliases: () => Promise<{ Aliases: Array<{ AliasName: string; TargetKeyId?: string }> }>;
    listResourceTags: (input: { KeyId: string }) => Promise<{ Tags: Array<{ TagKey: string; TagValue: string }> }>;
  } = {
    async createKey(input) {
      maybeFail("CreateKey");
      keyCounter += 1;
      const keyId = `00000000-0000-0000-0000-00000000000${keyCounter}`;
      const arn = `arn:aws:kms:us-east-1:${accountId}:key/${keyId}`;
      const tags: Record<string, string> = {};
      for (const t of input.Tags ?? []) tags[t.TagKey] = t.TagValue;
      keys.set(keyId, { keyId, arn, state: "Enabled", tags });
      return { KeyMetadata: { KeyId: keyId, Arn: arn } };
    },
    async createAlias(input) {
      maybeFail("CreateAlias");
      if (aliases.has(input.AliasName)) {
        throw makeErr("AlreadyExistsException", `Alias ${input.AliasName} already exists`);
      }
      const k = findKey(input.TargetKeyId);
      if (!k) throw makeErr("NotFoundException", "Target key not found");
      aliases.set(input.AliasName, k.keyId);
    },
    async deleteAlias(input) {
      maybeFail("DeleteAlias");
      if (!aliases.delete(input.AliasName)) {
        throw makeErr("NotFoundException", `Alias ${input.AliasName} not found`);
      }
    },
    async listAliases() {
      maybeFail("ListAliases");
      return {
        Aliases: Array.from(aliases.entries()).map(([AliasName, TargetKeyId]) => ({
          AliasName,
          TargetKeyId,
        })),
      };
    },
    async listResourceTags(input) {
      maybeFail("ListResourceTags");
      const k = findKey(input.KeyId);
      if (!k) throw makeErr("NotFoundException", "Key not found");
      return {
        Tags: Object.entries(k.tags).map(([TagKey, TagValue]) => ({ TagKey, TagValue })),
      };
    },
    async describeKey(input) {
      maybeFail("DescribeKey");
      const k = findKey(input.KeyId);
      if (!k) throw makeErr("NotFoundException", `Key ${input.KeyId} not found`);
      return {
        KeyMetadata: {
          KeyId: k.keyId,
          Arn: k.arn,
          KeyState: k.state,
          Enabled: k.state === "Enabled",
        },
      };
    },
    async encrypt(input) {
      maybeFail("Encrypt");
      const k = findKey(input.KeyId);
      if (!k) throw makeErr("NotFoundException", "Key not found");
      if (k.state === "Disabled") throw makeErr("DisabledException", "Key is disabled");
      if (k.state === "PendingDeletion") throw makeErr("KMSInvalidStateException", "Key is pending deletion");
      const payload = JSON.stringify({
        keyArn: k.arn,
        ctx: input.EncryptionContext ?? {},
        pt: Buffer.from(input.Plaintext).toString("base64"),
      });
      return { CiphertextBlob: Buffer.from(payload, "utf8") };
    },
    async decrypt(input) {
      maybeFail("Decrypt");
      const parsed = JSON.parse(Buffer.from(input.CiphertextBlob).toString("utf8"));
      if (input.KeyId && parsed.keyArn !== input.KeyId && findKey(input.KeyId)?.arn !== parsed.keyArn) {
        throw makeErr("IncorrectKeyException", "Ciphertext belongs to another key");
      }
      const k = findKey(parsed.keyArn);
      if (!k) throw makeErr("NotFoundException", "Key not found");
      if (k.state === "Disabled") throw makeErr("DisabledException", "Key is disabled");
      if (k.state === "PendingDeletion") throw makeErr("KMSInvalidStateException", "Key is pending deletion");
      if (JSON.stringify(parsed.ctx) !== JSON.stringify(input.EncryptionContext ?? {})) {
        throw makeErr("InvalidCiphertextException", "EncryptionContext mismatch");
      }
      return { Plaintext: Buffer.from(parsed.pt, "base64"), KeyId: k.arn };
    },
    async disableKey(input) {
      maybeFail("DisableKey");
      const k = findKey(input.KeyId);
      if (!k) throw makeErr("NotFoundException", "Key not found");
      if (k.state === "PendingDeletion") throw makeErr("KMSInvalidStateException", "Key is pending deletion");
      k.state = "Disabled";
    },
    async scheduleKeyDeletion(input) {
      maybeFail("ScheduleKeyDeletion");
      const k = findKey(input.KeyId);
      if (!k) throw makeErr("NotFoundException", "Key not found");
      if (k.state === "PendingDeletion") throw makeErr("KMSInvalidStateException", "Key is already pending deletion");
      k.state = "PendingDeletion";
      return { KeyState: "PendingDeletion", DeletionDate: new Date(Date.now() + 7 * 86400_000) };
    },
  };

  const clients: P6aAwsClients = {
    kms,
    sts: {
      async getCallerIdentity() {
        return { Account: accountId, Arn: callerArn };
      },
    },
    cloudtrail: {
      async lookupEvents() {
        return {
          Events: cloudTrailEvents.map((e) => ({
            EventId: e.EventId,
            EventName: e.EventName,
            Resources: [{ ResourceName: e.KeyArn }],
          })),
        };
      },
    },
  };

  const finalizeMockDeletion = (keyArn: string, recordCloudTrail = true) => {
    const k = findKey(keyArn);
    if (k) keys.delete(k.keyId);
    if (recordCloudTrail) {
      eventCounter += 1;
      cloudTrailEvents.push({
        EventId: `ct-evt-${eventCounter}`,
        EventName: "DeleteKey",
        KeyArn: keyArn,
      });
    }
  };

  return { clients, kms, keys, aliases, cloudTrailEvents, finalizeMockDeletion };
}

describe("P6a AWS KMS Adapter", () => {
  it("enforces account/key binding, fail-closed outage, and distinct denied/pending/destroyed states", async () => {
    const env = createMockAwsEnv();
    const keyA = await env.kms.createKey({ Tags: [{ TagKey: "swyra-purpose", TagValue: "p6a-proof" }] });
    const keyB = await env.kms.createKey({ Tags: [{ TagKey: "swyra-purpose", TagValue: "p6a-proof" }] });
    const arnA = keyA.KeyMetadata.Arn;
    const arnB = keyB.KeyMetadata.Arn;

    const provider = new AwsKmsAccountKeyProvider({
      client: env.kms,
      resolveAccountKeyRef: (accountId) => (accountId === "acct_A" ? arnA : arnB),
    });

    const dekA = Buffer.from("secret-dek-for-account-A-32bytes!");
    const wrappedA = await provider.wrapDataKey("acct_A", dekA);
    assert.equal(wrappedA.keyRef, arnA);
    assert.deepEqual(await provider.unwrapDataKey("acct_A", arnA, wrappedA.wrappedKey), dekA);

    // Cross-account unwrap must fail closed
    await assert.rejects(
      () => provider.unwrapDataKey("acct_B", arnA, wrappedA.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "cross_account_denied"
    );

    // Disable -> key_denied
    const denyRes = await provider.denyAccess("acct_A", arnA, "owner_revoked");
    assert.equal(denyRes.state, "denied");
    assert.equal((await provider.getKeyState("acct_A", arnA)).state, "denied");
    await assert.rejects(
      () => provider.unwrapDataKey("acct_A", arnA, wrappedA.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_denied"
    );

    // Schedule deletion -> key_scheduled_destruction + idempotent retry + no downgrade
    const sched1 = await provider.scheduleDestruction("acct_A", arnA);
    assert.equal(sched1.state, "scheduled_destruction");
    assert.equal(sched1.idempotent, false);
    const sched2 = await provider.scheduleDestruction("acct_A", arnA);
    assert.equal(sched2.state, "scheduled_destruction");
    assert.equal(sched2.idempotent, true);
    assert.equal((await provider.getKeyState("acct_A", arnA)).state, "scheduled_destruction");
    await assert.rejects(
      () => provider.unwrapDataKey("acct_A", arnA, wrappedA.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_scheduled_destruction"
    );
    await assert.rejects(
      () => provider.denyAccess("acct_A", arnA, "downgrade"),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_scheduled_destruction"
    );

    // Final deletion -> destroyed
    env.finalizeMockDeletion(arnA, true);
    assert.equal((await provider.getKeyState("acct_A", arnA)).state, "destroyed");
    await assert.rejects(
      () => provider.unwrapDataKey("acct_A", arnA, wrappedA.wrappedKey),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "key_destroyed"
    );
  });

  it("fails closed on KMS AccessDeniedException", async () => {
    const env = createMockAwsEnv({ failOnAction: "Decrypt" });
    const provider = new AwsKmsAccountKeyProvider({
      client: env.kms,
      resolveAccountKeyRef: () => "arn:aws:kms:us-east-1:111122223333:key/k1",
    });
    await assert.rejects(
      () => provider.unwrapDataKey("acct_A", "arn:aws:kms:us-east-1:111122223333:key/k1", Buffer.from("x").toString("base64")),
      (err: any) => err instanceof AccountKeyAccessError && err.code === "provider_outage"
    );
  });
});

describe("P6a Sandbox Runner Guardrails, Resume, and Evidence", () => {
  const baseConfig = (stateFile: string) => ({
    stateFile,
    accountId: "111122223333",
    roleArn: "arn:aws:iam::111122223333:role/swyra-p6a-sandbox-role",
    region: "us-east-1",
    cleanupOwner: "platform-sec",
    approved: true,
  });

  it("rejects missing approval, wrong account/role, wrong region, and alias collisions before mutation", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "p6a-runner-"));
    try {
      const env = createMockAwsEnv();
      await assert.rejects(
        () => runP6aSandboxStart({ ...baseConfig(path.join(dir, "s1.json")), approved: false }, env.clients),
        /Explicit execution approval is required/
      );
      await assert.rejects(
        () => runP6aSandboxStart({ ...baseConfig(path.join(dir, "s2.json")), region: "us-west-2" }, env.clients),
        /Pinned region must be us-east-1/
      );
      await assert.rejects(
        () => runP6aSandboxStart({ ...baseConfig(path.join(dir, "s3.json")), accountId: "999999999999" }, env.clients),
        /Caller account mismatch/
      );
      await assert.rejects(
        () =>
          runP6aSandboxStart(
            { ...baseConfig(path.join(dir, "s4.json")), roleArn: "arn:aws:iam::111122223333:role/other-role" },
            env.clients
          ),
        /Caller role mismatch/
      );
      assert.equal(env.keys.size, 0, "No KMS keys may be created when preflight fails");

      // Alias collision check
      const existing = await env.kms.createKey({ Tags: [] });
      await env.kms.createAlias({ AliasName: "alias/swyra-p6a-proof-a", TargetKeyId: existing.KeyMetadata.KeyId });
      await assert.rejects(
        () => runP6aSandboxStart(baseConfig(path.join(dir, "s5.json")), env.clients),
        /Alias collision/
      );
      assert.equal(env.keys.size, 1, "No new keys created on alias collision");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("executes start -> pending -> CloudTrail + DescribeKey final destruction -> cleanup B, and rejects missing/mismatched evidence", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "p6a-runner-full-"));
    try {
      const stateFile = path.join(dir, "state.json");
      const env = createMockAwsEnv();

      const startRes = await runP6aSandboxStart(baseConfig(stateFile), env.clients);
      assert.equal(startRes.status, "pending_destruction");
      assert.ok(startRes.state.completedSteps.includes("positiveDecrypt"));
      assert.ok(startRes.state.completedSteps.includes("disableKeyA"));
      assert.ok(startRes.state.completedSteps.includes("scheduleDeletionA"));

      // Resume while A is still PendingDeletion -> stays pending, B remains untouched
      const stillPending = await runP6aSandboxResume(baseConfig(stateFile), env.clients);
      assert.equal(stillPending.status, "pending_destruction");
      assert.ok(env.aliases.has("alias/swyra-p6a-proof-b"));

      // Delete A without CloudTrail DeleteKey event -> must NOT mark destroyed
      const arnA = startRes.state.keys.A!.arn;
      env.finalizeMockDeletion(arnA, false);
      const missingCt = await runP6aSandboxResume(baseConfig(stateFile), env.clients);
      assert.equal(missingCt.status, "pending_destruction");
      assert.ok(!missingCt.state.completedSteps.includes("verifyFinalDestructionA"));

      // Mismatched CloudTrail DeleteKey ARN -> must NOT mark destroyed
      env.cloudTrailEvents.push({
        EventId: "ct-wrong",
        EventName: "DeleteKey",
        KeyArn: "arn:aws:kms:us-east-1:111122223333:key/unrelated-key",
      });
      const mismatchedCt = await runP6aSandboxResume(baseConfig(stateFile), env.clients);
      assert.equal(mismatchedCt.status, "pending_destruction");

      // Exact ARN CloudTrail DeleteKey event -> marks A destroyed and cleans up B
      env.cloudTrailEvents.push({
        EventId: "ct-exact-a",
        EventName: "DeleteKey",
        KeyArn: arnA,
      });
      const done = await runP6aSandboxResume(baseConfig(stateFile), env.clients);
      assert.equal(done.status, "completed");
      assert.ok(done.state.completedSteps.includes("verifyFinalDestructionA"));
      assert.ok(done.state.completedSteps.includes("cleanupB"));
      assert.equal(done.state.evidence.finalDestructionA?.cloudTrailEventId, "ct-exact-a");
      assert.equal(env.aliases.has("alias/swyra-p6a-proof-b"), false);

      // Second resume after completion must succeed idempotently
      const doneAgain = await runP6aSandboxResume(baseConfig(stateFile), env.clients);
      assert.equal(doneAgain.status, "completed");
      assert.deepEqual(doneAgain.state.completedSteps, done.state.completedSteps);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("leaves destruction unconfirmed and B untouched on AccessDeniedException during CloudTrail verification", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "p6a-runner-denied-"));
    try {
      const stateFile = path.join(dir, "state.json");
      const env = createMockAwsEnv();
      const startRes = await runP6aSandboxStart(baseConfig(stateFile), env.clients);
      env.finalizeMockDeletion(startRes.state.keys.A!.arn, true);

      const deniedClients: P6aAwsClients = {
        ...env.clients,
        cloudtrail: {
          async lookupEvents() {
            const err = new Error("Denied lookupEvents") as Error & { name: string };
            err.name = "AccessDeniedException";
            throw err;
          },
        },
      };
      await assert.rejects(() => runP6aSandboxResume(baseConfig(stateFile), deniedClients), /Denied lookupEvents/);
      const persisted = JSON.parse(fs.readFileSync(stateFile, "utf8"));
      assert.ok(!persisted.completedSteps.includes("verifyFinalDestructionA"));
      assert.ok(env.aliases.has("alias/swyra-p6a-proof-b"), "Key B must remain untouched when verification fails");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("proves offline CLI across fresh Node processes: start -> pending -> simulate-delete-a -> resume -> completed -> second resume", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "p6a-cli-e2e-"));
    try {
      const stateFile = path.join(dir, "state.json");
      const cliPath = path.resolve(import.meta.dirname, "../../scripts/p6a-sandbox-cli.ts");
      const tsxPath = path.resolve(import.meta.dirname, "../../node_modules/.bin/tsx");
      const runCli = (action: string) =>
        JSON.parse(
          execFileSync(
            tsxPath,
            [cliPath, "--mode", "offline", "--action", action, "--state-file", stateFile, "--approved", "true"],
            { encoding: "utf8" }
          )
        );

      const s1 = runCli("start");
      assert.equal(s1.status, "pending_destruction");
      assert.ok(s1.completedSteps.includes("scheduleDeletionA"));

      const s2 = runCli("resume");
      assert.equal(s2.status, "pending_destruction");

      const s3 = runCli("simulate-delete-a");
      assert.equal(s3.simulatedFinalDeletionA, true);

      const s4 = runCli("resume");
      assert.equal(s4.status, "completed");
      assert.ok(s4.completedSteps.includes("verifyFinalDestructionA"));
      assert.ok(s4.completedSteps.includes("cleanupB"));

      const s5 = runCli("resume");
      assert.equal(s5.status, "completed");
      assert.deepEqual(s5.completedSteps, s4.completedSteps);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("resumes safely after interruption right after key creation and after lost ScheduleKeyDeletion response, never adopting unrelated keys", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "p6a-runner-resume-"));
    try {
      const env = createMockAwsEnv();
      const unrelated = await env.kms.createKey({ Tags: [{ TagKey: "swyra-purpose", TagValue: "other" }] });

      // 1. Interruption immediately after key A creation
      const s1 = path.join(dir, "interrupt-create.json");
      const keyA = await env.kms.createKey({
        Tags: [
          { TagKey: "swyra-purpose", TagValue: "p6a-proof" },
          { TagKey: "swyra-run-id", TagValue: "run-interrupt-1" },
        ],
      });
      fs.writeFileSync(
        s1,
        JSON.stringify({
          runId: "run-interrupt-1",
          accountId: "111122223333",
          roleArn: "arn:aws:iam::111122223333:role/swyra-p6a-sandbox-role",
          region: "us-east-1",
          cleanupOwner: "platform-sec",
          keys: { A: { keyId: keyA.KeyMetadata.KeyId, arn: keyA.KeyMetadata.Arn, alias: "alias/swyra-p6a-proof-a" } },
          completedSteps: ["createKeyA"],
          evidence: {},
        })
      );
      const res1 = await runP6aSandboxResume(baseConfig(s1), env.clients);
      assert.equal(res1.status, "pending_destruction");
      assert.equal(res1.state.keys.A?.arn, keyA.KeyMetadata.Arn);

      // 2. Interruption after ScheduleKeyDeletion whose response was lost (key is already PendingDeletion in KMS)
      const s2 = path.join(dir, "interrupt-sched.json");
      fs.copyFileSync(s1, s2);
      const parsed2 = JSON.parse(fs.readFileSync(s2, "utf8"));
      parsed2.completedSteps = parsed2.completedSteps.filter((step: string) => step !== "scheduleDeletionA");
      fs.writeFileSync(s2, JSON.stringify(parsed2));
      const res2 = await runP6aSandboxResume(baseConfig(s2), env.clients);
      assert.equal(res2.status, "pending_destruction");
      assert.ok(res2.state.completedSteps.includes("scheduleDeletionA"));

      // 3. Tampered state pointing at unrelated key must fail ownership check and never mutate it
      const s3 = path.join(dir, "tampered.json");
      parsed2.keys.A.keyId = unrelated.KeyMetadata.KeyId;
      parsed2.keys.A.arn = unrelated.KeyMetadata.Arn;
      fs.writeFileSync(s3, JSON.stringify(parsed2));
      await assert.rejects(
        () => runP6aSandboxResume(baseConfig(s3), env.clients),
        /Key ownership verification failed/
      );
      assert.equal(env.keys.get(unrelated.KeyMetadata.KeyId)?.state, "Enabled");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
