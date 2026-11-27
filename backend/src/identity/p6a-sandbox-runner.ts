import crypto from "node:crypto";
import fs from "node:fs";
import {
  ALIAS_A,
  ALIAS_B,
  awsErrName,
  ensureP6aTestKey,
  runP6aPreflight,
  saveP6aState,
  verifyP6aKeyOwnership,
  type P6aAwsClients,
  type P6aKeyRecord,
  type P6aRunState,
  type P6aSandboxConfig,
} from "./p6a-sandbox-guards";

export type { P6aAwsClients, P6aKeyRecord, P6aRunState, P6aSandboxConfig } from "./p6a-sandbox-guards";

async function assertKeyADecryptDenied(
  clients: P6aAwsClients,
  keyA: P6aKeyRecord,
  keyB: P6aKeyRecord,
  allowedErrors: string[],
  label: string
): Promise<string> {
  let caught = "";
  try {
    await clients.kms.decrypt({
      CiphertextBlob: Buffer.from(keyA.ciphertextBase64!, "base64"),
      KeyId: keyA.arn,
      EncryptionContext: { slot: "A" },
    });
    throw new Error(`Key A decrypt unexpectedly succeeded during ${label}`);
  } catch (err) {
    caught = awsErrName(err);
    if (!allowedErrors.includes(caught)) throw err;
  }
  await clients.kms.decrypt({
    CiphertextBlob: Buffer.from(keyB.ciphertextBase64!, "base64"),
    KeyId: keyB.arn,
    EncryptionContext: { slot: "B" },
  });
  return caught;
}

async function executeWorkflow(
  config: P6aSandboxConfig,
  clients: P6aAwsClients,
  state: P6aRunState
): Promise<{ status: "pending_destruction" | "completed"; state: P6aRunState }> {
  const has = (step: string) => state.completedSteps.includes(step);

  if (!has("verifyFinalDestructionA")) {
    let aDeletedInKms = false;
    try {
      await clients.kms.describeKey({ KeyId: state.keys.A?.arn ?? ALIAS_A });
    } catch (err) {
      if (state.keys.A && awsErrName(err) === "NotFoundException") {
        aDeletedInKms = true;
      }
    }

    if (!aDeletedInKms) {
      const keyA = await ensureP6aTestKey(clients, state, config.stateFile, "A", ALIAS_A);
      const keyB = await ensureP6aTestKey(clients, state, config.stateFile, "B", ALIAS_B);

      if (!has("positiveDecrypt")) {
        for (const [slot, rec] of [["A", keyA], ["B", keyB]] as const) {
          const pt = Buffer.from(`p6a-proof-${slot}-${state.runId}`);
          const enc = await clients.kms.encrypt({ KeyId: rec.arn, Plaintext: pt, EncryptionContext: { slot } });
          rec.ciphertextBase64 = Buffer.from(enc.CiphertextBlob!).toString("base64");
          const dec = await clients.kms.decrypt({
            CiphertextBlob: Buffer.from(rec.ciphertextBase64, "base64"),
            KeyId: rec.arn,
            EncryptionContext: { slot },
          });
          if (Buffer.from(dec.Plaintext!).toString("utf8") !== pt.toString("utf8")) {
            throw new Error(`Positive decrypt failed for ${slot}`);
          }
        }
        state.evidence.positiveDecrypt = true;
        state.completedSteps.push("positiveDecrypt");
        saveP6aState(config.stateFile, state);
      }

      if (!has("disableKeyA")) {
        const metaA = await verifyP6aKeyOwnership(clients, keyA, state.runId);
        if (metaA.KeyState === "Enabled") {
          await clients.kms.disableKey({ KeyId: keyA.arn });
        }
        state.evidence.disabledAError = await assertKeyADecryptDenied(
          clients,
          keyA,
          keyB,
          ["DisabledException", "KMSInvalidStateException"],
          "DisableKey"
        );
        state.completedSteps.push("disableKeyA");
        saveP6aState(config.stateFile, state);
      }

      if (!has("scheduleDeletionA")) {
        const metaA = await verifyP6aKeyOwnership(clients, keyA, state.runId);
        if (metaA.KeyState !== "PendingDeletion") {
          await clients.kms.scheduleKeyDeletion({ KeyId: keyA.arn, PendingWindowInDays: 7 });
        }
        state.evidence.scheduledDeletionAError = await assertKeyADecryptDenied(
          clients,
          keyA,
          keyB,
          ["KMSInvalidStateException"],
          "PendingDeletion"
        );
        state.completedSteps.push("scheduleDeletionA");
        saveP6aState(config.stateFile, state);
      }

      return { status: "pending_destruction", state };
    }

    const ct = await clients.cloudtrail.lookupEvents({
      LookupAttributes: [{ AttributeKey: "EventName", AttributeValue: "DeleteKey" }],
    });
    const match = (ct.Events ?? []).find(
      (e) => e.EventName === "DeleteKey" && e.Resources?.some((r) => r.ResourceName === state.keys.A!.arn)
    );
    if (!match?.EventId) {
      return { status: "pending_destruction", state };
    }
    state.evidence.finalDestructionA = {
      cloudTrailEventId: match.EventId,
      cloudTrailKeyArn: state.keys.A!.arn,
      describeNotFound: true,
    };
    state.completedSteps.push("verifyFinalDestructionA");
    saveP6aState(config.stateFile, state);
  }

  if (!has("cleanupB") && state.keys.B) {
    const metaB = await verifyP6aKeyOwnership(clients, state.keys.B, state.runId);
    if (metaB.KeyState !== "PendingDeletion") {
      await clients.kms.scheduleKeyDeletion({ KeyId: state.keys.B.arn, PendingWindowInDays: 7 });
    }
    try {
      await clients.kms.deleteAlias({ AliasName: ALIAS_B });
    } catch (err) {
      if (awsErrName(err) !== "NotFoundException") throw err;
    }
    state.evidence.cleanedUpB = true;
    state.completedSteps.push("cleanupB");
    saveP6aState(config.stateFile, state);
  }

  return { status: "completed", state };
}

export async function runP6aSandboxStart(
  config: P6aSandboxConfig,
  clients: P6aAwsClients
): Promise<{ status: "pending_destruction" | "completed"; state: P6aRunState }> {
  await runP6aPreflight(config, clients);
  const state: P6aRunState = {
    runId: `p6a-${crypto.randomBytes(6).toString("hex")}`,
    accountId: config.accountId,
    roleArn: config.roleArn,
    region: config.region,
    cleanupOwner: config.cleanupOwner,
    keys: {},
    completedSteps: [],
    evidence: {},
  };
  saveP6aState(config.stateFile, state);
  return executeWorkflow(config, clients, state);
}

export async function runP6aSandboxResume(
  config: P6aSandboxConfig,
  clients: P6aAwsClients
): Promise<{ status: "pending_destruction" | "completed"; state: P6aRunState }> {
  await runP6aPreflight(config, clients);
  if (!fs.existsSync(config.stateFile)) {
    throw new Error(`State file not found: ${config.stateFile}`);
  }
  const state = JSON.parse(fs.readFileSync(config.stateFile, "utf8")) as P6aRunState;
  if (state.accountId !== config.accountId || state.region !== config.region) {
    throw new Error("State file account/region does not match runner configuration");
  }
  return executeWorkflow(config, clients, state);
}
