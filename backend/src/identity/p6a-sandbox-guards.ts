import fs from "node:fs";
import path from "node:path";
import type { AwsKmsClient } from "./aws-kms-account-key-provider";

export interface P6aSandboxKmsClient extends AwsKmsClient {
  createKey(input: {
    Description?: string;
    MultiRegion?: boolean;
    Tags?: Array<{ TagKey: string; TagValue: string }>;
  }): Promise<{ KeyMetadata: { KeyId: string; Arn: string } }>;
  createAlias(input: { AliasName: string; TargetKeyId: string }): Promise<void>;
  deleteAlias(input: { AliasName: string }): Promise<void>;
  listAliases(): Promise<{ Aliases: Array<{ AliasName: string; TargetKeyId?: string }> }>;
  listResourceTags(input: { KeyId: string }): Promise<{ Tags: Array<{ TagKey: string; TagValue: string }> }>;
}

export interface P6aAwsClients {
  kms: P6aSandboxKmsClient;
  sts: { getCallerIdentity(): Promise<{ Account?: string; Arn?: string }> };
  cloudtrail: {
    lookupEvents(input: { LookupAttributes?: Array<{ AttributeKey: string; AttributeValue: string }> }): Promise<{
      Events?: Array<{ EventId?: string; EventName?: string; Resources?: Array<{ ResourceName?: string }> }>;
    }>;
  };
}

export interface P6aSandboxConfig {
  stateFile: string;
  accountId: string;
  roleArn: string;
  region: string;
  cleanupOwner: string;
  approved: boolean;
}

export interface P6aKeyRecord {
  keyId: string;
  arn: string;
  alias: string;
  ciphertextBase64?: string;
}

export interface P6aRunState {
  runId: string;
  accountId: string;
  roleArn: string;
  region: string;
  cleanupOwner: string;
  keys: { A?: P6aKeyRecord; B?: P6aKeyRecord };
  completedSteps: string[];
  evidence: {
    positiveDecrypt?: boolean;
    disabledAError?: string;
    scheduledDeletionAError?: string;
    finalDestructionA?: { cloudTrailEventId: string; cloudTrailKeyArn: string; describeNotFound: true };
    cleanedUpB?: boolean;
  };
}

export const PINNED_REGION = "us-east-1";
export const ALIAS_A = "alias/swyra-p6a-proof-a";
export const ALIAS_B = "alias/swyra-p6a-proof-b";

export function awsErrName(err: unknown): string {
  return err && typeof err === "object" && "name" in err ? String((err as { name?: unknown }).name ?? "") : "";
}

export function saveP6aState(stateFile: string, state: P6aRunState): void {
  fs.mkdirSync(path.dirname(stateFile), { recursive: true });
  const tmp = `${stateFile}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
  fs.renameSync(tmp, stateFile);
}

function roleMatchesCaller(expectedRoleArn: string, callerArn: string): boolean {
  if (callerArn === expectedRoleArn) return true;
  const match = expectedRoleArn.match(/^arn:aws:iam::(\d{12}):role\/(.+)$/);
  if (!match) return false;
  const [, acct, roleName] = match;
  return callerArn.startsWith(`arn:aws:sts::${acct}:assumed-role/${roleName}/`);
}

export async function runP6aPreflight(config: P6aSandboxConfig, clients: P6aAwsClients): Promise<void> {
  if (!config.approved) {
    throw new Error("Explicit execution approval is required before any AWS mutation");
  }
  if (config.region !== PINNED_REGION) {
    throw new Error(`Pinned region must be ${PINNED_REGION}, got "${config.region}"`);
  }
  if (!config.cleanupOwner.trim()) {
    throw new Error("Cleanup owner must be specified");
  }
  const caller = await clients.sts.getCallerIdentity();
  if (caller.Account !== config.accountId) {
    throw new Error(`Caller account mismatch: expected ${config.accountId}, got ${caller.Account}`);
  }
  if (!caller.Arn || !roleMatchesCaller(config.roleArn, caller.Arn)) {
    throw new Error(`Caller role mismatch: expected ${config.roleArn}, got ${caller.Arn}`);
  }
}

export async function verifyP6aKeyOwnership(
  clients: P6aAwsClients,
  key: P6aKeyRecord,
  runId: string
): Promise<{ KeyState?: string }> {
  const desc = await clients.kms.describeKey({ KeyId: key.arn });
  if (desc.KeyMetadata?.Arn !== key.arn || desc.KeyMetadata?.KeyId !== key.keyId) {
    throw new Error(`Key ownership verification failed: ARN/ID mismatch for ${key.arn}`);
  }
  const tagsRes = await clients.kms.listResourceTags({ KeyId: key.arn });
  const tagMap = new Map(tagsRes.Tags.map((t) => [t.TagKey, t.TagValue]));
  if (tagMap.get("swyra-purpose") !== "p6a-proof" || tagMap.get("swyra-run-id") !== runId) {
    throw new Error(`Key ownership verification failed: missing p6a-proof/runId tags on ${key.arn}`);
  }
  return { KeyState: desc.KeyMetadata?.KeyState };
}

export async function ensureP6aTestKey(
  clients: P6aAwsClients,
  state: P6aRunState,
  stateFile: string,
  slot: "A" | "B",
  alias: string
): Promise<P6aKeyRecord> {
  const aliasList = await clients.kms.listAliases();
  const existingAlias = aliasList.Aliases.find((a) => a.AliasName === alias);
  let rec = state.keys[slot];

  if (!rec) {
    if (existingAlias) {
      throw new Error(`Alias collision: ${alias} already exists for key ${existingAlias.TargetKeyId}`);
    }
    const created = await clients.kms.createKey({
      Description: `SWYRA P6a proof key ${slot} (${state.runId})`,
      MultiRegion: false,
      Tags: [
        { TagKey: "swyra-purpose", TagValue: "p6a-proof" },
        { TagKey: "swyra-run-id", TagValue: state.runId },
        { TagKey: "swyra-cleanup-owner", TagValue: state.cleanupOwner },
      ],
    });
    rec = { keyId: created.KeyMetadata.KeyId, arn: created.KeyMetadata.Arn, alias };
    state.keys[slot] = rec;
    state.completedSteps.push(`createKey${slot}`);
    saveP6aState(stateFile, state);
  } else {
    await verifyP6aKeyOwnership(clients, rec, state.runId);
  }

  if (existingAlias && existingAlias.TargetKeyId !== rec.keyId) {
    throw new Error(`Alias collision: ${alias} points to ${existingAlias.TargetKeyId}, expected ${rec.keyId}`);
  }
  if (!existingAlias) {
    await clients.kms.createAlias({ AliasName: alias, TargetKeyId: rec.keyId });
    state.completedSteps.push(`createAlias${slot}`);
    saveP6aState(stateFile, state);
  }
  return rec;
}
