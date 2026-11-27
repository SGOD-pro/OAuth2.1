import fs from "node:fs";
import { pathToFileURL } from "node:url";
import {
  runP6aSandboxStart,
  runP6aSandboxResume,
  type P6aAwsClients,
} from "../src/identity/p6a-sandbox-runner";

interface OfflineBackingStore {
  keys: Record<string, { keyId: string; arn: string; state: "Enabled" | "Disabled" | "PendingDeletion"; tags: Record<string, string> }>;
  aliases: Record<string, string>;
  events: Array<{ EventId: string; EventName: string; KeyArn: string }>;
  seq: number;
}

function createOfflineClients(backingFile: string, accountId: string, roleArn: string): P6aAwsClients {
  const load = (): OfflineBackingStore =>
    fs.existsSync(backingFile)
      ? JSON.parse(fs.readFileSync(backingFile, "utf8"))
      : { keys: {}, aliases: {}, events: [], seq: 0 };
  const save = (store: OfflineBackingStore) => fs.writeFileSync(backingFile, JSON.stringify(store, null, 2));
  const err = (name: string, msg: string) => Object.assign(new Error(msg), { name });
  const find = (store: OfflineBackingStore, idOrArn: string) =>
    Object.values(store.keys).find((k) => k.keyId === idOrArn || k.arn === idOrArn);

  return {
    sts: {
      async getCallerIdentity() {
        return { Account: accountId, Arn: roleArn };
      },
    },
    cloudtrail: {
      async lookupEvents() {
        const s = load();
        return {
          Events: s.events.map((e) => ({ EventId: e.EventId, EventName: e.EventName, Resources: [{ ResourceName: e.KeyArn }] })),
        };
      },
    },
    kms: {
      async createKey(input) {
        const s = load();
        s.seq += 1;
        const keyId = `offline-${s.seq}`;
        const arn = `arn:aws:kms:us-east-1:${accountId}:key/${keyId}`;
        const tags: Record<string, string> = {};
        for (const t of input.Tags ?? []) tags[t.TagKey] = t.TagValue;
        s.keys[keyId] = { keyId, arn, state: "Enabled", tags };
        save(s);
        return { KeyMetadata: { KeyId: keyId, Arn: arn } };
      },
      async createAlias(input) {
        const s = load();
        if (s.aliases[input.AliasName]) throw err("AlreadyExistsException", "Alias exists");
        s.aliases[input.AliasName] = input.TargetKeyId;
        save(s);
      },
      async deleteAlias(input) {
        const s = load();
        delete s.aliases[input.AliasName];
        save(s);
      },
      async listAliases() {
        const s = load();
        return { Aliases: Object.entries(s.aliases).map(([AliasName, TargetKeyId]) => ({ AliasName, TargetKeyId })) };
      },
      async listResourceTags(input) {
        const k = find(load(), input.KeyId);
        if (!k) throw err("NotFoundException", "Key not found");
        return { Tags: Object.entries(k.tags).map(([TagKey, TagValue]) => ({ TagKey, TagValue })) };
      },
      async describeKey(input) {
        const k = find(load(), input.KeyId);
        if (!k) throw err("NotFoundException", "Key not found");
        return { KeyMetadata: { KeyId: k.keyId, Arn: k.arn, KeyState: k.state, Enabled: k.state === "Enabled" } };
      },
      async encrypt(input) {
        const k = find(load(), input.KeyId);
        if (!k) throw err("NotFoundException", "Key not found");
        if (k.state === "Disabled") throw err("DisabledException", "Disabled");
        if (k.state === "PendingDeletion") throw err("KMSInvalidStateException", "PendingDeletion");
        return {
          CiphertextBlob: Buffer.from(JSON.stringify({ keyArn: k.arn, pt: Buffer.from(input.Plaintext).toString("base64") })),
        };
      },
      async decrypt(input) {
        const parsed = JSON.parse(Buffer.from(input.CiphertextBlob).toString("utf8"));
        const k = find(load(), parsed.keyArn);
        if (!k) throw err("NotFoundException", "Key not found");
        if (k.state === "Disabled") throw err("DisabledException", "Disabled");
        if (k.state === "PendingDeletion") throw err("KMSInvalidStateException", "PendingDeletion");
        return { Plaintext: Buffer.from(parsed.pt, "base64"), KeyId: k.arn };
      },
      async disableKey(input) {
        const s = load();
        const k = find(s, input.KeyId);
        if (!k) throw err("NotFoundException", "Key not found");
        k.state = "Disabled";
        save(s);
      },
      async scheduleKeyDeletion(input) {
        const s = load();
        const k = find(s, input.KeyId);
        if (!k) throw err("NotFoundException", "Key not found");
        k.state = "PendingDeletion";
        save(s);
        return { KeyState: "PendingDeletion", DeletionDate: new Date(Date.now() + 7 * 86400_000) };
      },
    },
  };
}

function arg(name: string, fallback = ""): string {
  const idx = process.argv.indexOf(`--${name}`);
  return idx >= 0 && process.argv[idx + 1] ? process.argv[idx + 1] : fallback;
}

async function main() {
  const mode = arg("mode", "offline");
  const action = arg("action", "start");
  const stateFile = arg("state-file", "/tmp/p6a-sandbox-state.json");
  const accountId = arg("account-id", "111122223333");
  const roleArn = arg("role-arn", `arn:aws:iam::${accountId}:role/swyra-p6a-sandbox-role`);
  const region = arg("region", "us-east-1");
  const cleanupOwner = arg("cleanup-owner", "offline-verifier");
  const approved = arg("approved", "false") === "true";

  if (mode !== "offline") {
    throw new Error("Live AWS execution is blocked until explicit sandbox approval and AWS SDK client wiring.");
  }
  const backingFile = `${stateFile}.offline-kms.json`;
  if (action === "simulate-delete-a") {
    const runState = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    const keyA = runState?.keys?.A;
    if (!keyA?.keyId || !keyA?.arn) {
      throw new Error("Cannot simulate deletion: state file has no key A");
    }
    const store = JSON.parse(fs.readFileSync(backingFile, "utf8")) as OfflineBackingStore;
    delete store.keys[keyA.keyId];
    delete store.aliases[keyA.alias];
    store.seq += 1;
    store.events.push({ EventId: `offline-ct-${store.seq}`, EventName: "DeleteKey", KeyArn: keyA.arn });
    fs.writeFileSync(backingFile, JSON.stringify(store, null, 2));
    console.log(JSON.stringify({ simulatedFinalDeletionA: true, keyArn: keyA.arn }));
    return;
  }
  if (action !== "start" && action !== "resume") {
    throw new Error(`Unsupported action: ${action}`);
  }
  const clients = createOfflineClients(backingFile, accountId, roleArn);
  const cfg = { stateFile, accountId, roleArn, region, cleanupOwner, approved };
  const result = action === "resume" ? await runP6aSandboxResume(cfg, clients) : await runP6aSandboxStart(cfg, clients);
  console.log(JSON.stringify({ status: result.status, runId: result.state.runId, completedSteps: result.state.completedSteps }, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
