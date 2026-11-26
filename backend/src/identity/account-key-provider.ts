import crypto from "node:crypto";

export type AccountKeyState =
  | "active"
  | "denied"
  | "scheduled_destruction"
  | "destroyed";

export class AccountKeyAccessError extends Error {
  constructor(
    public readonly code:
      | "cross_account_denied"
      | "key_denied"
      | "key_scheduled_destruction"
      | "key_destroyed"
      | "provider_outage"
      | "key_not_found",
    message: string
  ) {
    super(message);
    this.name = "AccountKeyAccessError";
  }
}

export interface AccountKeyProvider {
  wrapDataKey(
    accountId: string,
    plaintextKey: Buffer
  ): Promise<{ keyRef: string; wrappedKey: string; state: AccountKeyState }>;
  unwrapDataKey(
    accountId: string,
    keyRef: string,
    wrappedKey: string
  ): Promise<Buffer>;
  denyAccess(
    accountId: string,
    keyRef: string,
    reason: string
  ): Promise<{ state: "denied"; monotonicSeq: number }>;
  scheduleDestruction(
    accountId: string,
    keyRef: string
  ): Promise<{ state: "scheduled_destruction" | "destroyed"; idempotent: boolean }>;
  getKeyState(
    accountId: string,
    keyRef: string
  ): Promise<{ state: AccountKeyState; monotonicSeq: number }>;
}

interface StoredKeyRecord {
  accountId: string;
  kek: Buffer;
  state: AccountKeyState;
  monotonicSeq: number;
  denyReason?: string;
}

/**
 * Disposable in-memory key provider for P6a local proof.
 * Production cloud KMS or self-hosted HSM/Vault adapters implement AccountKeyProvider.
 */
export class InMemoryAccountKeyProvider implements AccountKeyProvider {
  private readonly records = new Map<string, StoredKeyRecord>();
  private seqCounter = 0;
  private outage = false;

  setOutage(enabled: boolean): void {
    this.outage = enabled;
  }

  completeDestructionForTest(accountId: string, keyRef: string): void {
    const rec = this.records.get(keyRef);
    if (!rec || rec.accountId !== accountId) {
      throw new AccountKeyAccessError("key_not_found", "Key not found");
    }
    rec.kek.fill(0);
    rec.state = "destroyed";
    rec.monotonicSeq = ++this.seqCounter;
  }

  async wrapDataKey(
    accountId: string,
    plaintextKey: Buffer
  ): Promise<{ keyRef: string; wrappedKey: string; state: AccountKeyState }> {
    if (this.outage) {
      throw new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
    const keyRef = `mem_key_${crypto.randomBytes(12).toString("hex")}`;
    const kek = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", kek, iv);
    cipher.setAAD(Buffer.from(`${accountId}:${keyRef}`, "utf8"));
    const enc = Buffer.concat([cipher.update(plaintextKey), cipher.final()]);
    const tag = cipher.getAuthTag();

    this.records.set(keyRef, {
      accountId,
      kek,
      state: "active",
      monotonicSeq: ++this.seqCounter,
    });

    return {
      keyRef,
      wrappedKey: Buffer.concat([iv, tag, enc]).toString("base64"),
      state: "active",
    };
  }

  async unwrapDataKey(
    accountId: string,
    keyRef: string,
    wrappedKey: string
  ): Promise<Buffer> {
    if (this.outage) {
      throw new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
    const rec = this.records.get(keyRef);
    if (!rec) {
      throw new AccountKeyAccessError("key_not_found", "Key not found");
    }
    if (rec.accountId !== accountId) {
      throw new AccountKeyAccessError(
        "cross_account_denied",
        "Account does not own this key"
      );
    }
    if (rec.state === "denied") {
      throw new AccountKeyAccessError("key_denied", "Key access is denied");
    }
    if (rec.state === "scheduled_destruction") {
      throw new AccountKeyAccessError(
        "key_scheduled_destruction",
        "Key is scheduled for destruction"
      );
    }
    if (rec.state === "destroyed") {
      throw new AccountKeyAccessError("key_destroyed", "Key has been destroyed");
    }

    const raw = Buffer.from(wrappedKey, "base64");
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const enc = raw.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", rec.kek, iv);
    decipher.setAAD(Buffer.from(`${accountId}:${keyRef}`, "utf8"));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]);
  }

  async denyAccess(
    accountId: string,
    keyRef: string,
    reason: string
  ): Promise<{ state: "denied"; monotonicSeq: number }> {
    if (this.outage) {
      throw new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
    const rec = this.records.get(keyRef);
    if (!rec || rec.accountId !== accountId) {
      throw new AccountKeyAccessError("key_not_found", "Key not found");
    }
    if (rec.state === "scheduled_destruction" || rec.state === "destroyed") {
      throw new AccountKeyAccessError(
        rec.state === "destroyed" ? "key_destroyed" : "key_scheduled_destruction",
        "Cannot downgrade destruction state to temporary denial"
      );
    }
    rec.state = "denied";
    rec.denyReason = reason;
    rec.monotonicSeq = ++this.seqCounter;
    return { state: "denied", monotonicSeq: rec.monotonicSeq };
  }

  async scheduleDestruction(
    accountId: string,
    keyRef: string
  ): Promise<{ state: "scheduled_destruction" | "destroyed"; idempotent: boolean }> {
    if (this.outage) {
      throw new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
    const rec = this.records.get(keyRef);
    if (!rec || rec.accountId !== accountId) {
      throw new AccountKeyAccessError("key_not_found", "Key not found");
    }
    if (rec.state === "destroyed") {
      return { state: "destroyed", idempotent: true };
    }
    if (rec.state === "scheduled_destruction") {
      return { state: "scheduled_destruction", idempotent: true };
    }
    rec.state = "scheduled_destruction";
    rec.monotonicSeq = ++this.seqCounter;
    return { state: "scheduled_destruction", idempotent: false };
  }

  async getKeyState(
    accountId: string,
    keyRef: string
  ): Promise<{ state: AccountKeyState; monotonicSeq: number }> {
    if (this.outage) {
      throw new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
    const rec = this.records.get(keyRef);
    if (!rec || rec.accountId !== accountId) {
      throw new AccountKeyAccessError("key_not_found", "Key not found");
    }
    return { state: rec.state, monotonicSeq: rec.monotonicSeq };
  }
}
