import {
  AccountKeyAccessError,
  type AccountKeyProvider,
  type AccountKeyState,
} from "./account-key-provider";

export interface AwsKmsKeyMetadata {
  KeyId?: string;
  Arn?: string;
  KeyState?: string;
  Enabled?: boolean;
}

export interface AwsKmsClient {
  encrypt(input: {
    KeyId: string;
    Plaintext: Uint8Array;
    EncryptionContext?: Record<string, string>;
  }): Promise<{ CiphertextBlob?: Uint8Array }>;
  decrypt(input: {
    CiphertextBlob: Uint8Array;
    KeyId?: string;
    EncryptionContext?: Record<string, string>;
  }): Promise<{ Plaintext?: Uint8Array; KeyId?: string }>;
  disableKey(input: { KeyId: string }): Promise<void>;
  scheduleKeyDeletion(input: {
    KeyId: string;
    PendingWindowInDays?: number;
  }): Promise<{ KeyState?: string; DeletionDate?: Date }>;
  describeKey(input: { KeyId: string }): Promise<{ KeyMetadata?: AwsKmsKeyMetadata }>;
}

function getAwsErrorName(err: unknown): string {
  if (err && typeof err === "object" && "name" in err) {
    return String((err as { name?: unknown }).name ?? "");
  }
  return "";
}

function mapKmsState(meta?: AwsKmsKeyMetadata): AccountKeyState {
  const keyState = meta?.KeyState;
  if (keyState === "PendingDeletion") return "scheduled_destruction";
  if (keyState === "Disabled" || meta?.Enabled === false) return "denied";
  if (keyState === "Enabled") return "active";
  return "denied";
}

/**
 * AWS KMS adapter for AccountKeyProvider.
 * Binds each wrap/unwrap to accountId via KMS EncryptionContext and fails closed on any outage or mismatch.
 */
export class AwsKmsAccountKeyProvider implements AccountKeyProvider {
  private readonly client: AwsKmsClient;
  private readonly resolveAccountKeyRef: (accountId: string) => Promise<string> | string;
  private readonly pendingWindowInDays: number;
  private seqCounter = 0;

  constructor(options: {
    client: AwsKmsClient;
    resolveAccountKeyRef: (accountId: string) => Promise<string> | string;
    pendingWindowInDays?: number;
  }) {
    this.client = options.client;
    this.resolveAccountKeyRef = options.resolveAccountKeyRef;
    this.pendingWindowInDays = options.pendingWindowInDays ?? 7;
  }

  private async assertAccountOwnsKeyRef(accountId: string, keyRef: string): Promise<void> {
    let expectedRef: string;
    try {
      expectedRef = await this.resolveAccountKeyRef(accountId);
    } catch {
      throw new AccountKeyAccessError("key_not_found", "Account key reference not found");
    }
    if (!expectedRef || expectedRef !== keyRef) {
      throw new AccountKeyAccessError("cross_account_denied", "Account does not own this key");
    }
  }

  private async classifyInvalidState(keyRef: string): Promise<AccountKeyAccessError> {
    try {
      const desc = await this.client.describeKey({ KeyId: keyRef });
      if (desc.KeyMetadata?.KeyState === "PendingDeletion") {
        return new AccountKeyAccessError("key_scheduled_destruction", "Key is scheduled for destruction");
      }
      return new AccountKeyAccessError("key_denied", "Key is not usable in its current state");
    } catch (descErr) {
      if (getAwsErrorName(descErr) === "NotFoundException") {
        return new AccountKeyAccessError("key_destroyed", "Key has been destroyed");
      }
      return new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
  }

  async wrapDataKey(
    accountId: string,
    plaintextKey: Buffer
  ): Promise<{ keyRef: string; wrappedKey: string; state: AccountKeyState }> {
    let keyRef = "";
    try {
      keyRef = await this.resolveAccountKeyRef(accountId);
    } catch {
      keyRef = "";
    }
    if (!keyRef) {
      throw new AccountKeyAccessError("key_not_found", "Account key reference not found");
    }
    try {
      const res = await this.client.encrypt({
        KeyId: keyRef,
        Plaintext: plaintextKey,
        EncryptionContext: { swyra_account_id: accountId },
      });
      if (!res.CiphertextBlob) {
        throw new AccountKeyAccessError("provider_outage", "KMS encrypt returned empty ciphertext");
      }
      return {
        keyRef,
        wrappedKey: Buffer.from(res.CiphertextBlob).toString("base64"),
        state: "active",
      };
    } catch (err) {
      if (err instanceof AccountKeyAccessError) throw err;
      const name = getAwsErrorName(err);
      if (name === "DisabledException") {
        throw new AccountKeyAccessError("key_denied", "Key access is denied");
      }
      if (name === "KMSInvalidStateException") {
        throw await this.classifyInvalidState(keyRef);
      }
      if (name === "NotFoundException") {
        throw new AccountKeyAccessError("key_destroyed", "Key has been destroyed");
      }
      throw new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
  }

  async unwrapDataKey(
    accountId: string,
    keyRef: string,
    wrappedKey: string
  ): Promise<Buffer> {
    await this.assertAccountOwnsKeyRef(accountId, keyRef);
    try {
      const res = await this.client.decrypt({
        CiphertextBlob: Buffer.from(wrappedKey, "base64"),
        KeyId: keyRef,
        EncryptionContext: { swyra_account_id: accountId },
      });
      if (!res.Plaintext) {
        throw new AccountKeyAccessError("provider_outage", "KMS decrypt returned empty plaintext");
      }
      return Buffer.from(res.Plaintext);
    } catch (err) {
      if (err instanceof AccountKeyAccessError) throw err;
      const name = getAwsErrorName(err);
      if (name === "IncorrectKeyException" || name === "InvalidCiphertextException") {
        throw new AccountKeyAccessError("cross_account_denied", "Account does not own this ciphertext");
      }
      if (name === "DisabledException") {
        throw new AccountKeyAccessError("key_denied", "Key access is denied");
      }
      if (name === "KMSInvalidStateException") {
        throw await this.classifyInvalidState(keyRef);
      }
      if (name === "NotFoundException") {
        throw new AccountKeyAccessError("key_destroyed", "Key has been destroyed");
      }
      throw new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
  }

  async denyAccess(
    accountId: string,
    keyRef: string,
    _reason: string
  ): Promise<{ state: "denied"; monotonicSeq: number }> {
    await this.assertAccountOwnsKeyRef(accountId, keyRef);
    const current = await this.getKeyState(accountId, keyRef);
    if (current.state === "scheduled_destruction" || current.state === "destroyed") {
      throw new AccountKeyAccessError(
        current.state === "destroyed" ? "key_destroyed" : "key_scheduled_destruction",
        "Cannot downgrade destruction state to temporary denial"
      );
    }
    try {
      await this.client.disableKey({ KeyId: keyRef });
      return { state: "denied", monotonicSeq: ++this.seqCounter };
    } catch (err) {
      const name = getAwsErrorName(err);
      if (name === "KMSInvalidStateException") {
        throw await this.classifyInvalidState(keyRef);
      }
      if (name === "NotFoundException") {
        throw new AccountKeyAccessError("key_destroyed", "Key has been destroyed");
      }
      throw new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
  }

  async scheduleDestruction(
    accountId: string,
    keyRef: string
  ): Promise<{ state: "scheduled_destruction" | "destroyed"; idempotent: boolean }> {
    await this.assertAccountOwnsKeyRef(accountId, keyRef);
    const current = await this.getKeyState(accountId, keyRef);
    if (current.state === "destroyed") {
      return { state: "destroyed", idempotent: true };
    }
    if (current.state === "scheduled_destruction") {
      return { state: "scheduled_destruction", idempotent: true };
    }
    try {
      await this.client.scheduleKeyDeletion({
        KeyId: keyRef,
        PendingWindowInDays: this.pendingWindowInDays,
      });
      this.seqCounter += 1;
      return { state: "scheduled_destruction", idempotent: false };
    } catch (err) {
      const name = getAwsErrorName(err);
      if (name === "KMSInvalidStateException") {
        const after = await this.getKeyState(accountId, keyRef);
        if (after.state === "scheduled_destruction") {
          return { state: "scheduled_destruction", idempotent: true };
        }
      }
      if (name === "NotFoundException") {
        return { state: "destroyed", idempotent: true };
      }
      throw new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
  }

  async getKeyState(
    accountId: string,
    keyRef: string
  ): Promise<{ state: AccountKeyState; monotonicSeq: number }> {
    await this.assertAccountOwnsKeyRef(accountId, keyRef);
    try {
      const desc = await this.client.describeKey({ KeyId: keyRef });
      return { state: mapKmsState(desc.KeyMetadata), monotonicSeq: ++this.seqCounter };
    } catch (err) {
      if (getAwsErrorName(err) === "NotFoundException") {
        return { state: "destroyed", monotonicSeq: ++this.seqCounter };
      }
      throw new AccountKeyAccessError("provider_outage", "Key provider unavailable");
    }
  }
}
