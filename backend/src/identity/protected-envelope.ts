import crypto from "node:crypto";
import type { AccountKeyProvider } from "./account-key-provider";

export interface ProtectedEnvelope {
  alg: "AES-256-GCM";
  keyRef: string;
  wrappedKey: string;
  keyVersion: number;
  nonce: string;
  ciphertext: string;
  tag: string;
  schemaVersion: number;
}

export class ProtectedFieldError extends Error {
  constructor(
    public readonly code: "invalid_envelope" | "decrypt_failed" | "profile_not_found",
    message: string
  ) {
    super(message);
    this.name = "ProtectedFieldError";
  }
}

function buildCanonicalAad(params: {
  accountId: string;
  collection: string;
  recordId: string;
  fieldPurpose: string;
  schemaVersion: number;
  keyVersion: number;
}): Buffer {
  return Buffer.from(
    JSON.stringify([
      params.accountId,
      params.collection,
      params.recordId,
      params.fieldPurpose,
      params.schemaVersion,
      params.keyVersion,
    ]),
    "utf8"
  );
}

/**
 * Seals a single field under a fresh per-field 256-bit DEK wrapped by AccountKeyProvider.
 */
export async function sealProtectedField(params: {
  provider: AccountKeyProvider;
  accountId: string;
  collection: string;
  recordId: string;
  fieldPurpose: string;
  plaintext: string;
  schemaVersion?: number;
  keyVersion?: number;
}): Promise<ProtectedEnvelope> {
  const schemaVersion = params.schemaVersion ?? 1;
  const keyVersion = params.keyVersion ?? 1;
  const dek = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const wrapped = await params.provider.wrapDataKey(params.accountId, dek);

  try {
    const cipher = crypto.createCipheriv("aes-256-gcm", dek, nonce);
    cipher.setAAD(
      buildCanonicalAad({
        accountId: params.accountId,
        collection: params.collection,
        recordId: params.recordId,
        fieldPurpose: params.fieldPurpose,
        schemaVersion,
        keyVersion,
      })
    );
    const ct = Buffer.concat([cipher.update(params.plaintext, "utf8"), cipher.final()]);
    return {
      alg: "AES-256-GCM",
      keyRef: wrapped.keyRef,
      wrappedKey: wrapped.wrappedKey,
      keyVersion,
      nonce: nonce.toString("base64url"),
      ciphertext: ct.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
      schemaVersion,
    };
  } finally {
    dek.fill(0);
  }
}

/**
 * Unwraps the DEK through AccountKeyProvider and verifies canonical AAD + GCM tag.
 */
export async function openProtectedField(params: {
  provider: AccountKeyProvider;
  accountId: string;
  collection: string;
  recordId: string;
  fieldPurpose: string;
  envelope: ProtectedEnvelope;
}): Promise<string> {
  const env = params.envelope;
  if (!env || env.alg !== "AES-256-GCM" || !env.keyRef || !env.wrappedKey || !env.nonce || !env.tag) {
    throw new ProtectedFieldError("invalid_envelope", "Malformed protected field envelope");
  }

  const dek = await params.provider.unwrapDataKey(params.accountId, env.keyRef, env.wrappedKey);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", dek, Buffer.from(env.nonce, "base64url"));
    decipher.setAAD(
      buildCanonicalAad({
        accountId: params.accountId,
        collection: params.collection,
        recordId: params.recordId,
        fieldPurpose: params.fieldPurpose,
        schemaVersion: env.schemaVersion,
        keyVersion: env.keyVersion,
      })
    );
    decipher.setAuthTag(Buffer.from(env.tag, "base64url"));
    const pt = Buffer.concat([decipher.update(Buffer.from(env.ciphertext, "base64url")), decipher.final()]);
    return pt.toString("utf8");
  } catch (err) {
    if (err instanceof ProtectedFieldError) throw err;
    throw new ProtectedFieldError("decrypt_failed", "Protected field authentication failed");
  } finally {
    dek.fill(0);
  }
}
