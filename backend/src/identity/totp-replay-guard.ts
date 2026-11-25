import crypto from "node:crypto";
import type { Db } from "mongodb";
import { symmetricDecrypt } from "better-auth/crypto";
import { ensureIdentityCollectionIndexes } from "../db/indexes";
import { digestToken } from "./registration-crypto";

export class TotpReplayError extends Error {
  constructor(public readonly code: string, public readonly status: number, message: string) {
    super(message);
  }
}

function computeTotpForStep(utf8Secret: string, step: number): string {
  const bytes = Buffer.from(utf8Secret, "utf8");
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const hmac = crypto.createHmac("sha1", bytes).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}

function safeCodeEquals(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Finds the exact TOTP step (-1, 0, +1) matching the supplied code and atomically claims it
 * across all endpoints (enroll, login, disable, admin) without pre-locking invalid guesses.
 * Returns null if the code does not match any step in the current window.
 */
export async function claimMatchedTotpStep(params: {
  database: Db;
  userId: string;
  code: string;
  encryptedSecret: string;
  engineSecret: any;
  session?: any;
}): Promise<number | null> {
  const { database, userId, code, encryptedSecret, engineSecret, session } = params;
  await ensureIdentityCollectionIndexes(database);

  let decryptedSecret = encryptedSecret;
  try {
    decryptedSecret = await symmetricDecrypt({ key: engineSecret, data: encryptedSecret });
  } catch {
    // Some test fixtures or legacy rows may store plaintext base32; fall through safely.
  }

  const normalizedCode = code.trim();
  const baseStep = Math.floor(Date.now() / 1000 / 30);
  let matchedStep: number | null = null;
  for (const offset of [0, -1, 1]) {
    const candidateStep = baseStep + offset;
    const expected = computeTotpForStep(decryptedSecret, candidateStep);
    if (safeCodeEquals(normalizedCode, expected)) {
      matchedStep = candidateStep;
      break;
    }
  }

  if (matchedStep === null) {
    return null;
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);
  const secretDigest = digestToken(encryptedSecret);
  try {
    await database.collection("totp_used_steps").insertOne(
      { userId, step: matchedStep, secretDigest, createdAt: now, expiresAt },
      session ? { session } : {}
    );
  } catch (err: any) {
    if (err?.code === 11000) {
      throw new TotpReplayError("ERR_TOTP_REPLAY", 409, "TOTP code already used for this time step");
    }
    throw err;
  }

  return matchedStep;
}

export async function releaseTotpTimeStep(database: Db, userId: string, step: number | null, encryptedSecret?: string): Promise<void> {
  if (step === null) return;
  const filter: any = { userId, step };
  if (encryptedSecret) filter.secretDigest = digestToken(encryptedSecret);
  await database.collection("totp_used_steps").deleteOne(filter).catch(() => {});
}
