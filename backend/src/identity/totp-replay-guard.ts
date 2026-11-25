import crypto from "node:crypto";
import type { Db } from "mongodb";
import { ensureIdentityCollectionIndexes } from "../db/indexes";

export class TotpReplayError extends Error {
  constructor(public readonly code: string, public readonly status: number, message: string) {
    super(message);
  }
}

export function computeTotpForStep(base32Secret: string, step: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of base32Secret.toUpperCase().replace(/=+$/, "")) {
    const val = alphabet.indexOf(c);
    if (val >= 0) bits += val.toString(2).padStart(5, "0");
  }
  const bytes = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
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

export async function claimTotpTimeStep(params: {
  database: Db;
  userId: string;
  purpose: "enroll" | "login" | "disable";
  session?: any;
}): Promise<number> {
  const { database, userId, purpose, session } = params;
  await ensureIdentityCollectionIndexes(database);

  const step = Math.floor(Date.now() / 1000 / 30);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);
  try {
    await database.collection("totp_used_steps").insertOne(
      { userId, step, purpose, createdAt: now, expiresAt },
      session ? { session } : {}
    );
  } catch (err: any) {
    if (err?.code === 11000) {
      throw new TotpReplayError("ERR_TOTP_REPLAY", 409, "TOTP code already used for this time step");
    }
    throw err;
  }

  return step;
}

export async function releaseTotpTimeStep(database: Db, userId: string, step: number, purpose: "enroll" | "login" | "disable"): Promise<void> {
  await database.collection("totp_used_steps").deleteOne({ userId, step, purpose }).catch(() => {});
}
