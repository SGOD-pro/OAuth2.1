import crypto from "node:crypto";

export interface UsernameBloomOptions {
  expectedItems: number;
  falsePositiveRate: number;
  maxAgeMs: number;
}

export class UsernameBloomFilter {
  public readonly bitCount: number;
  public readonly hashCount: number;
  public readonly maxAgeMs: number;
  private readonly bits: Uint8Array;
  private builtAtMs = 0;
  private invalidated = false;

  constructor(options: UsernameBloomOptions) {
    const n = Math.max(1, options.expectedItems);
    const p = Math.min(0.99, Math.max(1e-6, options.falsePositiveRate));
    this.bitCount = Math.max(8, Math.ceil((-n * Math.log(p)) / (Math.LN2 * Math.LN2)));
    this.hashCount = Math.max(1, Math.round((this.bitCount / n) * Math.LN2));
    this.maxAgeMs = Math.max(0, options.maxAgeMs);
    this.bits = new Uint8Array(Math.ceil(this.bitCount / 8));
  }

  private indexes(normalizedUsername: string): number[] {
    const digest = crypto.createHash("sha256").update(normalizedUsername, "utf8").digest();
    const h1 = digest.readUInt32BE(0);
    const h2 = digest.readUInt32BE(4) | 1;
    const out: number[] = [];
    for (let i = 0; i < this.hashCount; i++) {
      const combined = (h1 + i * h2) >>> 0;
      out.push(combined % this.bitCount);
    }
    return out;
  }

  markFresh(nowMs = Date.now()): void {
    this.builtAtMs = nowMs;
    this.invalidated = false;
  }

  invalidate(): void {
    this.invalidated = true;
  }

  isFresh(nowMs = Date.now()): boolean {
    return !this.invalidated && this.builtAtMs > 0 && nowMs - this.builtAtMs <= this.maxAgeMs;
  }

  add(normalizedUsername: string): void {
    for (const bit of this.indexes(normalizedUsername)) {
      this.bits[bit >>> 3] |= 1 << (bit & 7);
    }
  }

  mightContain(normalizedUsername: string): boolean {
    for (const bit of this.indexes(normalizedUsername)) {
      if ((this.bits[bit >>> 3] & (1 << (bit & 7))) === 0) {
        return false;
      }
    }
    return true;
  }

  memoryBytes(): number {
    return this.bits.byteLength;
  }
}

export type UsernameCheckPath =
  | "bloom_negative"
  | "mongo_confirm_taken"
  | "mongo_confirm_available"
  | "mongo_fallback_stale";

/**
 * Checks normalized username availability.
 * Uses negative fast path only when Bloom filter freshness is proven; always confirms positives in MongoDB.
 */
export async function checkUsernameAvailability(params: {
  database: any;
  normalizedUsername: string;
  keyedLookup: string;
  bloomFilter?: UsernameBloomFilter;
  nowMs?: number;
}): Promise<{ available: boolean; path: UsernameCheckPath; mongoQueries: number }> {
  const nowMs = params.nowMs ?? Date.now();
  const fresh = Boolean(params.bloomFilter && params.bloomFilter.isFresh(nowMs));
  if (fresh && !params.bloomFilter!.mightContain(params.normalizedUsername)) {
    return { available: true, path: "bloom_negative", mongoQueries: 0 };
  }

  const taken = await params.database.collection("identity_lookup").findOne(
    { kind: "username", keyVersion: 1, keyedLookup: params.keyedLookup },
    { projection: { _id: 1 } }
  );
  if (!fresh) {
    return { available: !taken, path: "mongo_fallback_stale", mongoQueries: 1 };
  }
  return {
    available: !taken,
    path: taken ? "mongo_confirm_taken" : "mongo_confirm_available",
    mongoQueries: 1,
  };
}
