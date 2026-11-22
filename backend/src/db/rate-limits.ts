import { getDb } from "./mongo";
import { ensureTtlIndexes } from "./indexes";

export interface RateLimitEntry {
  count: number;
  resetAt: number;
}

export interface RateLimitDoc {
  _id: string;
  count: number;
  createdAt: Date;
}

let rateLimitStoreFailureSimulated = false;

export function __simulateRateLimitStoreFailure(enable: boolean): void {
  rateLimitStoreFailureSimulated = enable;
}

export async function incrementRateLimit(
  ip: string,
  now: number,
  windowMs: number,
): Promise<RateLimitEntry> {
  if (rateLimitStoreFailureSimulated) {
    throw new Error("Simulated rate limit backing store failure / database connection failure");
  }

  await ensureTtlIndexes();

  const db = await getDb();
  const createdAt = new Date(now);
  const cutoff = new Date(now - windowMs);
  const resetAt = now + windowMs;

  const result = await db.collection<RateLimitDoc>("rate_limits").findOneAndUpdate(
    { _id: `RATE#${ip}` },
    [
      {
        $set: {
          count: {
            $cond: [
              { $gt: ["$createdAt", cutoff] },
              { $add: [{ $ifNull: ["$count", 0] }, 1] },
              1,
            ],
          },
          createdAt: {
            $cond: [{ $gt: ["$createdAt", cutoff] }, "$createdAt", createdAt],
          },
        },
      },
    ],
    { upsert: true, returnDocument: "after" },
  );

  return {
    count: result?.count ?? 1,
    resetAt:
      (result?.createdAt?.getTime() ?? createdAt.getTime()) + windowMs,
  };
}
