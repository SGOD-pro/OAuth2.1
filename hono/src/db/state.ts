import { getDb } from "./mongo";

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

interface RateLimitDoc {
  _id: string;
  count: number;
  createdAt: Date;
}

interface OriginCacheDoc {
  _id: string;
  allowed: boolean;
  cachedAt: Date;
}

let indexPromise: Promise<void> | null = null;

async function ensureTtlIndexes(): Promise<void> {
  indexPromise ??= (async () => {
    const db = await getDb();

    await Promise.all([
      db
        .collection<RateLimitDoc>("rate_limits")
        .createIndex({ createdAt: 1 }, { expireAfterSeconds: 60 }),
      db
        .collection<OriginCacheDoc>("origin_cache")
        .createIndex({ cachedAt: 1 }, { expireAfterSeconds: 300 }),
    ]);
  })();

  return indexPromise;
}

export async function incrementRateLimit(
  ip: string,
  now: number,
  windowMs: number,
): Promise<RateLimitEntry> {
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

export async function getOriginCache(
  origin: string,
): Promise<boolean | null> {
  await ensureTtlIndexes();

  const db = await getDb();
  const entry = await db
    .collection<OriginCacheDoc>("origin_cache")
    .findOne({ _id: `ORIGIN#${origin}` });

  return entry?.allowed ?? null;
}

export async function putOriginCache(
  origin: string,
  allowed: boolean,
): Promise<void> {
  await ensureTtlIndexes();

  const db = await getDb();
  await db.collection<OriginCacheDoc>("origin_cache").updateOne(
    { _id: `ORIGIN#${origin}` },
    {
      $set: {
        allowed,
        cachedAt: new Date(),
      },
    },
    { upsert: true },
  );
}

export async function invalidateOriginCache(
  origins?: string[],
): Promise<void> {
  await ensureTtlIndexes();

  const db = await getDb();
  const collection = db.collection<OriginCacheDoc>("origin_cache");

  if (origins && origins.length > 0) {
    await collection.deleteMany({
      _id: { $in: origins.map((origin) => `ORIGIN#${origin}`) },
    });
    return;
  }

  await collection.deleteMany({ _id: /^ORIGIN#/ });
}
