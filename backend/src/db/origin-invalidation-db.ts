import { getDb } from "./mongo";
import { ensureTtlIndexes } from "./indexes";
import { OriginCacheDoc } from "./origin-state";

export async function invalidateOriginCache(
  origins?: string[],
  version?: number,
): Promise<void> {
  await ensureTtlIndexes();

  const db = await getDb();
  const collection = db.collection<OriginCacheDoc>("origin_cache");
  const now = new Date();

  if (origins && origins.length > 0) {
    const operations: any[] = [];
    for (const origin of origins) {
      operations.push({
        updateOne: {
          filter: { _id: `ORIGIN_INV#${origin}` },
          update: {
            $set: {
              updatedAt: now,
            },
            $unset: {
              cachedAt: "",
            },
            ...(typeof version === "number" && version > 0
              ? { $max: { invalidatedVersion: version } }
              : {}),
          },
          upsert: true,
        },
      });

      operations.push({
        updateOne: {
          filter: { _id: `ORIGIN#${origin}` },
          update: {
            $set: {
              allowed: null,
            },
            $unset: {
              cachedAt: "",
            },
            ...(typeof version === "number" && version > 0
              ? { $max: { invalidatedVersion: version } }
              : {}),
          },
          upsert: true,
        },
      });
    }

    if (typeof collection.bulkWrite === "function") {
      await collection.bulkWrite(operations, { ordered: false });
    } else {
      for (const op of operations) {
        await collection.updateOne(op.updateOne.filter, op.updateOne.update, { upsert: op.updateOne.upsert });
      }
    }
    return;
  }

  // Global invalidation
  await collection.updateOne(
    { _id: "ORIGIN#__GLOBAL_TOMBSTONE__" },
    {
      $set: { allowed: null, updatedAt: now },
      $unset: { cachedAt: "" },
      ...(typeof version === "number" && version > 0
        ? { $max: { invalidatedVersion: version } }
        : {}),
    },
    { upsert: true },
  );

  await collection.updateMany(
    { _id: /^ORIGIN#https?:\/\// },
    {
      $set: { allowed: null },
      $unset: { cachedAt: "" },
      ...(typeof version === "number" && version > 0
        ? { $max: { invalidatedVersion: version } }
        : {}),
    },
  );

  await collection.updateMany(
    { _id: /^ORIGIN_INV#https?:\/\// },
    {
      $set: { updatedAt: now },
      $unset: { cachedAt: "" },
      ...(typeof version === "number" && version > 0
        ? { $max: { invalidatedVersion: version } }
        : {}),
    },
  );
}
