import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  DeleteCommand,
  ScanCommand,
} from "@aws-sdk/lib-dynamodb";
import { config } from "../config";

const raw = new DynamoDBClient({ region: config.dynamodb.region });
const ddb = DynamoDBDocumentClient.from(raw);
const TableName = config.dynamodb.table;

// ── Rate Limit ──────────────────────────────────────────

interface RateLimitEntry {
  count: number;
  resetAt: number; // epoch ms
}

export async function getRateLimit(ip: string): Promise<RateLimitEntry | null> {
  const { Item } = await ddb.send(
    new GetCommand({ TableName, Key: { pk: `RATE#${ip}` } }),
  );
  if (!Item) return null;
  return { count: Item["count"] as number, resetAt: Item["resetAt"] as number };
}

export async function putRateLimit(
  ip: string,
  count: number,
  resetAt: number,
): Promise<void> {
  await ddb.send(
    new PutCommand({
      TableName,
      Item: {
        pk: `RATE#${ip}`,
        count,
        resetAt,
        ttl: Math.ceil(resetAt / 1000), // DynamoDB TTL is epoch seconds
      },
    }),
  );
}

// ── Origin Cache ────────────────────────────────────────

const ORIGIN_TTL_SEC = 300; // 5 minutes, matches previous LRU TTL

export async function getOriginCache(
  origin: string,
): Promise<boolean | null> {
  const { Item } = await ddb.send(
    new GetCommand({ TableName, Key: { pk: `ORIGIN#${origin}` } }),
  );
  if (!Item) return null;
  return Item["allowed"] as boolean;
}

export async function putOriginCache(
  origin: string,
  allowed: boolean,
): Promise<void> {
  await ddb.send(
    new PutCommand({
      TableName,
      Item: {
        pk: `ORIGIN#${origin}`,
        allowed,
        ttl: Math.ceil(Date.now() / 1000) + ORIGIN_TTL_SEC,
      },
    }),
  );
}

/**
 * Invalidate origin cache entries.
 * If origins are provided, deletes those specific keys.
 * Otherwise, scans all ORIGIN# keys and deletes them.
 * ponytail: full-table scan is acceptable here — single-tenant, small table by construction (design.md).
 */
export async function invalidateOriginCache(
  origins?: string[],
): Promise<void> {
  if (origins && origins.length > 0) {
    await Promise.all(
      origins.map((o) =>
        ddb.send(new DeleteCommand({ TableName, Key: { pk: `ORIGIN#${o}` } })),
      ),
    );
    return;
  }

  // Wholesale invalidation — bounded scan
  // ponytail: Scan is acceptable — single-tenant, small table by construction (design.md).
  const { Items } = await ddb.send(
    new ScanCommand({
      TableName,
      FilterExpression: "begins_with(pk, :prefix)",
      ExpressionAttributeValues: { ":prefix": "ORIGIN#" },
    }),
  );

  if (Items && Items.length > 0) {
    await Promise.all(
      Items.map((item) =>
        ddb.send(new DeleteCommand({ TableName, Key: { pk: item["pk"] as string } })),
      ),
    );
  }
}
