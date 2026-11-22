import { importJWK } from "jose";
import { getDb } from "../db/mongo";
import { ObjectId } from "mongodb";

interface CachedPublicKey {
  key: any;
  cachedAt: number;
}
const MAX_PUBLIC_KEY_CACHE_SIZE = 50;
const publicKeyCache = new Map<string, CachedPublicKey>();

function setInPublicKeyCache(keyId: string, entry: CachedPublicKey): void {
  if (publicKeyCache.size >= MAX_PUBLIC_KEY_CACHE_SIZE) {
    const oldestKey = publicKeyCache.keys().next().value;
    if (oldestKey) {
      publicKeyCache.delete(oldestKey);
    }
  }
  publicKeyCache.set(keyId, entry);
}

export function clearPublicKeyCacheForTesting(): void {
  publicKeyCache.clear();
}

export async function getIdpPublicKey(kid?: string): Promise<any> {
  const now = Date.now();
  const cacheKey = kid || "latest";
  const cached = publicKeyCache.get(cacheKey);
  if (cached && now - cached.cachedAt < 60_000) {
    return cached.key;
  }

  const database = await getDb();
  let jwksRecord: any = null;
  let matchedRequestedKid = false;

  if (kid) {
    jwksRecord = await database.collection("jwks").findOne({
      $or: [
        { kid: kid },
        { id: kid },
        ...(ObjectId.isValid(kid) ? [{ _id: new ObjectId(kid) }] : []),
      ],
    });
    if (jwksRecord) {
      matchedRequestedKid = true;
    }
  }

  if (!jwksRecord) {
    jwksRecord = await database.collection("jwks").findOne({}, { sort: { createdAt: -1 } });
  }

  if (!jwksRecord || !jwksRecord.publicKey) {
    return null;
  }

  let jwk: any;
  try {
    jwk = typeof jwksRecord.publicKey === "string" ? JSON.parse(jwksRecord.publicKey) : jwksRecord.publicKey;
  } catch {
    return null;
  }

  const importedKey = await importJWK(jwk, "RS256");
  const cacheEntry = { key: importedKey, cachedAt: now };

  // Only cache under the requested kid if it matched, or if no kid was specified (latest)
  if (cacheKey === "latest" || matchedRequestedKid) {
    setInPublicKeyCache(cacheKey, cacheEntry);
  }
  if (jwksRecord.kid) {
    setInPublicKeyCache(jwksRecord.kid, cacheEntry);
  }

  return importedKey;
}
