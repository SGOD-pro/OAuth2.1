import {
  normalizeOrigin,
  deriveAllowedOriginsFromRedirectUris,
} from "../utils/security";

/**
 * Extracts all unique normalized web origins from an OAuth client document
 * or update payload, including explicit allowed origins and origins derived
 * from redirect URIs.
 */
export function extractClientOrigins(client: any): string[] {
  if (!client || typeof client !== "object") return [];
  const origins = new Set<string>();

  const rawAllowed = [
    ...(Array.isArray(client.allowedOrigins) ? client.allowedOrigins : []),
    ...(Array.isArray(client.allowed_origins) ? client.allowed_origins : []),
  ];
  for (const raw of rawAllowed) {
    if (typeof raw === "string") {
      let normalized = normalizeOrigin(raw);
      if (!normalized) {
        try {
          const parsed = new URL(raw);
          if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            normalized = normalizeOrigin(parsed.origin);
          }
        } catch {
          // ignore invalid URLs
        }
      }
      if (normalized) origins.add(normalized);
    }
  }

  const rawRedirects = [
    ...(Array.isArray(client.redirectUris) ? client.redirectUris : []),
    ...(Array.isArray(client.redirect_uris) ? client.redirect_uris : []),
  ];
  const derived = deriveAllowedOriginsFromRedirectUris(rawRedirects);
  for (const d of derived) {
    const normalized = normalizeOrigin(d);
    if (normalized) origins.add(normalized);
  }

  return Array.from(origins);
}
