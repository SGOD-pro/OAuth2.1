export function validateUri(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
    if (value.includes('*')) return false;
    if (url.username || url.password) return false;
    if (!url.hostname) return false;
    return true;
  } catch {
    return false;
  }
}

export function safeCallbackURL(value: string | null): string | undefined {
  if (!value || !value.startsWith('/') || value.startsWith('//')) return undefined;

  try {
    const url = new URL(value, 'https://callback.invalid');
    if (url.origin !== 'https://callback.invalid') return undefined;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return undefined;
  }
}

export function isStrongPassword(password: string): boolean {
  if (password.length < 12 || password.length > 128) return false;
  return (
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

export function isPublicSignupEnabled(): boolean {
  return import.meta.env.VITE_PUBLIC_SIGNUP_ENABLED !== 'false';
}

/**
 * Extract unique, valid web origins (protocol + host + optional port)
 * from registered HTTP and HTTPS OAuth redirect URIs. Non-web schemes
 * (such as custom native mobile schemes) are safely skipped.
 */
export function deriveOrigins(uris: string[]): string[] {
  if (!Array.isArray(uris)) return [];
  const origins = new Set<string>();
  for (const uri of uris) {
    if (!uri || typeof uri !== 'string') continue;
    try {
      const parsed = new URL(uri.trim());
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        if (parsed.origin && parsed.origin !== 'null') {
          origins.add(parsed.origin);
        }
      }
    } catch {
      // Safely ignore non-web or malformed URIs
    }
  }
  return Array.from(origins);
}

