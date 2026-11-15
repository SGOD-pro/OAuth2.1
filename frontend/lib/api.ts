const metaEnv = (typeof import.meta !== 'undefined' && (import.meta as unknown as { env?: Record<string, string | undefined> }).env) || {};
const nodeProcess = typeof globalThis !== 'undefined' ? (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process : undefined;
const nodeEnv = nodeProcess?.env || {};

export function getApiUrl(path: string) {
  // If we are in the browser, always use relative paths so they go through the Vite/Vercel proxy.
  if (typeof window !== 'undefined') {
    return path;
  }
  const baseUrl = metaEnv.VITE_API_URL || nodeEnv.VITE_API_URL;
  if (!baseUrl) {
    const isProd = metaEnv.PROD || metaEnv.MODE === 'production' || nodeEnv.NODE_ENV === 'production';
    if (isProd) {
      throw new Error('VITE_API_URL is required in production non-browser environments');
    }
    return `http://127.0.0.1:3000${path}`;
  }
  return `${baseUrl}${path}`;
}

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const url = getApiUrl(path);
  return fetch(url, {
    ...init,
    credentials: 'include',
  });
}
