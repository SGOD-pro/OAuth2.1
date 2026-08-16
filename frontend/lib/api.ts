export const API_BASE = import.meta.env.VITE_AUTH_URL?.replace(/\/$/, '') || '';

export function getApiUrl(path: string) {
  // If we are in the browser, always use relative paths so they go through the Vite/Vercel proxy.
  if (typeof window !== 'undefined') {
    return path;
  }
  const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:3000';
  return `${baseUrl}${path}`;
}

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const url = getApiUrl(path);
  return fetch(url, {
    ...init,
    credentials: 'include',
  });
}
