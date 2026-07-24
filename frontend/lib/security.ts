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
  return !import.meta.env.PROD || import.meta.env.VITE_PUBLIC_SIGNUP_ENABLED === 'true';
}
