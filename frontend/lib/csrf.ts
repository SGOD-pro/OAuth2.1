export function getCsrfToken(): string | null {
  const match = document.cookie
    .split("; ")
    .find((row) => row.startsWith("csrf_token="));
  return match ? decodeURIComponent(match.split("=")[1]) : null;
}

export function csrfHeaders(): Record<string, string> {
  const token = getCsrfToken();
  if (!token) return {};
  return { "x-csrf-token": token };
}
