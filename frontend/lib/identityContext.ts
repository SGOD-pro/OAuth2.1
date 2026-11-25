import { csrfHeaders } from "./csrf";

// Tab-scoped in-memory handle only; never persisted to localStorage or sessionStorage.
let activeOwnerContextHandle: string | null = null;

export function getOwnerContextHandle(): string | null {
  return activeOwnerContextHandle;
}

export function clearOwnerContextHandle(): void {
  activeOwnerContextHandle = null;
}

export async function issueOwnerContext(entryId: string): Promise<{
  contextHandle: string;
  expiresAt: string;
  purpose: string;
  account: { entryId: string; label: string };
}> {
  const res = await fetch("/api/identity/contexts", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...csrfHeaders() },
    body: JSON.stringify({ entryId, purpose: "owner_dashboard" }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.contextHandle) {
    throw new Error(data.message || data.code || "Failed to issue owner dashboard context");
  }
  activeOwnerContextHandle = data.contextHandle;
  return data;
}

export async function fetchOwnerContextMe(): Promise<{
  entryId: string;
  userId: string;
  label: string;
  purpose: string;
  expiresAt: string;
}> {
  if (!activeOwnerContextHandle) {
    throw new Error("NO_ACTIVE_CONTEXT");
  }
  const res = await fetch("/api/identity/contexts/me", {
    method: "GET",
    credentials: "include",
    headers: { "X-Identity-Context": activeOwnerContextHandle },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) activeOwnerContextHandle = null;
    throw new Error(data.code || "ERR_CONTEXT_INVALID");
  }
  return data;
}
