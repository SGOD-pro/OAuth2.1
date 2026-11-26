import { useCallback, useEffect, useState } from "react";
import { getOwnerContextHandle } from "../lib/identityContext";
import { getCsrfToken } from "../lib/csrf";

function contextHeaders(): Record<string, string> {
  const h = getOwnerContextHandle();
  return h ? { "X-Identity-Context": h } : {};
}

interface OwnerSession {
  sessionId: string;
  current: boolean;
  label: string;
  createdAt: string | null;
  status: string;
}

interface ConnectedApp {
  clientId: string;
  name: string;
  scopes: string[];
  status: string;
}

export function AccountSessionsAppsPanel() {
  const [sessions, setSessions] = useState<OwnerSession[]>([]);
  const [apps, setApps] = useState<ConnectedApp[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setError(null);
    const headers = contextHeaders();
    const [sRes, aRes] = await Promise.all([
      fetch("/api/identity/sessions", { credentials: "include", headers }),
      fetch("/api/identity/apps", { credentials: "include", headers }),
    ]);
    if (sRes.ok) {
      const sJson = await sRes.json();
      setSessions(Array.isArray(sJson.sessions) ? sJson.sessions : []);
    }
    if (aRes.ok) {
      const aJson = await aRes.json();
      setApps(Array.isArray(aJson.apps) ? aJson.apps : []);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  async function revokeSession(sessionId: string) {
    setBusyId(sessionId);
    setError(null);
    try {
      const csrf = await getCsrfToken();
      const res = await fetch(`/api/identity/sessions/${encodeURIComponent(sessionId)}/revoke`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "x-csrf-token": csrf || "", ...contextHeaders() },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        setError(body?.message || "Failed to revoke session");
        return;
      }
      await loadData();
    } finally {
      setBusyId(null);
    }
  }

  async function disconnectApp(clientId: string) {
    setBusyId(clientId);
    setError(null);
    try {
      const csrf = await getCsrfToken();
      const res = await fetch(`/api/identity/apps/${encodeURIComponent(clientId)}/disconnect`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "x-csrf-token": csrf || "", ...contextHeaders() },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        setError(body?.message || "Failed to disconnect app");
        return;
      }
      await loadData();
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="space-y-4 border-t pt-4">
      {error && <p className="text-xs text-destructive" data-testid="portal-error">{error}</p>}
      <div className="space-y-2" data-testid="owner-sessions-section">
        <h2 className="text-sm font-medium">Sessions</h2>
        {sessions.length === 0 ? (
          <p className="text-xs text-muted-foreground">No active sessions.</p>
        ) : (
          <ul className="space-y-1.5">
            {sessions.map((s) => (
              <li key={s.sessionId} className="flex items-center justify-between rounded border px-2.5 py-1.5 text-xs" data-testid={`session-row-${s.sessionId}`}>
                <div>
                  <span className="font-medium">{s.label}</span>{" "}
                  <span className="text-muted-foreground">({s.current ? "current" : s.status})</span>
                </div>
                <button
                  type="button"
                  disabled={busyId === s.sessionId}
                  onClick={() => void revokeSession(s.sessionId)}
                  className="rounded border px-2 py-0.5 text-xs hover:bg-muted"
                  data-testid={`revoke-session-${s.sessionId}`}
                >
                  Revoke
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="space-y-2" data-testid="owner-apps-section">
        <h2 className="text-sm font-medium">Connected Apps</h2>
        {apps.length === 0 ? (
          <p className="text-xs text-muted-foreground">No connected apps.</p>
        ) : (
          <ul className="space-y-1.5">
            {apps.map((a) => (
              <li key={a.clientId} className="flex items-center justify-between rounded border px-2.5 py-1.5 text-xs" data-testid={`app-row-${a.clientId}`}>
                <div>
                  <span className="font-medium">{a.name}</span>{" "}
                  <span className="text-muted-foreground">({a.status})</span>
                </div>
                <button
                  type="button"
                  disabled={busyId === a.clientId}
                  onClick={() => void disconnectApp(a.clientId)}
                  className="rounded border px-2 py-0.5 text-xs hover:bg-muted"
                  data-testid={`disconnect-app-${a.clientId}`}
                >
                  Disconnect
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
