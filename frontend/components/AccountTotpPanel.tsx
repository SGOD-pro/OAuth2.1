import { useState } from "react";
import { csrfHeaders } from "../lib/csrf";
import { getOwnerContextHandle } from "../lib/identityContext";

export function AccountTotpPanel({ onCompleted }: { onCompleted: () => void }) {
  const [mode, setMode] = useState<"idle" | "enrolling" | "backup" | "disabling">("idle");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [totpURI, setTotpURI] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  function ctxHeaders(): Record<string, string> {
    const h = getOwnerContextHandle();
    return { "Content-Type": "application/json", ...csrfHeaders(), ...(h ? { "X-Identity-Context": h } : {}) };
  }

  async function startEnable() {
    setError(null);
    const res = await fetch("/api/identity/totp/enable", {
      method: "POST", credentials: "include", headers: ctxHeaders(), body: JSON.stringify({ password }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return setError(data.message || data.code || "Failed to start TOTP enrollment");
    setTotpURI(data.totpURI || "");
    setBackupCodes(Array.isArray(data.backupCodes) ? data.backupCodes : []);
    setMode("enrolling");
  }

  async function verifyEnrollment() {
    setError(null);
    const res = await fetch("/api/identity/totp/verify", {
      method: "POST", credentials: "include", headers: ctxHeaders(), body: JSON.stringify({ code }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return setError(data.message || data.code || "Invalid TOTP code");
    setMode("backup");
  }

  async function disableTotp() {
    setError(null);
    const res = await fetch("/api/identity/totp/disable", {
      method: "POST", credentials: "include", headers: ctxHeaders(), body: JSON.stringify({ password, code }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return setError(data.message || data.code || "Failed to disable TOTP");
    setMode("idle");
    setPassword("");
    setCode("");
    onCompleted();
  }

  const secret = totpURI ? new URL(totpURI).searchParams.get("secret") || "" : "";

  return (
    <div className="border-t pt-4 space-y-3">
      <h2 className="text-sm font-medium">Two-Factor Authentication (TOTP)</h2>
      {error ? <p className="text-xs text-destructive" data-testid="totp-error">{error}</p> : null}

      {mode === "idle" ? (
        <div className="space-y-2">
          <input
            type="password"
            placeholder="Current password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded border px-3 py-1.5 text-sm bg-background"
            data-testid="totp-password-input"
          />
          <div className="flex gap-2">
            <button type="button" onClick={startEnable} className="rounded bg-primary px-3 py-1.5 text-xs text-primary-foreground" data-testid="totp-enable-btn">
              Enable TOTP
            </button>
            <button type="button" onClick={() => setMode("disabling")} className="rounded border px-3 py-1.5 text-xs" data-testid="totp-start-disable-btn">
              Disable TOTP
            </button>
          </div>
        </div>
      ) : null}

      {mode === "enrolling" ? (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">Manual setup key: <code data-testid="totp-manual-secret">{secret}</code></p>
          <input
            type="text"
            placeholder="6-digit TOTP code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            className="w-full rounded border px-3 py-1.5 text-sm bg-background"
            data-testid="totp-code-input"
          />
          <button type="button" onClick={verifyEnrollment} className="rounded bg-primary px-3 py-1.5 text-xs text-primary-foreground" data-testid="totp-verify-btn">
            Verify &amp; Enable
          </button>
        </div>
      ) : null}

      {mode === "backup" ? (
        <div className="space-y-2" data-testid="totp-backup-codes">
          <p className="text-xs font-medium">Save these backup codes (shown once):</p>
          <pre className="rounded bg-muted p-2 text-xs">{backupCodes.join("\n")}</pre>
          <button type="button" onClick={() => { setMode("idle"); onCompleted(); }} className="rounded border px-3 py-1.5 text-xs">
            Done
          </button>
        </div>
      ) : null}

      {mode === "disabling" ? (
        <div className="space-y-2">
          <input
            type="password"
            placeholder="Current password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded border px-3 py-1.5 text-sm bg-background"
            data-testid="totp-disable-password"
          />
          <input
            type="text"
            placeholder="6-digit TOTP code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            className="w-full rounded border px-3 py-1.5 text-sm bg-background"
            data-testid="totp-disable-code"
          />
          <button type="button" onClick={disableTotp} className="rounded bg-destructive px-3 py-1.5 text-xs text-destructive-foreground" data-testid="totp-confirm-disable-btn">
            Confirm Disable
          </button>
        </div>
      ) : null}
    </div>
  );
}
