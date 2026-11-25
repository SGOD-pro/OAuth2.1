import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { csrfHeaders } from "../lib/csrf";
import { getOwnerContextHandle } from "../lib/identityContext";

function parseTotpSecret(uri: string): string {
  if (!uri) return "";
  try {
    return new URL(uri).searchParams.get("secret") || "";
  } catch {
    return "";
  }
}

export function AccountTotpPanel({ totpEnabled, onCompleted }: { totpEnabled: boolean; onCompleted: () => void }) {
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

  function resetFields() {
    setPassword("");
    setCode("");
    setError(null);
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
    setPassword("");
    setCode("");
    setMode("enrolling");
  }

  async function verifyEnrollment() {
    setError(null);
    const res = await fetch("/api/identity/totp/verify", {
      method: "POST", credentials: "include", headers: ctxHeaders(), body: JSON.stringify({ code }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return setError(data.message || data.code || "Invalid TOTP code");
    setPassword("");
    setCode("");
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
    resetFields();
    onCompleted();
  }

  const secret = parseTotpSecret(totpURI);

  return (
    <div className="border-t pt-4 space-y-3">
      <h2 className="text-sm font-medium">Two-Factor Authentication (TOTP)</h2>
      {error ? <p className="text-xs text-destructive" data-testid="totp-error">{error}</p> : null}

      {mode === "idle" && !totpEnabled ? (
        <div className="space-y-2">
          <input
            type="password"
            placeholder="Current password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded border px-3 py-1.5 text-sm bg-background"
            data-testid="totp-password-input"
          />
          <button type="button" onClick={startEnable} className="rounded bg-primary px-3 py-1.5 text-xs text-primary-foreground" data-testid="totp-enable-btn">
            Enable TOTP
          </button>
        </div>
      ) : null}

      {mode === "idle" && totpEnabled ? (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground" data-testid="totp-enabled-badge">TOTP is currently enabled on this account.</p>
          <button type="button" onClick={() => { resetFields(); setMode("disabling"); }} className="rounded border px-3 py-1.5 text-xs" data-testid="totp-start-disable-btn">
            Disable TOTP
          </button>
        </div>
      ) : null}

      {mode === "enrolling" ? (
        <div className="space-y-2">
          {totpURI ? (
            <div className="inline-block rounded bg-white p-2" data-testid="totp-qr-container">
              <QRCodeSVG value={totpURI} size={140} />
            </div>
          ) : null}
          <p className="text-xs text-muted-foreground">Manual setup key: <code data-testid="totp-manual-secret">{secret}</code></p>
          <input
            type="text"
            placeholder="6-digit TOTP code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            className="w-full rounded border px-3 py-1.5 text-sm bg-background"
            data-testid="totp-code-input"
          />
          <div className="flex gap-2">
            <button type="button" onClick={verifyEnrollment} className="rounded bg-primary px-3 py-1.5 text-xs text-primary-foreground" data-testid="totp-verify-btn">
              Verify &amp; Enable
            </button>
            <button type="button" onClick={() => { resetFields(); setTotpURI(""); setBackupCodes([]); setMode("idle"); }} className="rounded border px-3 py-1.5 text-xs" data-testid="totp-cancel-enroll-btn">
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      {mode === "backup" ? (
        <div className="space-y-2" data-testid="totp-backup-codes">
          <p className="text-xs font-medium">Save these backup codes (shown once):</p>
          <pre className="rounded bg-muted p-2 text-xs">{backupCodes.join("\n")}</pre>
          <button type="button" onClick={() => { setMode("idle"); setBackupCodes([]); setTotpURI(""); onCompleted(); }} className="rounded border px-3 py-1.5 text-xs">
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
          <div className="flex gap-2">
            <button type="button" onClick={disableTotp} className="rounded bg-destructive px-3 py-1.5 text-xs text-destructive-foreground" data-testid="totp-confirm-disable-btn">
              Confirm Disable
            </button>
            <button type="button" onClick={() => { resetFields(); setMode("idle"); }} className="rounded border px-3 py-1.5 text-xs" data-testid="totp-cancel-disable-btn">
              Cancel
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
