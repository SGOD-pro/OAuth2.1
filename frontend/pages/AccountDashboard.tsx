import { useCallback, useEffect, useState } from "react";
import { AccountChooser, type BrowserAccountEntry } from "../components/AccountChooser";
import { AccountTotpPanel } from "../components/AccountTotpPanel";
import { AccountSessionsAppsPanel } from "../components/AccountSessionsAppsPanel";
import { csrfHeaders } from "../lib/csrf";
import { clearOwnerContextHandle, fetchOwnerContextMe, issueOwnerContext } from "../lib/identityContext";

export default function AccountDashboard() {
  const [account, setAccount] = useState<{ entryId: string; userId: string; label: string; expiresAt: string; totpEnabled?: boolean } | null>(null);
  const [accounts, setAccounts] = useState<BrowserAccountEntry[]>([]);
  const [selectingEntryId, setSelectingEntryId] = useState<string | null>(null);
  const [signingOutEntryId, setSigningOutEntryId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadAccounts = useCallback(async () => {
    const res = await fetch("/api/identity/accounts", { credentials: "include" });
    const data = await res.json().catch(() => ({}));
    if (res.ok && Array.isArray(data.accounts)) setAccounts(data.accounts);
  }, []);

  useEffect(() => {
    fetchOwnerContextMe()
      .then((me) => setAccount(me))
      .catch(() => {
        setAccount(null);
        void loadAccounts();
      });
  }, [loadAccounts]);

  async function handleSelect(entryId: string) {
    setError(null);
    setSelectingEntryId(entryId);
    try {
      await issueOwnerContext(entryId);
      const me = await fetchOwnerContextMe();
      setAccount(me);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Unable to open account dashboard");
    } finally {
      setSelectingEntryId(null);
    }
  }

  async function handleSignOut(entryId: string) {
    setSigningOutEntryId(entryId);
    try {
      await fetch("/api/identity/accounts/sign-out", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ entryId }),
      });
      await loadAccounts();
    } finally {
      setSigningOutEntryId(null);
    }
  }

  if (!account) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-background">
        <div className="w-full max-w-md space-y-3">
          <AccountChooser
            accounts={accounts}
            selectingEntryId={selectingEntryId}
            signingOutEntryId={signingOutEntryId}
            error={error}
            onSelectAccount={handleSelect}
            onSignOutAccount={handleSignOut}
            onSignInAgain={() => {
              window.location.href = "/signin?redirect_to=%2Faccount";
            }}
            onUseAnotherAccount={() => {
              window.location.href = "/signin?redirect_to=%2Faccount";
            }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-background">
      <div className="w-full max-w-md rounded-lg border bg-card p-6 space-y-4">
        <h1 className="text-lg font-semibold">Account Dashboard</h1>
        <p className="text-sm text-muted-foreground" data-testid="dashboard-account-label">
          Signed in as <span className="font-medium text-foreground">{account.label}</span>
        </p>
        <p className="text-xs text-muted-foreground" data-testid="dashboard-user-id">
          Subject: {account.userId}
        </p>
        <AccountTotpPanel
          totpEnabled={Boolean(account.totpEnabled)}
          onCompleted={() => {
            clearOwnerContextHandle();
            setAccount(null);
            void loadAccounts();
          }}
        />
        <AccountSessionsAppsPanel />
        <button
          type="button"
          className="text-sm underline text-muted-foreground hover:text-foreground"
          onClick={() => {
            clearOwnerContextHandle();
            setAccount(null);
            void loadAccounts();
          }}
        >
          Switch account in this tab
        </button>
      </div>
    </div>
  );
}
