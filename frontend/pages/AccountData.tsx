import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AccountChooser, type BrowserAccountEntry } from "../components/AccountChooser";
import { csrfHeaders } from "../lib/csrf";
import {
  clearOwnerContextHandle,
  fetchOwnerContextMe,
  getOwnerContextHandle,
  issueOwnerContext,
} from "../lib/identityContext";

interface ExportStatus {
  jobId: string;
  status: string;
  expiresAt: string;
  downloadExpiresAt?: string | null;
  downloadAvailable?: boolean;
  errorCode?: string | null;
}

interface DeletionStatus {
  operationId: string;
  status: string;
  committedAt: string;
  updatedAt?: string;
}

export default function AccountData() {
  const [accounts, setAccounts] = useState<BrowserAccountEntry[]>([]);
  const [ownerLabel, setOwnerLabel] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [exportJob, setExportJob] = useState<ExportStatus | null>(null);
  const [exportBusy, setExportBusy] = useState(false);

  const [confirmText, setConfirmText] = useState("");
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deletionReceipt, setDeletionReceipt] = useState<DeletionStatus | null>(null);

  const loadAccounts = useCallback(async () => {
    const res = await fetch("/api/identity/accounts", { credentials: "include" });
    const data = await res.json().catch(() => ({}));
    if (res.ok && Array.isArray(data.accounts)) setAccounts(data.accounts);
  }, []);

  const verifyContext = useCallback(async () => {
    setLoading(true);
    try {
      const me = await fetchOwnerContextMe();
      setOwnerLabel(me.label);
    } catch {
      setOwnerLabel(null);
      await loadAccounts();
    } finally {
      setLoading(false);
    }
  }, [loadAccounts]);

  useEffect(() => {
    void verifyContext();
  }, [verifyContext]);

  const refreshExportStatus = useCallback(async (jobId: string) => {
    const handle = getOwnerContextHandle();
    if (!handle) return;
    const res = await fetch(`/api/identity/me/export/${encodeURIComponent(jobId)}`, {
      credentials: "include",
      headers: { "X-Identity-Context": handle },
    });
    if (res.ok) {
      setExportJob((await res.json()) as ExportStatus);
    }
  }, []);

  useEffect(() => {
    if (!exportJob || (exportJob.status !== "queued" && exportJob.status !== "processing")) {
      return;
    }
    const id = setInterval(() => {
      void refreshExportStatus(exportJob.jobId);
    }, 1500);
    return () => clearInterval(id);
  }, [exportJob, refreshExportStatus]);

  async function handleSelectAccount(entryId: string) {
    setError(null);
    try {
      const issued = await issueOwnerContext(entryId);
      setOwnerLabel(issued.account.label);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Unable to select account");
    }
  }

  async function handleRequestExport() {
    const handle = getOwnerContextHandle();
    if (!handle) return;
    setExportBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/identity/me/export", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "X-Identity-Context": handle, ...csrfHeaders() },
        body: JSON.stringify({}),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.message || data.error || "Failed to request export");
      }
      setExportJob(data as ExportStatus);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to request export");
    } finally {
      setExportBusy(false);
    }
  }

  async function handleDownloadExport() {
    const handle = getOwnerContextHandle();
    if (!handle || !exportJob) return;
    setError(null);
    const res = await fetch(`/api/identity/me/export/${encodeURIComponent(exportJob.jobId)}/download`, {
      credentials: "include",
      headers: { "X-Identity-Context": handle },
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setError(data.message || data.error || "Export download unavailable");
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `swyra-account-export-${exportJob.jobId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function handleRequestDeletion() {
    const handle = getOwnerContextHandle();
    if (!handle) return;
    setDeleteBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/identity/me/deletion", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "X-Identity-Context": handle, ...csrfHeaders() },
        body: JSON.stringify({ confirmation: confirmText.trim() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.message || data.error || "Failed to initiate account deletion");
      }
      clearOwnerContextHandle();
      setDeletionReceipt(data as DeletionStatus);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to initiate account deletion");
    } finally {
      setDeleteBusy(false);
    }
  }

  async function handleRefreshDeletionStatus() {
    setError(null);
    const res = await fetch("/api/identity/deletion/status", { credentials: "include" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setError(data.message || "Deletion status unavailable");
      return;
    }
    setDeletionReceipt(data as DeletionStatus);
  }

  if (loading) {
    return (
      <div className="max-w-2xl mx-auto p-6">
        <p className="text-sm text-muted-foreground">Loading account data controls...</p>
      </div>
    );
  }

  if (deletionReceipt) {
    return (
      <div className="max-w-xl mx-auto p-6 space-y-4">
        <h1 className="text-2xl font-semibold">Account Deletion Accepted</h1>
        <div className="rounded-lg border p-4 space-y-2 text-sm" data-testid="deletion-receipt-card">
          <p>Operation ID: <span className="font-mono">{deletionReceipt.operationId}</span></p>
          <p>Status: <span className="font-semibold" data-testid="deletion-status-value">{deletionReceipt.status}</span></p>
          <p>Committed: {deletionReceipt.committedAt}</p>
        </div>
        <div className="flex gap-3">
          <button
            type="button"
            className="px-4 py-2 rounded border text-sm"
            onClick={() => void handleRefreshDeletionStatus()}
            data-testid="refresh-deletion-status-btn"
          >
            Refresh status
          </button>
          <Link to="/account" className="px-4 py-2 rounded bg-primary text-primary-foreground text-sm">
            Return to Account Chooser
          </Link>
        </div>
      </div>
    );
  }

  if (!ownerLabel) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-background">
        <div className="w-full max-w-md space-y-3">
          <AccountChooser
            accounts={accounts}
            selectingEntryId={null}
            signingOutEntryId={null}
            error={error}
            onSelectAccount={handleSelectAccount}
            onSignOutAccount={async () => {}}
            onSignInAgain={() => { window.location.href = "/auth"; }}
            onUseAnotherAccount={() => { window.location.href = "/auth"; }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Data Export & Account Deletion</h1>
          <p className="text-sm text-muted-foreground">Account: {ownerLabel}</p>
        </div>
        <Link to="/account" className="text-sm underline text-muted-foreground hover:text-foreground">
          Back to Account
        </Link>
      </div>

      {error && (
        <div role="alert" className="p-3 rounded bg-red-50 text-red-700 text-sm" data-testid="account-data-error">
          {error}
        </div>
      )}

      <section className="border rounded-lg p-5 space-y-3">
        <h2 className="text-lg font-medium">Export Your Data</h2>
        <p className="text-sm text-muted-foreground">
          Prepare an encrypted export of your profile, privacy preferences, app grants, and security history. Artifacts expire after 24 hours; downloads are valid for 5 minutes once ready.
        </p>
        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={exportBusy}
            onClick={() => void handleRequestExport()}
            className="px-4 py-2 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50"
            data-testid="request-export-btn"
          >
            {exportBusy ? "Requesting..." : "Request Data Export"}
          </button>
          {exportJob && (
            <button
              type="button"
              onClick={() => void refreshExportStatus(exportJob.jobId)}
              className="px-3 py-2 rounded border text-sm"
              data-testid="refresh-export-btn"
            >
              Refresh Status
            </button>
          )}
        </div>
        {exportJob && (
          <div className="text-sm space-y-2 pt-2" data-testid="export-job-card">
            <p>Job ID: <span className="font-mono">{exportJob.jobId}</span></p>
            <p>Status: <span className="font-semibold" data-testid="export-job-status">{exportJob.status}</span></p>
            {exportJob.downloadAvailable && (
              <button
                type="button"
                onClick={() => void handleDownloadExport()}
                className="px-4 py-2 rounded bg-green-600 text-white text-sm"
                data-testid="download-export-btn"
              >
                Download Export JSON
              </button>
            )}
          </div>
        )}
      </section>

      <section className="border border-red-300 rounded-lg p-5 space-y-3">
        <h2 className="text-lg font-medium text-red-700">Delete Account</h2>
        <p className="text-sm text-muted-foreground">
          Deleting this account immediately revokes its sessions and OAuth tokens, suppresses pending exports, and schedules irreversible key destruction. Other accounts in this browser stay active.
        </p>
        <div className="space-y-2">
          <label className="block text-sm font-medium" htmlFor="delete-confirm-input">
            Type DELETE to confirm
          </label>
          <input
            id="delete-confirm-input"
            type="text"
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            placeholder="DELETE"
            className="w-full px-3 py-2 border rounded text-sm"
            data-testid="delete-confirm-input"
          />
        </div>
        <button
          type="button"
          disabled={deleteBusy || confirmText.trim() !== "DELETE"}
          onClick={() => void handleRequestDeletion()}
          className="px-4 py-2 rounded bg-red-600 text-white text-sm disabled:opacity-50"
          data-testid="confirm-delete-btn"
        >
          {deleteBusy ? "Deleting..." : "Delete Account Permanently"}
        </button>
      </section>
    </div>
  );
}
