import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AccountChooser, type BrowserAccountEntry } from "../components/AccountChooser";
import { getOwnerContextHandle, issueOwnerContext, clearOwnerContextHandle } from "../lib/identityContext";
import { getCsrfToken } from "../lib/csrf";

interface ProfileData {
  userId: string;
  username: string | null;
  name: string;
  email: string;
  emailVerified: boolean;
}

export default function AccountProfile() {
  const [accounts, setAccounts] = useState<BrowserAccountEntry[]>([]);
  const [profile, setProfile] = useState<ProfileData | null>(null);
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const loadProfile = useCallback(async () => {
    const handle = getOwnerContextHandle();
    if (!handle) return false;
    const res = await fetch("/api/identity/me", {
      credentials: "include",
      headers: { "X-Identity-Context": handle },
    });
    if (!res.ok) {
      clearOwnerContextHandle();
      return false;
    }
    const data: ProfileData = await res.json();
    setProfile(data);
    setName(data.name || "");
    setUsername(data.username || "");
    return true;
  }, []);

  const init = useCallback(async () => {
    setLoading(true);
    try {
      if (await loadProfile()) return;
      const res = await fetch("/api/identity/accounts", { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setAccounts(Array.isArray(data.accounts) ? data.accounts : []);
      }
    } finally {
      setLoading(false);
    }
  }, [loadProfile]);

  useEffect(() => {
    void init();
  }, [init]);

  async function handleSelectAccount(entryId: string) {
    setError(null);
    const issued = await issueOwnerContext(entryId);
    if (!issued) {
      setError("Failed to select account");
      return;
    }
    await loadProfile();
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setSaved(false);
    setError(null);
    try {
      const handle = getOwnerContextHandle();
      const csrf = await getCsrfToken();
      const res = await fetch("/api/identity/me", {
        method: "PATCH",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": csrf || "",
          ...(handle ? { "X-Identity-Context": handle } : {}),
        },
        body: JSON.stringify({ name, username }),
      });
      const body = await res.json().catch(() => null);
      if (!res.ok) {
        setError(body?.message || "Failed to update profile");
        return;
      }
      setProfile(body);
      setName(body.name || "");
      setUsername(body.username || "");
      setSaved(true);
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center text-sm text-muted-foreground">Loading...</div>;
  }

  if (!profile) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-background">
        <div className="w-full max-w-md rounded-lg border bg-card p-6 space-y-4">
          <h1 className="text-lg font-semibold">Select Account</h1>
          {error && <p className="text-xs text-destructive">{error}</p>}
          <AccountChooser
            accounts={accounts}
            selectingEntryId={null}
            signingOutEntryId={null}
            error={error}
            onSelectAccount={handleSelectAccount}
            onSignOutAccount={async () => {}}
            onSignInAgain={() => {}}
            onUseAnotherAccount={() => {}}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-background">
      <div className="w-full max-w-md rounded-lg border bg-card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-semibold">Edit Profile</h1>
          <Link to="/account" className="text-xs underline text-muted-foreground hover:text-foreground">Back to Account</Link>
        </div>
        <p className="text-xs text-muted-foreground" data-testid="profile-user-id">Subject: {profile.userId}</p>
        <p className="text-xs text-muted-foreground" data-testid="profile-email">
          Email: {profile.email} ({profile.emailVerified ? "verified" : "unverified"})
        </p>
        <form onSubmit={handleSave} className="space-y-3">
          <div className="space-y-1">
            <label className="text-xs font-medium" htmlFor="profile-name">Display Name</label>
            <input
              id="profile-name"
              data-testid="profile-name-input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded border px-3 py-1.5 text-sm bg-background"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium" htmlFor="profile-username">Username</label>
            <input
              id="profile-username"
              data-testid="profile-username-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded border px-3 py-1.5 text-sm bg-background"
            />
          </div>
          {error && <p className="text-xs text-destructive" data-testid="profile-error">{error}</p>}
          {saved && <p className="text-xs text-green-600" data-testid="profile-saved">Profile saved.</p>}
          <button
            type="submit"
            disabled={saving}
            data-testid="profile-save-btn"
            className="rounded bg-primary px-3 py-1.5 text-xs text-primary-foreground"
          >
            {saving ? "Saving..." : "Save Profile"}
          </button>
        </form>
      </div>
    </div>
  );
}
