import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

interface PrivacyState {
  userId: string;
  privacyVersion: number;
  shareEmail: boolean;
  shareProfile: boolean;
}

export default function AccountPrivacy() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);
  const [privacy, setPrivacy] = useState<PrivacyState | null>(null);

  const ownerContext =
    typeof window !== "undefined" ? sessionStorage.getItem("owner_context_id") : null;

  const buildHeaders = (extra: Record<string, string> = {}) => ({
    ...(ownerContext ? { "x-identity-context": ownerContext } : {}),
    ...extra,
  });

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const res = await fetch("/api/identity/privacy", {
          credentials: "include",
          headers: buildHeaders(),
        });
        if (!res.ok) {
          throw new Error("Failed to load privacy settings");
        }
        const data = (await res.json()) as PrivacyState;
        if (active) setPrivacy(data);
      } catch (err: any) {
        if (active) setError(err?.message || "Failed to load privacy settings");
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const handleSave = async () => {
    if (!privacy) return;
    setSaving(true);
    setError(null);
    setSavedMsg(null);
    try {
      const res = await fetch("/api/identity/privacy", {
        method: "PATCH",
        credentials: "include",
        headers: buildHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          shareEmail: privacy.shareEmail,
          shareProfile: privacy.shareProfile,
        }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.message || "Failed to save privacy settings");
      }
      const updated = (await res.json()) as PrivacyState;
      setPrivacy(updated);
      setSavedMsg("Privacy preferences saved.");
    } catch (err: any) {
      setError(err?.message || "Failed to save privacy settings");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="max-w-2xl mx-auto p-6">
        <p className="text-sm text-gray-500">Loading privacy settings...</p>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Privacy Settings</h1>
        <Link to="/account" className="text-sm text-blue-600 hover:underline">
          Back to Account
        </Link>
      </div>

      {error && (
        <div role="alert" className="p-3 rounded bg-red-50 text-red-700 text-sm">
          {error}
        </div>
      )}
      {savedMsg && (
        <div role="status" className="p-3 rounded bg-green-50 text-green-700 text-sm">
          {savedMsg}
        </div>
      )}

      {privacy && (
        <div className="space-y-4 border rounded-lg p-5 bg-white">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={privacy.shareEmail}
              onChange={(e) =>
                setPrivacy({ ...privacy, shareEmail: e.target.checked })
              }
              aria-label="Share email address with connected apps"
              className="mt-1"
            />
            <div>
              <div className="font-medium">Share email address with connected apps</div>
              <div className="text-sm text-gray-500">
                When disabled, connected apps will not receive your email or email_verified claims even if they request the email scope. Your own account and security emails are unaffected.
              </div>
            </div>
          </label>

          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={privacy.shareProfile}
              onChange={(e) =>
                setPrivacy({ ...privacy, shareProfile: e.target.checked })
              }
              aria-label="Share profile details with connected apps"
              className="mt-1"
            />
            <div>
              <div className="font-medium">Share profile details with connected apps</div>
              <div className="text-sm text-gray-500">
                When disabled, connected apps will not receive your display name or profile claims even if they request the profile scope.
              </div>
            </div>
          </label>

          <button
            type="button"
            onClick={handleSave}
            disabled={saving}
            className="px-4 py-2 rounded bg-blue-600 text-white text-sm font-medium disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save privacy settings"}
          </button>
        </div>
      )}
    </div>
  );
}
