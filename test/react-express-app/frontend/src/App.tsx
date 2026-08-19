import { useState, useEffect, useCallback } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:4000';
const CLIENT_ID   = import.meta.env.VITE_CLIENT_ID   || '(not set)';

interface UserProfile {
  sub?: string;
  email?: string;
  name?: string;
  scope?: string;
  [key: string]: unknown;
}

interface TelemetryData {
  status: string;
  authorizedSubject?: string;
  email?: string;
  timestamp: string;
  engineMetrics: Record<string, string | number>;
  securityContext: Record<string, unknown>;
}

// ─── Home Page ────────────────────────────────────────────────────────────────
function HomePage({ error }: { error?: string }) {
  return (
    <div className="home-wrapper">
      <div className="card">
        <div className="tricolor-bar" />

        {error && (
          <div className="error-banner">
            ⚠️ Auth Error: {decodeURIComponent(error)}
          </div>
        )}

        <div className="card-header">
          <span className="label-tag">Consumer Test Application</span>
          <h1 className="card-title">React + Express OAuth 2.1</h1>
          <p className="card-desc">
            Demonstrates Authorization Code + PKCE (S256) flow via a confidential
            Express BFF. No tokens are ever stored in the browser.
          </p>
        </div>

        <div className="info-grid">
          <div className="info-row">
            <span className="info-key">Target IdP (AUTH_ISSUER)</span>
            <span className="info-val">{BACKEND_URL.replace(':4000', ':3000')}</span>
          </div>
          <div className="info-row">
            <span className="info-key">Client ID (VITE_CLIENT_ID)</span>
            <span className="info-val">{CLIENT_ID}</span>
          </div>
          <div className="info-row">
            <span className="info-key">Callback URL</span>
            <span className="info-val">{BACKEND_URL}/auth/callback</span>
          </div>
          <div className="info-row">
            <span className="info-key">Token Storage</span>
            <span className="info-val info-val--green">HttpOnly Cookie (Server-Side Only)</span>
          </div>
        </div>

        <a href={`${BACKEND_URL}/auth/login`} className="btn-primary" id="login-btn">
          Sign In with SWYRA M Auth
          <span aria-hidden="true">→</span>
        </a>

        <div className="footer-note">
          Protected with S256 PKCE Code Challenge & One-Time Nonce State
        </div>
      </div>
    </div>
  );
}

// ─── Dashboard Page ───────────────────────────────────────────────────────────
function DashboardPage({
  user,
  onLogout,
}: {
  user: UserProfile;
  onLogout: () => void;
}) {
  const [telemetry, setTelemetry] = useState<TelemetryData | null>(null);
  const [telemetryLoading, setTelemetryLoading] = useState(false);
  const [telemetryError, setTelemetryError] = useState<string | null>(null);
  const [fetched, setFetched] = useState(false);

  const fetchTelemetry = useCallback(async () => {
    setTelemetryLoading(true);
    setTelemetryError(null);
    try {
      const res = await fetch(`${BACKEND_URL}/api/secure-telemetry`, {
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.message || body.error || `HTTP ${res.status}`);
      }
      setTelemetry(await res.json());
      setFetched(true);
    } catch (err: unknown) {
      setTelemetryError(err instanceof Error ? err.message : 'Request failed');
    } finally {
      setTelemetryLoading(false);
    }
  }, []);

  const avatar = (user.name || user.email || 'U')[0].toUpperCase();

  return (
    <div className="dashboard-wrapper">
      {/* Top Bar */}
      <div className="card topbar">
        <div className="tricolor-bar" />
        <div className="topbar-left">
          <div className="avatar">{avatar}</div>
          <div>
            <div className="topbar-name-row">
              <h1 className="topbar-name">{user.name || 'Authenticated Pilot'}</h1>
              <span className="badge badge--green">OAuth 2.1 Authenticated</span>
            </div>
            <p className="topbar-email">{user.email || user.sub || 'No email reported'}</p>
          </div>
        </div>
        <button id="logout-btn" className="btn-danger" onClick={onLogout}>
          Sign Out Session
        </button>
      </div>

      {/* Grid */}
      <div className="dash-grid">

        {/* Left — Protected Data Stream */}
        <div className="dash-main space-y-4">
          <div className="card">
            <div className="section-label">Protected Express Route</div>
            <h2 className="section-title">Secure Telemetry Stream</h2>
            <p className="section-desc">
              The browser holds <strong>no access token</strong>. It sends the
              HttpOnly <code>app_session</code> cookie to Express, which reads
              the stored token, verifies it against SWYRA M Auth, then returns
              protected data.
            </p>

            <button
              id="fetch-telemetry-btn"
              className="btn-primary btn-primary--sm"
              onClick={fetchTelemetry}
              disabled={telemetryLoading}
            >
              {telemetryLoading ? (
                <>
                  <span className="spinner-sm" />
                  Fetching from Express...
                </>
              ) : fetched ? 'Refresh Telemetry' : 'Fetch Secure Telemetry'}
            </button>

            {telemetryError && (
              <div className="error-banner" style={{ marginTop: '1rem' }}>
                ⚠️ {telemetryError}
              </div>
            )}

            {telemetry && (
              <>
                {/* Stats row */}
                <div className="stats-grid">
                  {[
                    { label: 'Engine RPM',  val: telemetry.engineMetrics?.rpm ?? '—' },
                    { label: 'Speed (km/h)', val: telemetry.engineMetrics?.speedKmh ?? '—' },
                    { label: 'Gear',         val: telemetry.engineMetrics?.gear ?? '—' },
                    { label: 'Turbo (bar)',  val: telemetry.engineMetrics?.turboBoostBar ?? '—' },
                  ].map((s) => (
                    <div key={s.label} className="stat-card">
                      <span className="stat-label">{s.label}</span>
                      <span className="stat-val">{String(s.val)}</span>
                    </div>
                  ))}
                </div>

                {/* Raw JSON */}
                <div className="json-box">
                  <div className="json-header">
                    <span className="dot dot--green" />
                    <span className="json-title">Express /api/secure-telemetry Response</span>
                    <span className="json-ts">{telemetry.timestamp}</span>
                  </div>
                  <pre className="json-body">{JSON.stringify(telemetry, null, 2)}</pre>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Right — Token Inspector */}
        <div className="card">
          <div className="section-label">OIDC Token Claims</div>
          <h3 className="section-title">Active Security Subject</h3>

          <div className="claim-list">
            <ClaimRow label="Subject ID (sub)" value={user.sub || 'N/A'} code />
            <ClaimRow label="Email" value={user.email || 'N/A'} />
            <ClaimRow label="Name" value={user.name || 'N/A'} />
            <ClaimRow
              label="Granted Scopes"
              value={user.scope || 'openid profile email'}
              scopes
            />
          </div>

          <div className="divider" />

          <div className="flow-title">Auth Flow Architecture</div>
          <div className="flow-list">
            {[
              ['1', 'React', 'Redirects browser to Express /auth/login'],
              ['2', 'Express', 'Generates PKCE verifier + state, sets cookies'],
              ['3', 'SWYRA IdP', 'User authenticates, issues auth code'],
              ['4', 'Express', 'Exchanges code + client_secret for tokens'],
              ['5', 'Express', 'Stores tokens in HttpOnly app_session cookie'],
              ['6', 'React', 'Fetches /api/secure-telemetry via cookie auth'],
              ['7', 'Express', 'Verifies token, returns protected data'],
            ].map(([step, actor, desc]) => (
              <div key={step} className="flow-step">
                <span className="flow-num">{step}</span>
                <span className="flow-actor">{actor}</span>
                <span className="flow-desc">{desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function ClaimRow({
  label, value, code, scopes,
}: {
  label: string; value: string; code?: boolean; scopes?: boolean;
}) {
  return (
    <div className="claim-row">
      <span className="claim-label">{label}</span>
      {scopes ? (
        <div className="scope-chips">
          {value.split(' ').map((s) => <span key={s} className="scope-chip">{s}</span>)}
        </div>
      ) : code ? (
        <code className="claim-code">{value}</code>
      ) : (
        <span className="claim-val">{value}</span>
      )}
    </div>
  );
}

// ─── Root App ─────────────────────────────────────────────────────────────────
export function App() {
  const [user, setUser]     = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [urlError, setUrlError] = useState<string | undefined>();

  useEffect(() => {
    // Capture ?error= from OAuth redirect failure
    const params = new URLSearchParams(window.location.search);
    const err = params.get('error') || params.get('error_description');
    if (err) {
      setUrlError(err);
      window.history.replaceState({}, '', window.location.pathname);
    }

    // Check if backend already has a session for us
    fetch(`${BACKEND_URL}/auth/me`, { credentials: 'include' })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data?.authenticated && data?.user) setUser(data.user);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleLogout = async () => {
    // 1. Sign out of IDP to clear the global SSO session
    await fetch(`${BACKEND_URL.replace(':4000', ':3000')}/api/auth/sign-out`, {
      method: 'POST',
      credentials: 'include',
    }).catch(() => {});

    // 2. Sign out of consumer app (Express backend)
    await fetch(`${BACKEND_URL}/auth/logout`, {
      method: 'POST',
      credentials: 'include',
    }).catch(() => {});
    
    setUser(null);
    setUrlError(undefined);
  };

  if (loading) {
    return (
      <div className="splash">
        <div className="spinner" />
        <p className="splash-text">Verifying session…</p>
      </div>
    );
  }

  return user
    ? <DashboardPage user={user} onLogout={handleLogout} />
    : <HomePage error={urlError} />;
}
