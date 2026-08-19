import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { TelemetryViewer } from './TelemetryViewer';
import { LogoutButton } from './LogoutButton';

export default async function DashboardPage() {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('auth_session')?.value;

  if (!sessionCookie) {
    redirect('/');
  }

  let session: any = null;
  try {
    session = JSON.parse(sessionCookie);
  } catch {
    redirect('/');
  }

  const user = session?.user || {};
  const tokens = session?.tokens || {};

  return (
    <div className="space-y-8">
      {/* Top Welcome Bar */}
      <div className="bg-[#0f131a] border border-[#21262d] rounded-2xl p-6 relative overflow-hidden flex flex-wrap items-center justify-between gap-4 shadow-xl">
        <div 
          className="absolute top-0 left-0 right-0 h-[3px]"
          style={{
            background: 'linear-gradient(to right, #0066B1 0%, #0066B1 33.3%, #1C69D4 33.3%, #1C69D4 66.6%, #E22718 66.6%, #E22718 100%)'
          }}
        />

        <div className="flex items-center gap-4">
          <div className="size-12 rounded-xl bg-[#161b22] border border-[#30363d] flex items-center justify-center font-mono text-lg font-bold text-white">
            {(user.name || user.email || 'U')[0].toUpperCase()}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">
                {user.name || 'Authenticated Pilot'}
              </h1>
              <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-mono uppercase px-2 py-0.5 rounded-full font-semibold">
                OAuth 2.1 Authenticated
              </span>
            </div>
            <p className="font-mono text-xs text-neutral-400 mt-0.5">
              {user.email || user.sub || 'No email reported'}
            </p>
          </div>
        </div>

        <LogoutButton issuer={process.env.AUTH_ISSUER || 'http://localhost:3000'} />
      </div>

      {/* Main Grid: Live Telemetry + Token Claims */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: Protected Data Stream */}
        <div className="lg:col-span-2 space-y-6">
          <TelemetryViewer />
        </div>

        {/* Right 1 Col: Token Claims & Session Inspector */}
        <div className="bg-[#0f131a] border border-[#21262d] rounded-2xl p-6 shadow-xl space-y-4 font-mono text-xs">
          <div className="border-b border-[#21262d] pb-3">
            <span className="text-[10px] uppercase tracking-wider text-neutral-400 block font-semibold">
              OIDC Token Claims
            </span>
            <h3 className="text-sm font-bold text-white mt-1">
              Active Security Subject
            </h3>
          </div>

          <div className="space-y-3">
            <div>
              <span className="text-neutral-400 block text-[10px]">Subject ID (sub)</span>
              <code className="text-neutral-200 bg-[#161b22] px-2 py-1 rounded block mt-0.5 break-all">
                {user.sub || 'N/A'}
              </code>
            </div>

            <div>
              <span className="text-neutral-400 block text-[10px]">Granted Scopes</span>
              <div className="flex flex-wrap gap-1.5 mt-1">
                {(tokens.scope || 'openid profile email').split(' ').map((s: string) => (
                  <span key={s} className="bg-[#161b22] text-[#0066B1] border border-[#0066B1]/30 px-2 py-0.5 rounded text-[10px]">
                    {s}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span className="text-neutral-400 block text-[10px]">Access Token (Truncated)</span>
              <code className="text-emerald-400 bg-[#161b22] px-2 py-1 rounded block mt-0.5 break-all text-[11px]">
                {tokens.access_token ? `${tokens.access_token.slice(0, 20)}...` : 'None'}
              </code>
            </div>

            <div>
              <span className="text-neutral-400 block text-[10px]">Token Type / Expires In</span>
              <div className="text-neutral-200 mt-0.5">
                {tokens.token_type || 'Bearer'} — {tokens.expires_in || 3600}s
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
