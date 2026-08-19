import Link from 'next/link';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';

export default async function HomePage(props: {
  searchParams?: Promise<{ error?: string }>;
}) {
  const searchParams = await props.searchParams;
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('auth_session')?.value;

  if (sessionCookie) {
    redirect('/dashboard');
  }


  const issuer = process.env.AUTH_ISSUER || 'http://localhost:3000';
  const clientId = process.env.CLIENT_ID || '(Not set)';

  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh]">
      <div className="w-full max-w-xl bg-[#0f131a] border border-[#21262d] rounded-2xl p-8 relative overflow-hidden shadow-2xl">
        {/* Tricolor bar */}
        <div 
          className="absolute top-0 left-0 right-0 h-[3px]"
          style={{
            background: 'linear-gradient(to right, #0066B1 0%, #0066B1 33.3%, #1C69D4 33.3%, #1C69D4 66.6%, #E22718 66.6%, #E22718 100%)'
          }}
        />

        {searchParams?.error && (
          <div className="mb-6 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 font-mono text-xs text-rose-400">
            ⚠️ Auth Error: {searchParams.error}
          </div>
        )}

        <div className="mb-6">
          <span className="font-mono text-xs uppercase tracking-widest text-[#0066B1] font-semibold block mb-1">
            Consumer Test Application
          </span>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
            Next.js OAuth 2.1 Consumer
          </h1>
          <p className="text-sm text-neutral-400 mt-2">
            This application demonstrates server-side OAuth 2.1 Authorization Code Flow with PKCE (S256), token exchange, and secure data access against SWYRA M Auth IdP.
          </p>
        </div>

        <div className="bg-[#161b22] rounded-xl p-4 border border-[#30363d] space-y-2 mb-8 font-mono text-xs">
          <div className="flex justify-between">
            <span className="text-neutral-400">Target IdP (AUTH_ISSUER):</span>
            <span className="text-neutral-200 truncate max-w-[280px]">{issuer}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-neutral-400">Client ID (CLIENT_ID):</span>
            <span className="text-neutral-200 truncate max-w-[280px]">{clientId}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-neutral-400">Callback URL:</span>
            <span className="text-neutral-200 truncate max-w-[280px]">/api/auth/callback</span>
          </div>
        </div>

        <a
          href="/api/auth/login"
          className="w-full inline-flex items-center justify-center gap-2 bg-[#0066B1] hover:bg-[#1C69D4] text-white font-medium text-sm py-3 px-6 rounded-xl transition-all shadow-lg hover:shadow-[#0066B1]/20 cursor-pointer"
        >
          <span>Sign In with SWYRA M Auth</span>
          <span aria-hidden="true">→</span>
        </a>

        <div className="mt-6 pt-4 border-t border-[#21262d] text-center">
          <span className="font-mono text-[11px] text-neutral-500">
            Protected with S256 PKCE Code Challenge & One-Time Nonce State
          </span>
        </div>
      </div>
    </div>
  );
}
