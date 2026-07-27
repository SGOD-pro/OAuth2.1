import React, { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';


export const AuthCallback: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const code     = searchParams.get('code');
  const state    = searchParams.get('state');
  const clientId = searchParams.get('client_id');

  useEffect(() => {
    if (!code && clientId) {
      navigate(
        { pathname: '/auth', search: searchParams.toString() },
        { replace: true, viewTransition: true }
      );
    }
  }, [code, clientId, navigate, searchParams]);

  if (code && state) {
    return (
      <div className="w-full max-w-md px-4 mx-auto">
        <div className="glass-card rounded-[22px] p-8 w-full transition-all duration-300 relative overflow-hidden flex flex-col items-center justify-center text-center">
          <div className="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center mb-6">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          </div>
          <h1 className="text-xl font-semibold text-foreground font-heading">Authenticating</h1>
          <p className="mt-2 text-sm text-muted-foreground">Completing your secure sign in...</p>
        </div>
      </div>
    );
  }

  if (!code && clientId) {
    return (
      <div className="w-full max-w-md px-4 mx-auto">
        <div className="glass-card rounded-[22px] p-12 w-full transition-all duration-300 relative overflow-hidden flex flex-col items-center justify-center text-center">
           <div className="h-12 w-12 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-md px-4 mx-auto">
      <div className="glass-card rounded-[22px] p-8 w-full transition-all duration-300 relative overflow-hidden text-center">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-card border border-border shadow-sm mb-6">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-primary"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
        </div>
        <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground font-mono mb-2">NexusID</p>
        <h1 className="text-2xl font-semibold text-foreground font-heading mb-4">Authentication Service</h1>
        <p className="text-sm text-muted-foreground leading-relaxed mb-8">
          This service handles secure authentication. To sign in, please return to the application you were using and initiate the process from there.
        </p>
      </div>
    </div>
  );
};
