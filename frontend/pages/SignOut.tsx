import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Card, CardContent } from '@/components/ui/card';
import { authClient } from '@/lib/auth-client';

export const SignOut: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  
  const clientId = searchParams.get('client_id');
  const redirectUri = searchParams.get('redirect_uri');
  const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:3000';

  useEffect(() => {
    let mounted = true;
    const processSignOut = async () => {
      if (!clientId || !redirectUri) {
        if (mounted) setError("Missing required parameters: client_id and redirect_uri");
        return;
      }

      try {
        const res = await fetch(`${backendUrl}/api/auth/sign-out-client`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ client_id: clientId, redirect_uri: redirectUri })
        });
        
        const data = await res.json();
        
        if (res.ok && data.success) {
          // Clear any local Better Auth frontend state if it exists
          await authClient.signOut().catch(() => {});
          
          if (mounted) {
            window.location.href = data.redirect_uri;
          }
        } else {
          if (mounted) setError(data.error || "Failed to validate redirect URI");
        }
      } catch (e) {
        if (mounted) setError("Network error during sign out");
      }
    };

    processSignOut();
    return () => { mounted = false; };
  }, [clientId, redirectUri, backendUrl]);

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6 bg-background">
      <div className="w-full max-w-[400px]">
        <Card className="w-full">
          <CardContent className="p-12 flex flex-col items-center justify-center text-center">
            {error ? (
              <>
                <div className="mb-4 size-12 rounded-full bg-destructive/10 border border-destructive/30 flex items-center justify-center text-destructive">
                  <svg className="size-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </div>
                <h2 className="text-lg font-heading text-destructive mb-2">Logout Failed</h2>
                <p className="text-sm font-mono text-muted-foreground">{error}</p>
              </>
            ) : (
              <>
                <div className="relative mb-6">
                  <div className="size-16 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center">
                    <svg className="size-8 text-primary animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                    </svg>
                  </div>
                  <div className="absolute inset-0 rounded-full border-2 border-primary border-t-transparent animate-spin" />
                </div>
                <h2 className="text-xl font-heading mb-2">Terminating Session</h2>
                <p className="font-mono text-xs text-muted-foreground">Destroying IDP tokens and validating return path...</p>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
