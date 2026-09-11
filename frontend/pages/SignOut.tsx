import React, { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { authClient } from '@/lib/auth-client';
import { usePageTitle } from '@/hooks/usePageTitle';
import { AlertCircle, ArrowLeft } from 'lucide-react';

export const SignOut: React.FC = () => {
  usePageTitle('Sign out');
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
          await authClient.signOut({}).catch(() => {});
          
          if (mounted) {
            window.location.href = data.redirect_uri;
          }
        } else {
          if (mounted) setError(data.error || "Failed to validate redirect URI");
        }
      } catch {
        if (mounted) setError("Network error during sign out");
      }
    };

    processSignOut();
    return () => { mounted = false; };
  }, [clientId, redirectUri, backendUrl]);

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6 bg-background">
      <div className="w-full max-w-[420px]">
        <Card className="w-full shadow-lg border-border">
          <CardContent className="p-10 flex flex-col items-center justify-center text-center">
            {error ? (
              <>
                <div className="mb-4 size-12 rounded-full bg-destructive/10 border border-destructive/20 flex items-center justify-center text-destructive">
                  <AlertCircle className="size-6" />
                </div>
                <h2 className="text-xl font-heading font-semibold text-foreground mb-2">
                  Sign out failed
                </h2>
                <p className="text-xs text-muted-foreground mb-6 max-w-xs">{error}</p>
                <Button asChild variant="outline" className="w-full">
                  <Link to="/auth" className="flex items-center justify-center gap-2">
                    <ArrowLeft className="size-4" /> Return to sign in
                  </Link>
                </Button>
              </>
            ) : (
              <>
                <div className="mb-6 flex items-center gap-1.5 py-4">
                  <span className="size-2 rounded-full bg-[#0066B1] animate-pulse" />
                  <span className="size-2 rounded-full bg-[#1C69D4] animate-pulse [animation-delay:150ms]" />
                  <span className="size-2 rounded-full bg-[#E22718] animate-pulse [animation-delay:300ms]" />
                </div>
                <h2 className="text-xl font-heading font-semibold text-foreground mb-2">
                  Signing out
                </h2>
                <p className="font-sans text-xs text-muted-foreground">
                  Terminating session and returning to application...
                </p>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
