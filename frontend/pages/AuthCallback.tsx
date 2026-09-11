import React, { useEffect } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';

export const AuthCallback: React.FC = () => {
  usePageTitle('Authenticating');
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const code = searchParams.get('code');
  const state = searchParams.get('state');
  const clientId = searchParams.get('client_id');

  useEffect(() => {
    if (!code && clientId) {
      navigate(
        { pathname: '/auth', search: searchParams.toString() },
        { replace: true }
      );
    }
  }, [code, clientId, navigate, searchParams]);

  if (code && state) {
    return (
      <div className="min-h-screen w-full flex items-center justify-center p-6 bg-background">
        <div className="w-full max-w-[460px]">
          <Card className="w-full text-center shadow-lg border-border">
            <CardContent className="p-8 sm:p-[34px] flex flex-col items-center justify-center">
              <div className="mb-6">
                <BrandMark size="lg" />
              </div>
              <div className="flex items-center gap-1.5 py-3 mb-4">
                <span className="size-2 rounded-full bg-[#0066B1] animate-pulse" />
                <span className="size-2 rounded-full bg-[#1C69D4] animate-pulse [animation-delay:150ms]" />
                <span className="size-2 rounded-full bg-[#E22718] animate-pulse [animation-delay:300ms]" />
              </div>
              <h2 className="font-heading text-xl font-semibold text-foreground">
                Authorizing session
              </h2>
              <p className="font-sans text-xs text-muted-foreground mt-2">
                Completing secure authentication exchange...
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6 bg-background">
      <div className="w-full max-w-[460px]">
        <Card className="w-full text-center shadow-lg border-border">
          <CardContent className="p-8 sm:p-[34px]">
            <div className="flex justify-center mb-6">
              <BrandMark size="md" />
            </div>
            <h1 className="font-heading text-2xl font-semibold text-foreground mb-3">
              M Auth Service Active
            </h1>
            <p className="font-sans text-sm text-muted-foreground leading-relaxed mb-6">
              This node coordinates OAuth 2.1 authentication and token issuance. Please return to your application client to initiate a session.
            </p>
            <Button asChild variant="outline" className="w-full">
              <Link to="/auth">Go to sign in</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
