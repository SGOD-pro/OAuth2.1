import React, { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Card, CardContent } from '@/components/ui/card';

export const AuthCallback: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const code = searchParams.get('code');
  const state = searchParams.get('state');
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
      <div className="min-h-screen w-full flex items-center justify-center p-6">
        <div className="w-full max-w-[460px]">
          <Card className="w-full text-center">
            <CardContent className="p-8 sm:p-[34px] flex flex-col items-center justify-center">
              <div className="font-heading text-[34px] tracking-tighter text-foreground mb-6 font-normal">
                M Auth
              </div>
              <div className="flex w-48 flex-col gap-2.5 mb-6">
                <div className="h-[2.5px] w-full bg-[#0066B1] rounded-full animate-m-line-1" />
                <div className="h-[2.5px] w-3/4 bg-[#1C69D4] rounded-full animate-m-line-2" />
                <div className="h-[2.5px] w-1/2 bg-[#E22718] rounded-full animate-m-line-3" />
              </div>
              <h2 className="font-heading text-lg font-medium text-foreground">
                Exchanging Telemetry Code
              </h2>
              <p className="font-mono text-xs uppercase tracking-wider text-muted-foreground mt-2">
                Completing secure handshake...
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6">
      <div className="w-full max-w-[460px]">
        <Card className="w-full text-center">
          <CardContent className="p-8 sm:p-[34px]">
            <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
              SWYRA // M Telemetry Service
            </span>
            <h1 className="font-heading text-[26px] font-normal text-foreground mb-4">
              Authentication Active
            </h1>
            <p className="font-sans text-sm text-muted-foreground leading-relaxed">
              This node coordinates cryptographic token verification. Return to your primary application client to initiate a session.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
