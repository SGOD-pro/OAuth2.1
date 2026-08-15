import React from 'react';
import { Card, CardContent } from '@/components/ui/card';

type Reason = 'missing_params' | 'invalid_client' | 'invalid_redirect';

const CONTENT: Record<Reason, { title: string; message: string }> = {
  missing_params: {
    title: 'Invalid Request',
    message:
      'Required authorization parameters are missing. Return to your application and initiate sign in from there.',
  },
  invalid_client: {
    title: 'Unknown Application',
    message:
      'This application is not registered with M Auth. Contact the application administrator.',
  },
  invalid_redirect: {
    title: 'Invalid Redirect URI',
    message:
      'The redirect URI does not match what is registered for this application. Telemetry session blocked.',
  },
};

interface InvalidRequestProps {
  reason: Reason;
}

export const InvalidRequest: React.FC<InvalidRequestProps> = ({ reason }) => {
  const { title, message } = CONTENT[reason];

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6 bg-background">
      <div className="w-full max-w-[460px]">
        <Card className="w-full text-center">
          <CardContent className="p-8 sm:p-[34px]">
            <div className="mx-auto size-12 rounded-full border border-destructive/30 bg-destructive/10 text-destructive flex items-center justify-center mb-6">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
            </div>
            <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted-foreground mb-2">
              Telemetry Violation
            </p>
            <h1 className="font-heading text-[26px] font-normal text-foreground mb-3">{title}</h1>
            <p className="font-sans text-sm text-muted-foreground leading-relaxed">{message}</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
