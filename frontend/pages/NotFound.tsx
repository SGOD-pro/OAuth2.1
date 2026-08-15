import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';

export const NotFound: React.FC = () => {
  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6">
      <div className="w-full max-w-[460px]">
        <Card className="w-full text-center">
          <CardContent className="p-8 sm:p-[34px]">
            <div className="mx-auto size-12 rounded-full bg-destructive/10 border border-destructive/20 text-destructive flex items-center justify-center mb-6">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
            </div>
            <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted-foreground mb-2">
              Error // 404
            </p>
            <h1 className="font-heading text-[26px] font-normal text-foreground mb-3">
              Route Not Found
            </h1>
            <p className="font-sans text-sm text-muted-foreground leading-relaxed mb-8">
              The requested telemetry endpoint does not exist or has been relocated.
            </p>
            <Button asChild className="w-full">
              <Link to="/auth" viewTransition>
                Return to Console
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
