import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';

export const NotFound: React.FC = () => {
  return (
    <div className="w-full max-w-md px-4 mx-auto">
      <div className="glass-card rounded-[22px] p-8 w-full transition-all duration-300 relative overflow-hidden text-center">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-destructive/10 border border-destructive/20 text-destructive mb-6">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
        </div>
        <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground font-mono mb-2">Error 404</p>
        <h1 className="text-2xl font-semibold text-foreground font-heading mb-3">Page not found</h1>
        <p className="text-sm text-muted-foreground leading-relaxed mb-8">
          The page you are looking for does not exist or has been moved to a new location.
        </p>
        <Button asChild className="w-full rounded-full">
          <Link to="/auth" viewTransition>
            Back to Authentication
          </Link>
        </Button>
      </div>
    </div>
  );
};
