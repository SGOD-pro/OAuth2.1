import React from 'react';
import { useOAuthParams } from '../hooks/useOAuthParams';
import { InvalidRequest } from '../components/InvalidRequest';
import { ThemeToggle } from './ThemeToggle';
import { Toaster } from '@/components/ui/sonner';
import { TooltipProvider } from '@/components/ui/tooltip';

export const Layout = ({ children }: { children: React.ReactNode }) => {
  const { isValid } = useOAuthParams();

  if (!isValid) {
    return <InvalidRequest reason="missing_params" />;
  }

  return (
    <TooltipProvider>
      <main className="min-h-dvh overflow-x-hidden w-full flex items-center justify-center relative bg-background text-foreground selection:bg-accent selection:text-accent-foreground">
        {/* Stark precision telemetry background texture */}
        <div 
          className="fixed inset-0 pointer-events-none opacity-[0.025] -z-10"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)`,
            backgroundSize: '24px 24px'
          }}
        />

        <div className="fixed top-5 right-5 z-50">
          <ThemeToggle />
        </div>

        <Logo />

        <div className="z-10 w-full relative">
          {children}
        </div>
      </main>
      <Toaster />
    </TooltipProvider>
  );
};

export const Logo = () => {
  return (
    <div className="fixed top-5 left-5 flex items-center gap-2.5 bg-card/60 backdrop-blur-md rounded-pill px-4 py-2 border border-border shadow-sm z-50">
      <div className="flex h-3 gap-0.5 items-center">
        <div className="w-[3px] h-3 bg-[#0066B1] -skew-x-12" />
        <div className="w-[3px] h-3 bg-[#1C69D4] -skew-x-12" />
        <div className="w-[3px] h-3 bg-[#E22718] -skew-x-12" />
      </div>
      <p className="text-xs font-mono tracking-[0.15em] uppercase text-foreground font-medium">
        <span className="text-muted-foreground font-normal">SWYRA //</span> M AUTH
      </p>
    </div>
  );
};