import React from 'react';
import { useLocation } from 'react-router-dom';
import { useOAuthParams } from '../hooks/useOAuthParams';
import { InvalidRequest } from '../components/InvalidRequest';
import { ThemeToggle } from './ThemeToggle';
import { BrandMark } from './BrandMark';
import { Toaster } from '@/components/ui/sonner';
import { TooltipProvider } from '@/components/ui/tooltip';

export const Layout = ({ children }: { children: React.ReactNode }) => {
  const location = useLocation();
  const { isValid } = useOAuthParams();

  const isStrictOAuthEntry = location.pathname === '/auth';
  const isAuthPage = location.pathname === '/auth';

  if (isStrictOAuthEntry && !isValid) {
    return <InvalidRequest reason="missing_params" />;
  }

  return (
    <TooltipProvider>
      <main className="min-h-dvh overflow-x-hidden w-full flex items-center justify-center relative bg-background text-foreground">
        {!isAuthPage && (
          <div className="fixed top-4 right-4 z-50">
            <ThemeToggle />
          </div>
        )}

        {!isAuthPage && (
          <div className="fixed top-4 left-4 z-50">
            <BrandMark />
          </div>
        )}

        <div className="z-10 w-full relative">
          {children}
        </div>
      </main>
      <Toaster />
    </TooltipProvider>
  );
};

export const Logo = BrandMark;