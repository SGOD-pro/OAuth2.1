import React from 'react';

export const RouteLoader: React.FC = () => {
  return (
    <div className="flex h-screen w-screen flex-col items-center justify-center gap-4 bg-background" role="status" aria-live="polite">
      <div className="flex flex-col items-center gap-1">
        <div className="flex items-center gap-2">
          <div className="flex h-4 gap-0.5 items-center">
            <div className="w-[3.5px] h-4 bg-[#0066B1] -skew-x-12" />
            <div className="w-[3.5px] h-4 bg-[#1C69D4] -skew-x-12" />
            <div className="w-[3.5px] h-4 bg-[#E22718] -skew-x-12" />
          </div>
          <span className="font-heading text-xl font-medium tracking-tight text-foreground">
            M Auth
          </span>
        </div>
        <span className="font-sans text-xs text-muted-foreground">
          by SWYRA
        </span>
      </div>

      <div className="flex w-36 h-[2px] overflow-hidden rounded-full bg-secondary mt-2">
        <div className="w-1/3 h-full bg-[#0066B1] animate-pulse" />
        <div className="w-1/3 h-full bg-[#1C69D4] animate-pulse [animation-delay:150ms]" />
        <div className="w-1/3 h-full bg-[#E22718] animate-pulse [animation-delay:300ms]" />
      </div>
    </div>
  );
};
