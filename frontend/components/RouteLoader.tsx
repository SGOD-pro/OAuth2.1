import React from 'react';

export const RouteLoader: React.FC = () => {
  return (
    <div className="flex h-screen w-screen flex-col items-center justify-center gap-6 bg-background" role="status" aria-live="polite">
      <div className="flex flex-col items-center gap-1.5">
        <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-muted-foreground">
          SWYRA Systems
        </span>
        <div className="font-heading text-[34px] tracking-tighter text-foreground font-normal">
          M Auth
        </div>
      </div>
      <div className="flex w-64 flex-col gap-2.5">
        {/* 3 bars: 1st full length, 2nd 3/4 length, 3rd 1/2 length */}
        <div className="h-[2.5px] w-full bg-[#0066B1] rounded-full animate-m-line-1" />
        <div className="h-[2.5px] w-3/4 bg-[#1C69D4] rounded-full animate-m-line-2" />
        <div className="h-[2.5px] w-1/2 bg-[#E22718] rounded-full animate-m-line-3" />
      </div>
    </div>
  );
};
