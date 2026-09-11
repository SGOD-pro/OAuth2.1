import React from 'react';

interface BrandMarkProps {
  size?: 'sm' | 'default' | 'md' | 'lg';
  className?: string;
}

export const BrandMark: React.FC<BrandMarkProps> = ({ size = 'default', className = '' }) => {
  const isLg = size === 'lg';
  const isSm = size === 'sm';

  return (
    <div className={`flex items-center gap-2.5 select-none ${className}`}>
      {/* BMW M-Series Inspired Motorsport Geometric Signature */}
      <div className="flex gap-0.5 items-center shrink-0">
        <div className={`${isLg ? 'w-1 h-5' : isSm ? 'w-[2.5px] h-3' : 'w-[3px] h-4'} bg-[#0066B1] -skew-x-12 rounded-[0.5px]`} />
        <div className={`${isLg ? 'w-1 h-5' : isSm ? 'w-[2.5px] h-3' : 'w-[3px] h-4'} bg-[#1C69D4] -skew-x-12 rounded-[0.5px]`} />
        <div className={`${isLg ? 'w-1 h-5' : isSm ? 'w-[2.5px] h-3' : 'w-[3px] h-4'} bg-[#E22718] -skew-x-12 rounded-[0.5px]`} />
      </div>

      <div className="flex flex-col leading-none">
        <span className={`font-heading ${isLg ? 'text-2xl' : isSm ? 'text-sm' : 'text-base'} font-semibold tracking-tight text-foreground`}>
          M Auth
        </span>
        <span className={`font-sans ${isLg ? 'text-xs' : 'text-[11px]'} text-muted-foreground mt-0.5 font-normal tracking-normal`}>
          by SWYRA
        </span>
      </div>
    </div>
  );
};
