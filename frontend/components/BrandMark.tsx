import React from 'react';

interface BrandMarkProps {
  size?: 'sm' | 'default' | 'md' | 'lg';
  className?: string;
  showBadge?: boolean;
}

export const BrandMark: React.FC<BrandMarkProps> = ({ size = 'default', className = '', showBadge = false }) => {
  const isLg = size === 'lg';
  const isSm = size === 'sm';
  const isMd = size === 'md';

  return (
    <div className={`flex items-center gap-3 select-none ${className}`}>
      {/* BMW M-Series Motorsport Geometric Signature inside balanced badge */}
      <div className={`flex items-center justify-center shrink-0 rounded-xl bg-evergreen border border-border/80 shadow-xs transition-[transform,box-shadow] duration-140 ease-standard ${
        isLg ? 'size-11' : isSm ? 'size-7' : isMd ? 'size-8' : 'size-9'
      }`}>
        <div className="flex gap-[2.5px] items-center">
          <div 
            className={`${isLg ? 'w-1.5 h-5' : isSm ? 'w-[2px] h-3' : 'w-[2.5px] h-3.5'} bg-motorsport-light -skew-x-[18deg] rounded-[0.5px]`} 
            style={{ backgroundColor: 'var(--motorsport-light, oklch(50.27% 0.1425 250.05))' }}
          />
          <div 
            className={`${isLg ? 'w-1.5 h-5' : isSm ? 'w-[2px] h-3' : 'w-[2.5px] h-3.5'} bg-motorsport-dark -skew-x-[18deg] rounded-[0.5px]`} 
            style={{ backgroundColor: 'var(--motorsport-dark, oklch(53.81% 0.1804 258.30))' }}
          />
          <div 
            className={`${isLg ? 'w-1.5 h-5' : isSm ? 'w-[2px] h-3' : 'w-[2.5px] h-3.5'} bg-motorsport-red -skew-x-[18deg] rounded-[0.5px]`} 
            style={{ backgroundColor: 'var(--motorsport-red, oklch(58.76% 0.2212 29.82))' }}
          />
        </div>
      </div>

      <div className="flex flex-col min-w-0">
        <div className="flex items-center gap-2">
          <span className={`font-heading ${isLg ? 'text-2xl' : isSm ? 'text-sm' : isMd ? 'text-base' : 'text-base'} font-bold tracking-tight text-foreground leading-none`}>
            M Auth
          </span>
          {showBadge && (
            <span className="px-1.5 py-0.5 rounded-full font-mono text-[9px] font-semibold text-on-accent-cta bg-accent-cta border border-accent-cta/30 leading-none">
              IDP 2.1
            </span>
          )}
        </div>
        <span className={`font-sans ${isLg ? 'text-xs' : 'text-[11px]'} text-muted-foreground mt-1 leading-tight font-normal`}>
          by SWYRA
        </span>
      </div>
    </div>
  );
};
