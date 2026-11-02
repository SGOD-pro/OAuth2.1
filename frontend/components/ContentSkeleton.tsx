import React, { useState, useEffect } from 'react';
import { Skeleton } from '@/components/ui/skeleton';

export const ContentSkeleton: React.FC = () => {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), 150);
    return () => clearTimeout(timer);
  }, []);

  if (!visible) return null;

  return (
    <div className="flex flex-col gap-6 w-full animate-in fade-in duration-200" aria-busy="true" aria-label="Loading content">
      <div className="flex flex-col gap-2">
        <Skeleton className="h-8 w-56 rounded-md" />
        <Skeleton className="h-4 w-80 rounded-md" />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Skeleton className="h-28 rounded-lg" />
        <Skeleton className="h-28 rounded-lg" />
        <Skeleton className="h-28 rounded-lg" />
        <Skeleton className="h-28 rounded-lg" />
      </div>

      <div className="flex flex-col gap-3 rounded-lg border border-border p-6 bg-card">
        <div className="flex justify-between items-center pb-4 border-b border-border/50">
          <Skeleton className="h-5 w-40 rounded-md" />
          <Skeleton className="h-8 w-24 rounded-pill" />
        </div>
        <div className="flex flex-col gap-3 pt-2">
          <Skeleton className="h-10 w-full rounded-md" />
          <Skeleton className="h-10 w-full rounded-md" />
          <Skeleton className="h-10 w-full rounded-md" />
          <Skeleton className="h-10 w-full rounded-md" />
        </div>
      </div>
    </div>
  );
};

