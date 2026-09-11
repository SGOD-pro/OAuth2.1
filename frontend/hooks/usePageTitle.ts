import { useEffect } from 'react';

/**
 * Hook to set the document title according to the M Auth specification:
 * Pattern: "[Page Name] · M Auth"
 */
export function usePageTitle(pageTitle: string) {
  useEffect(() => {
    const previousTitle = document.title;
    document.title = `${pageTitle} · M Auth`;
    return () => {
      document.title = previousTitle;
    };
  }, [pageTitle]);
}
