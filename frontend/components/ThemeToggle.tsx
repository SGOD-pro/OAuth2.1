import React from 'react';
import { useTheme } from 'next-themes';

export const ThemeToggle: React.FC = () => {
  const { setTheme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return <div className="h-8 w-14 rounded-full bg-secondary/50" />;
  }

  const isDark = resolvedTheme === 'dark';

  const switchTheme = () => {
    setTheme(isDark ? 'light' : 'dark');
  };

  const toggleTheme = () => {
    if (!document.startViewTransition) {
      switchTheme();
      return;
    }
    document.startViewTransition(switchTheme);
  };

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label="Toggle theme"
      className="relative h-8 w-14 rounded-full bg-secondary transition-colors duration-300 ease-in-out focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background cursor-pointer"
    >
      <span className="absolute left-1 top-1 flex h-6 w-6 items-center justify-center rounded-full bg-background shadow-sm transition-transform duration-300 ease-in-out dark:translate-x-6 text-foreground">
        {isDark ? (
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
          </svg>
        ) : (
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2" />
            <path d="M12 20v2" />
            <path d="m4.93 4.93 1.41 1.41" />
            <path d="m17.66 17.66 1.41 1.41" />
            <path d="M2 12h2" />
            <path d="M20 12h2" />
            <path d="m6.34 17.66-1.41 1.41" />
            <path d="m19.07 4.93-1.41 1.41" />
          </svg>
        )}
      </span>
    </button>
  );
};
