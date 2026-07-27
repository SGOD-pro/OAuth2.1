import React, { useCallback } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { authClient, useSession } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { ThemeToggle } from '@/components/ThemeToggle';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Toaster } from '@/components/ui/sonner';

const navItems = [
  {
    to: '/admin',
    label: 'Overview',
    end: true,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" />
        <rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" />
      </svg>
    ),
  },
  {
    to: '/admin/clients',
    label: 'Applications',
    end: false,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
      </svg>
    ),
  },
  {
    to: '/admin/logs',
    label: 'Audit Logs',
    end: false,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
  },
  {
    to: '/admin/security',
    label: 'Security',
    end: false,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
];

export const AdminLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { data: session } = useSession();
  const navigate = useNavigate();

  const handleSignOut = useCallback(async () => {
    await authClient.signOut();
    navigate('/admin/login', { viewTransition: true });
  }, [navigate]);

  return (
    <TooltipProvider>
      <div className="min-h-screen w-full bg-background flex">
        {/* Sidebar */}
        <aside className="w-[280px] border-r border-border bg-card/40 backdrop-blur-md flex flex-col transition-colors">
          <div className="p-6 flex items-center gap-3 border-b border-border/50">
            <div className="h-10 w-10 rounded-xl bg-primary flex items-center justify-center text-primary-foreground">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-sparkle"><path d="M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594z" /></svg>
            </div>
            <div>
              <p className="text-sm font-semibold font-heading text-foreground">NexusID</p>
              <p className="text-xs uppercase tracking-widest text-muted-foreground font-mono">Enterprise</p>
            </div>
          </div>

          <nav className="flex-1 px-4 py-6 flex flex-col gap-1">
            {navItems.map(({ to, label, end, icon }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                viewTransition
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-primary/10 text-primary dark:bg-primary/20'
                      : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                  }`
                }
              >
                <span className="opacity-80">{icon}</span>
                {label}
              </NavLink>
            ))}
          </nav>

          <div className="p-4 border-t border-border/50">
            <div className="flex items-center justify-between px-2 mb-4">
              <span className="text-xs font-medium text-muted-foreground">Theme</span>
              <ThemeToggle />
            </div>
            <Button variant="ghost" className="w-full justify-start text-muted-foreground hover:text-destructive hover:bg-destructive/10" onClick={handleSignOut}>
              <svg className="mr-3 h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                <polyline points="16 17 21 12 16 7" />
                <line x1="21" y1="12" x2="9" y2="12" />
              </svg>
              Sign out
            </Button>
          </div>
        </aside>

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-h-screen bg-accent/30 overflow-hidden relative">
           <header className="h-16 flex items-center justify-end px-8 border-b border-border/50 bg-background/50 backdrop-blur-sm z-10">
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <p className="text-sm font-medium text-foreground">
                    {(session?.user as { name?: string })?.name || 'Administrator'}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {(session?.user as { email?: string })?.email ?? ''}
                  </p>
                </div>
                <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center text-primary font-bold text-xs">
                  {((session?.user as { name?: string })?.name || 'A')[0].toUpperCase()}
                </div>
              </div>
           </header>
           
           <main className="flex-1 overflow-y-auto p-8 z-10 relative">
             {children}
           </main>
           
           {/* Subtle background decoration for the main area */}
           <div className="fixed top-0 right-0 w-[800px] h-[800px] bg-primary/5 rounded-full blur-[100px] -z-0 pointer-events-none translate-x-1/2 -translate-y-1/2" />
           <div className="fixed bottom-0 left-[280px] w-[600px] h-[600px] bg-ring/5 rounded-full blur-[100px] -z-0 pointer-events-none -translate-x-1/4 translate-y-1/4" />
        </div>
      </div>
      <Toaster />
    </TooltipProvider>
  );
};
