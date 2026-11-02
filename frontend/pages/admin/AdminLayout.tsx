import React, { useCallback, useMemo, useState, useEffect, Suspense } from 'react';
import { useLocation, useNavigate, Outlet } from 'react-router-dom';
import { authClient, useSession } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Toaster } from '@/components/ui/sonner';
import { AppSidebar } from "@/components/app-sidebar"
import { Separator } from "@/components/ui/separator"
import { ContentSkeleton } from "@/components/ContentSkeleton"
import { cn } from "@/lib/utils"
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"

export const AdminLayout: React.FC = () => {
  const { data: session } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 8);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const user = (session as { user?: { name?: string; email?: string } } | null)?.user;

  const handleSignOut = useCallback(async () => {
    try {
      await authClient.signOut({});
    } catch {
      // ignore
    }
    navigate('/admin/login');
  }, [navigate]);

  const breadcrumbSection = useMemo(() => {
    const path = location.pathname.toLowerCase();
    if (path.includes('/clients')) return 'Applications';
    if (path.includes('/logs')) return 'Audit logs';
    if (path.includes('/security')) return 'Security';
    return 'Overview';
  }, [location.pathname]);

  return (
    <TooltipProvider>
      <div className="min-h-screen md:h-screen md:overflow-hidden bg-background text-foreground antialiased selection:bg-accent selection:text-accent-foreground">
        <SidebarProvider
          style={
            {
              "--sidebar-width": "264px",
            } as React.CSSProperties
          }
          className="p-2 sm:p-3 min-h-screen md:h-screen md:overflow-hidden"
        >
          <AppSidebar />
          <SidebarInset className="bg-card md:rounded-[24px] border border-border/70 shadow-xs min-h-[calc(100vh-24px)] md:h-[calc(100vh-24px)] flex flex-col overflow-hidden">
            <header
              className={cn(
                "sticky top-0 z-40 flex h-16 shrink-0 items-center justify-between gap-4 px-4 sm:px-8 border-b border-border/60 transition-colors duration-200",
                scrolled ? "glass shadow-xs" : "bg-card/90 backdrop-blur-sm"
              )}
            >
              <div className="flex items-center gap-3">
                <SidebarTrigger className="-ml-1 text-muted-foreground hover:text-foreground transition-colors" />
                <Separator orientation="vertical" className="h-4 bg-border/80" />
                <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 font-sans text-xs sm:text-sm">
                  <span className="text-muted-foreground">Console</span>
                  <span className="text-muted-foreground/60">/</span>
                  <span className="font-medium text-foreground">{breadcrumbSection}</span>
                </nav>
                <div className="hidden lg:flex items-center gap-1.5 ml-3 pl-3 border-l border-border/80">
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-pill text-[11px] font-sans font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                    <span className="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    Engine Active
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2.5 sm:gap-3">
                <ThemeToggle />
                <Separator orientation="vertical" className="h-4 bg-border/80 hidden sm:block" />
                
                <div className="flex items-center gap-2.5 pl-1">
                  <div className="text-right hidden md:block">
                    <div className="flex items-center gap-1.5 justify-end">
                      <p className="font-sans text-xs font-medium text-foreground leading-none">
                        {user?.name || 'Administrator'}
                      </p>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold tracking-wider uppercase bg-primary/10 text-primary border border-primary/20">
                        SUPER
                      </span>
                    </div>
                    <p className="font-mono text-[11px] text-muted-foreground mt-1 leading-none">
                      {user?.email ?? ''}
                    </p>
                  </div>
                  <div 
                    className="size-8 rounded-full border border-border bg-secondary flex items-center justify-center font-mono text-xs text-foreground font-semibold shrink-0 shadow-2xs"
                    aria-hidden="true"
                  >
                    {(user?.name || 'A')[0].toUpperCase()}
                  </div>
                </div>

                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button 
                      variant="ghost" 
                      size="icon" 
                      className="size-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10 rounded-pill transition-colors" 
                      onClick={handleSignOut} 
                      aria-label="Sign out"
                    >
                      <svg className="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                        <polyline points="16 17 21 12 16 7" />
                        <line x1="21" y1="12" x2="9" y2="12" />
                      </svg>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="bottom">
                    Sign out
                  </TooltipContent>
                </Tooltip>
              </div>
            </header>

            <main className="flex-1 w-full max-w-[1400px] mx-auto p-4 sm:p-6 lg:p-8 flex flex-col md:overflow-y-auto">
              <Suspense fallback={<ContentSkeleton />}>
                <Outlet />
              </Suspense>
            </main>
            <Toaster />
          </SidebarInset>
        </SidebarProvider>
      </div>
    </TooltipProvider>
  );
};
