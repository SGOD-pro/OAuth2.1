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
    let ticking = false;
    const handleScroll = () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          const isScrolled = window.scrollY > 8;
          setScrolled((prev) => (prev !== isScrolled ? isScrolled : prev));
          ticking = false;
        });
        ticking = true;
      }
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
      <div className="min-h-screen flex flex-col bg-background text-foreground antialiased selection:bg-accent selection:text-accent-foreground">
        <SidebarProvider
          style={
            {
              "--sidebar-width": "264px",
            } as React.CSSProperties
          }
          className="p-2 sm:p-3 min-h-screen flex-1 w-full"
        >
          <AppSidebar />
          <SidebarInset className="bg-card md:rounded-[24px] border border-border/70 shadow-xs min-h-[calc(100vh-24px)] flex flex-col overflow-clip">
            <header
              className={cn(
                "sticky top-0 z-40 flex h-16 shrink-0 items-center justify-between gap-4 px-4 sm:px-8 border-b border-border/60 transition-colors duration-200 md:rounded-t-[23px]",
                scrolled ? "glass shadow-xs" : "bg-card/90 backdrop-blur-sm"
              )}
            >
              <div className="flex items-center gap-3 min-w-0">
                <SidebarTrigger className="-ml-1 text-muted-foreground hover:text-foreground transition-colors shrink-0" />
                <Separator orientation="vertical" className="h-4 self-center my-auto bg-border/80 shrink-0" />
                <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 font-sans text-xs sm:text-sm min-w-0 truncate">
                  <span className="text-muted-foreground shrink-0">Console</span>
                  <span className="text-muted-foreground/60 shrink-0">/</span>
                  <span className="font-medium text-foreground truncate">{breadcrumbSection}</span>
                </nav>
              </div>

              <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
                <ThemeToggle />
                <Separator orientation="vertical" className="h-4 self-center my-auto bg-border/80 hidden sm:block shrink-0" />
                
                <div className="flex items-center gap-2.5 pl-1">
                  <div className="text-right hidden xl:block">
                    <div className="flex items-center gap-1.5 justify-end">
                      <p className="font-sans text-xs font-medium text-foreground leading-none">
                        {user?.name || 'Administrator'}
                      </p>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold tracking-wider uppercase bg-primary/10 text-primary border border-primary/20">
                        SUPER
                      </span>
                    </div>
                    <p className="font-mono text-[11px] text-muted-foreground mt-1 leading-none max-w-[180px] truncate">
                      {user?.email ?? ''}
                    </p>
                  </div>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <div 
                        className="size-8 rounded-full border border-border bg-secondary flex items-center justify-center font-mono text-xs text-foreground font-semibold shrink-0 shadow-2xs cursor-default"
                        aria-label={`Signed in as ${user?.email || 'Administrator'}`}
                      >
                        {(user?.name || 'A')[0].toUpperCase()}
                      </div>
                    </TooltipTrigger>
                    <TooltipContent side="bottom" className="text-xs xl:hidden">
                      <p className="font-medium">{user?.name || 'Administrator'}</p>
                      <p className="font-mono text-[11px] text-muted-foreground">{user?.email}</p>
                    </TooltipContent>
                  </Tooltip>
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

            <main className="flex-1 w-full max-w-[1400px] mx-auto p-4 sm:p-6 lg:p-8 flex flex-col">
              <Suspense fallback={<ContentSkeleton />}>
                <div key={location.pathname} className="animate-content-reveal flex flex-col flex-1">
                  <Outlet />
                </div>
              </Suspense>
            </main>
          </SidebarInset>
        </SidebarProvider>
      </div>
      <Toaster />
    </TooltipProvider>
  );
};
