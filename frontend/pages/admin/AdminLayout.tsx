import React, { useCallback, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { authClient, useSession } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Toaster } from '@/components/ui/sonner';
import { AppSidebar } from "@/components/app-sidebar"
import { Separator } from "@/components/ui/separator"
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"

export const AdminLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { data: session } = useSession();
  const navigate = useNavigate();
  const location = useLocation();

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
      <SidebarProvider
        style={
          {
            "--sidebar-width": "232px",
          } as React.CSSProperties
        }
      >
        <AppSidebar />
        <SidebarInset className="bg-background min-h-screen flex flex-col">
          <header className="flex h-[60px] shrink-0 items-center justify-between gap-3 px-4 sm:px-6 border-b border-border/80 bg-background/95 backdrop-blur-md sticky top-0 z-40">
            <div className="flex items-center gap-3">
              <SidebarTrigger className="-ml-1 text-muted-foreground hover:text-foreground transition-colors" />
              <Separator orientation="vertical" className="h-4 bg-border" />
              <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 font-sans text-xs sm:text-sm">
                <span className="text-muted-foreground">Admin</span>
                <span className="text-muted-foreground/60">/</span>
                <span className="font-medium text-foreground">{breadcrumbSection}</span>
              </nav>
            </div>

            <div className="flex items-center gap-2.5 sm:gap-3">
              <ThemeToggle />
              <Separator orientation="vertical" className="h-4 bg-border hidden sm:block" />
              
              <div className="flex items-center gap-2.5 pl-1">
                <div className="text-right hidden md:block">
                  <p className="font-sans text-xs font-medium text-foreground leading-none">
                    {user?.name || 'Administrator'}
                  </p>
                  <p className="font-mono text-[11px] text-muted-foreground mt-1 leading-none">
                    {user?.email ?? ''}
                  </p>
                </div>
                <div 
                  className="size-8 rounded-full border border-border bg-secondary flex items-center justify-center font-mono text-xs text-foreground font-semibold shrink-0"
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
                    className="size-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10 rounded-md transition-colors" 
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

          <main className="flex-1 w-full max-w-[1440px] mx-auto p-4 sm:p-6 lg:p-[34px] flex flex-col">
            {children}
          </main>
          <Toaster />
        </SidebarInset>
      </SidebarProvider>
    </TooltipProvider>
  )
}
