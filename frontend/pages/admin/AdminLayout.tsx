import React, { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { authClient, useSession } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { ThemeToggle } from '@/components/ThemeToggle';
import { TooltipProvider } from '@/components/ui/tooltip';
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

  const handleSignOut = useCallback(async () => {
    await authClient.signOut();
    navigate('/admin/login', { viewTransition: true });
  }, [navigate]);

  return (
    <TooltipProvider>
      <SidebarProvider
        style={
          {
            "--sidebar-width": "260px",
          } as React.CSSProperties
        }
      >
        <AppSidebar />
        <SidebarInset className="bg-background min-h-screen flex flex-col">
          <header className="flex h-16 shrink-0 items-center justify-between gap-2 px-6 border-b border-border/50 bg-background/80 backdrop-blur-md sticky top-0 z-40">
            <div className="flex items-center gap-3">
              <SidebarTrigger className="-ml-1 text-muted-foreground hover:text-foreground" />
              <Separator orientation="vertical" className="h-4" />
              <span className="font-heading text-sm font-medium text-foreground tracking-tight">
                <span className="text-muted-foreground font-mono text-xs mr-1">SWYRA //</span> M Telemetry Hub
              </span>
            </div>

            <div className="flex items-center gap-4">
              <ThemeToggle />
              <Separator orientation="vertical" className="h-6 hidden md:block" />
              <div className="flex items-center gap-3">
                <div className="text-right hidden sm:block">
                  <p className="font-sans text-xs font-medium text-foreground">
                    {(session?.user as { name?: string })?.name || 'Administrator'}
                  </p>
                  <p className="font-mono text-[10px] text-muted-foreground">
                    {(session?.user as { email?: string })?.email ?? ''}
                  </p>
                </div>
                <div className="size-8 rounded-full border border-border bg-secondary flex items-center justify-center font-mono text-xs text-foreground font-semibold">
                  {((session?.user as { name?: string })?.name || 'A')[0].toUpperCase()}
                </div>
              </div>

              <Button 
                variant="ghost" 
                size="icon-sm" 
                className="text-muted-foreground hover:text-destructive hover:bg-destructive/10" 
                onClick={handleSignOut} 
                title="Sign out"
              >
                <svg className="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                  <polyline points="16 17 21 12 16 7" />
                  <line x1="21" y1="12" x2="9" y2="12" />
                </svg>
              </Button>
            </div>
          </header>

          <main className="flex-1 p-6 sm:p-8 lg:p-[34px] relative flex flex-col">
            {/* Subtle telemetry grid */}
            <div 
              className="absolute inset-0 pointer-events-none opacity-[0.015] -z-10"
              style={{
                backgroundImage: `radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)`,
                backgroundSize: '24px 24px'
              }}
            />
            {children}
          </main>
          <Toaster />
        </SidebarInset>
      </SidebarProvider>
    </TooltipProvider>
  )
}
