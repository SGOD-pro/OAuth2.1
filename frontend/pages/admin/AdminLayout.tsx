import React, { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { authClient, useSession } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { ThemeToggle } from '@/components/ThemeToggle';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Toaster } from '@/components/ui/sonner';
import { AppSidebar } from "@/components/app-sidebar"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
} from "@/components/ui/breadcrumb"
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
            "--sidebar-width": "19rem",
          } as React.CSSProperties
        }
      >
        <AppSidebar />
        <SidebarInset>
          <header className="flex h-16 shrink-0 items-center gap-2 px-4 border-b border-border/50 bg-background/50 backdrop-blur-sm z-50 sticky top-0">
            <div className="flex items-center gap-2">
              <SidebarTrigger className="-ml-1" />
              <Separator
                orientation="vertical"
                className="mr-2 h-4"
              />
              <Breadcrumb>
                <BreadcrumbList>
                  <BreadcrumbItem>
                    <BreadcrumbPage className="font-semibold text-foreground">NexusID Admin</BreadcrumbPage>
                  </BreadcrumbItem>
                </BreadcrumbList>
              </Breadcrumb>
            </div>
            <div className="ml-auto flex items-center gap-4">
              <ThemeToggle />
              <Separator orientation="vertical" className="h-6 hidden md:block" />
              <div className="flex items-center gap-3">
                <div className="text-right hidden sm:block">
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
              <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-destructive hover:bg-destructive/10" onClick={handleSignOut} title="Sign out">
                <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                  <polyline points="16 17 21 12 16 7" />
                  <line x1="21" y1="12" x2="9" y2="12" />
                </svg>
              </Button>
            </div>
          </header>
          <div className="flex-1 flex flex-col min-h-0 min-w-0 relative">
            <main className="flex-1 p-8 z-10 relative flex flex-col">
              {children}
            </main>

            <div className="fixed top-0 right-0 w-[800px] h-[800px] bg-primary/5 rounded-full blur-[100px] -z-0 pointer-events-none translate-x-1/2 -translate-y-1/2" />
            <div className="fixed bottom-0 left-[280px] w-[600px] h-[600px] bg-ring/5 rounded-full blur-[100px] -z-0 pointer-events-none -translate-x-1/4 translate-y-1/4" />
          </div>
          <Toaster />
        </SidebarInset>
      </SidebarProvider>
    </TooltipProvider>
  )
}
