import * as React from "react"
import { NavLink } from "react-router-dom"
import { useSession } from "@/lib/auth-client"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { BrandMark } from "@/components/BrandMark"

const navItems = [
  {
    to: '/admin',
    label: 'Overview',
    end: true,
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="14" width="7" height="7" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
      </svg>
    ),
  },
  {
    to: '/admin/clients',
    label: 'Applications',
    end: false,
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
      </svg>
    ),
  },
  {
    to: '/admin/logs',
    label: 'Audit logs',
    end: false,
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
  },
  {
    to: '/admin/security',
    label: 'Security',
    end: false,
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
];

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const { data: session } = useSession();
  const twoFactorEnabled = (session?.user as { twoFactorEnabled?: boolean } | undefined)?.twoFactorEnabled;

  return (
    <Sidebar variant="inset" className="w-[264px] border-r border-sidebar-border bg-sidebar" {...props}>
      <SidebarHeader className="h-[64px] flex items-center px-4 border-b border-sidebar-border">
        <BrandMark size="default" />
      </SidebarHeader>

      <SidebarContent className="p-3">
        <SidebarGroup>
          <SidebarMenu className="gap-1.5">
            {navItems.map(({ to, label, end, icon }) => (
              <SidebarMenuItem key={to}>
                <NavLink
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    `group relative flex items-center gap-3 px-3.5 h-11 rounded-lg text-sm font-sans transition-colors duration-140 outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring ${
                      isActive
                        ? 'bg-sidebar-accent text-sidebar-accent-foreground font-medium shadow-2xs'
                        : 'text-sidebar-foreground/75 hover:bg-sidebar-accent/60 hover:text-sidebar-foreground'
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      {isActive && (
                        <div
                          aria-hidden="true"
                          className="absolute left-1.5 top-1/2 -translate-y-1/2 w-1 h-5 rounded-full bg-primary transition-transform duration-200"
                        />
                      )}
                      <span className="shrink-0 opacity-80 group-hover:opacity-100 transition-opacity pl-1">
                        {icon}
                      </span>
                      <span>{label}</span>
                    </>
                  )}
                </NavLink>
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>

      {twoFactorEnabled === false && (
        <SidebarFooter className="p-3">
          <div className="relative overflow-hidden rounded-xl border border-primary/20 bg-[#102D25] p-3.5 text-white shadow-xs">
            <svg
              aria-hidden="true"
              className="absolute inset-0 w-full h-full opacity-[0.08] pointer-events-none"
              viewBox="0 0 200 120"
              preserveAspectRatio="none"
            >
              <path
                d="M0,20 Q50,60 100,20 T200,30 M0,50 Q70,90 130,40 T200,60 M0,80 Q40,110 110,70 T200,90"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
              />
            </svg>
            <div className="relative z-10 flex flex-col gap-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-[#B7C9AD]">
                <svg className="size-3.5 text-[#B7C9AD]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>Security notice</span>
              </div>
              <p className="text-xs text-[#EEECE5]/90 leading-snug">
                Two-factor is off. This account can change credentials for every application.
              </p>
              <NavLink
                to="/admin/security"
                className="mt-1 inline-flex items-center justify-center h-8 px-3 rounded-pill bg-[#B7C9AD] text-[#0A1310] text-xs font-medium hover:bg-[#B7C9AD]/90 transition-colors"
              >
                Turn on two-factor
              </NavLink>
            </div>
          </div>
        </SidebarFooter>
      )}
    </Sidebar>
  )
}
