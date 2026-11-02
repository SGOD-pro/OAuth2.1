import { useTheme } from "next-themes"
import { Toaster as Sonner, type ToasterProps } from "sonner"
import { HugeiconsIcon } from "@hugeicons/react"
import {
  CheckmarkCircle02Icon,
  InformationCircleIcon,
  Alert02Icon,
  MultiplicationSignCircleIcon,
  Loading03Icon,
} from "@hugeicons/core-free-icons"

const Toaster = ({ ...props }: ToasterProps) => {
  const { theme = "system", resolvedTheme } = useTheme()
  const activeTheme = (resolvedTheme || theme) as ToasterProps["theme"]

  return (
    <Sonner
      theme={activeTheme}
      className="toaster group"
      position="bottom-right"
      icons={{
        success: (
          <HugeiconsIcon
            icon={CheckmarkCircle02Icon}
            strokeWidth={2}
            className="size-4 text-emerald-500 dark:text-emerald-400 shrink-0"
          />
        ),
        info: (
          <HugeiconsIcon
            icon={InformationCircleIcon}
            strokeWidth={2}
            className="size-4 text-sky-500 dark:text-sky-400 shrink-0"
          />
        ),
        warning: (
          <HugeiconsIcon
            icon={Alert02Icon}
            strokeWidth={2}
            className="size-4 text-amber-500 dark:text-amber-400 shrink-0"
          />
        ),
        error: (
          <HugeiconsIcon
            icon={MultiplicationSignCircleIcon}
            strokeWidth={2}
            className="size-4 text-destructive shrink-0"
          />
        ),
        loading: (
          <HugeiconsIcon
            icon={Loading03Icon}
            strokeWidth={2}
            className="size-4 text-primary animate-spin shrink-0"
          />
        ),
      }}
      style={
        {
          "--normal-bg": "var(--card)",
          "--normal-text": "var(--card-foreground)",
          "--normal-border": "var(--border)",
          "--border-radius": "16px",
        } as React.CSSProperties
      }
      toastOptions={{
        classNames: {
          toast:
            "group toast group-[.toaster]:bg-card group-[.toaster]:text-card-foreground group-[.toaster]:border-border group-[.toaster]:shadow-float group-[.toaster]:rounded-xl font-sans text-xs border backdrop-blur-md",
          description: "group-[.toast]:text-muted-foreground font-sans text-xs",
          actionButton:
            "group-[.toast]:bg-primary group-[.toast]:text-primary-foreground group-[.toast]:rounded-pill group-[.toast]:px-3 group-[.toast]:py-1.5 group-[.toast]:text-xs font-medium hover:opacity-90 active:scale-[0.98] transition-all duration-120",
          cancelButton:
            "group-[.toast]:bg-secondary group-[.toast]:text-secondary-foreground group-[.toast]:rounded-pill group-[.toast]:px-3 group-[.toast]:py-1.5 group-[.toast]:text-xs font-medium hover:opacity-90 active:scale-[0.98] transition-all duration-120",
          closeButton:
            "group-[.toast]:border-border group-[.toast]:bg-card group-[.toast]:text-muted-foreground hover:group-[.toast]:text-foreground transition-colors duration-120",
          success:
            "group-[.toaster]:!border-emerald-500/25 dark:group-[.toaster]:!border-emerald-500/20",
          error:
            "group-[.toaster]:!border-destructive/30 dark:group-[.toaster]:!border-destructive/25",
          warning:
            "group-[.toaster]:!border-amber-500/25 dark:group-[.toaster]:!border-amber-500/20",
          info:
            "group-[.toaster]:!border-sky-500/25 dark:group-[.toaster]:!border-sky-500/20",
        },
      }}
      {...props}
    />
  )
}

export { Toaster }
