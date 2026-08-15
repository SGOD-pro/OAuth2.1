import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { Slot } from "radix-ui"

import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "group/badge inline-flex h-6 w-fit shrink-0 items-center justify-center gap-1.5 overflow-hidden rounded-pill border px-2.5 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-all",
  {
    variants: {
      variant: {
        default:
          "border-primary/20 bg-primary/10 text-primary",
        secondary:
          "border-border bg-secondary text-secondary-foreground",
        destructive:
          "border-destructive/30 bg-destructive/10 text-destructive",
        outline:
          "border-border bg-transparent text-foreground",
        success:
          "border-emerald-500/30 bg-emerald-500/10 text-emerald-500",
        accent:
          "border-accent/30 bg-accent/10 text-accent",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Badge({
  className,
  variant = "default",
  asChild = false,
  ...props
}: React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot.Root : "span"

  return (
    <Comp
      data-slot="badge"
      data-variant={variant}
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  )
}

export { Badge, badgeVariants }
