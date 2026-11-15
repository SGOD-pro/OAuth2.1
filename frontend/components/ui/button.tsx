import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { Slot } from "radix-ui"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center rounded-[10px] font-sans text-sm font-semibold whitespace-nowrap transition-[color,background-color,border-color,box-shadow,transform] duration-140 outline-none select-none disabled:pointer-events-none disabled:opacity-50 cursor-pointer hover:-translate-y-px active:translate-y-0 active:scale-[0.99] focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground hover:bg-primary-hover active:bg-primary-active shadow-xs font-semibold",
        cta:
          "bg-accent-cta text-on-accent-cta hover:bg-accent-cta-hover active:bg-accent-cta-active shadow-xs font-semibold",
        accent:
          "bg-accent-cta text-on-accent-cta hover:bg-accent-cta-hover active:bg-accent-cta-active shadow-xs font-semibold",
        brand:
          "bg-brand text-on-brand hover:bg-brand-hover active:bg-brand-active shadow-xs font-semibold",
        supporting:
          "bg-accent text-accent-foreground hover:bg-accent/80 active:bg-accent/90 shadow-2xs font-semibold",
        outline:
          "border border-border bg-transparent text-foreground hover:bg-secondary/70 active:bg-secondary",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/80 active:bg-secondary/90",
        ghost:
          "bg-transparent text-foreground hover:bg-secondary/60 active:bg-secondary/80 hover:-translate-y-0",
        destructive:
          "bg-destructive text-destructive-foreground hover:bg-destructive-hover active:bg-destructive-active shadow-xs font-semibold",
        link: "text-accent underline-offset-4 hover:underline p-0 h-auto rounded-none hover:-translate-y-0 active:scale-100",
      },
      size: {
        default: "min-h-[44px] h-11 px-5 gap-2",
        sm: "min-h-[36px] h-9 px-3.5 text-xs gap-1.5",
        xs: "min-h-[28px] h-7 px-2.5 text-xs gap-1",
        lg: "min-h-[48px] h-12 px-6 text-base gap-2.5 font-medium",
        icon: "size-11 min-h-[44px] rounded-[10px]",
        "icon-sm": "size-9 min-h-[36px] rounded-[8px]",
        "icon-xs": "size-7 min-h-[28px] rounded-[6px]",
        "icon-lg": "size-12 min-h-[48px] rounded-[10px]",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  asChild = false,
  children,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot.Root : "button"

  return (
    <Comp
      data-slot="button"
      data-variant={variant}
      data-size={size}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    >
      {children}
    </Comp>
  )
}

export { Button, buttonVariants }
