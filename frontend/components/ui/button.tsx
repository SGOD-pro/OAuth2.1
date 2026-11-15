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
          "bg-primary text-primary-foreground hover:bg-[oklch(22.44%_0.0288_171.94)] active:bg-[oklch(18.49%_0.0228_174.75)] dark:bg-[oklch(97%_0.0082_91.48)] dark:text-[oklch(20.77%_0.0145_172.36)] dark:hover:bg-[oklch(92%_0.01_91.48)] dark:active:bg-[oklch(88%_0.015_91.48)] shadow-xs font-semibold",
        cta:
          "bg-tomato text-white hover:bg-tomato-hover active:bg-tomato-active shadow-xs font-semibold",
        accent:
          "bg-tomato text-white hover:bg-tomato-hover active:bg-tomato-active shadow-xs font-semibold",
        brand:
          "bg-evergreen text-white hover:bg-[oklch(22.44%_0.0288_171.94)] active:bg-[oklch(18.49%_0.0228_174.75)] shadow-xs font-semibold",
        supporting:
          "bg-accent text-accent-foreground hover:bg-accent/80 active:bg-accent/90 shadow-2xs font-semibold",
        outline:
          "border border-border bg-transparent text-foreground hover:bg-secondary/70 active:bg-secondary",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/80 active:bg-secondary/90",
        ghost:
          "bg-transparent text-foreground hover:bg-secondary/60 active:bg-secondary/80 hover:-translate-y-0",
        destructive:
          "bg-error-container text-destructive dark:bg-destructive dark:text-destructive-foreground hover:bg-[#FFC9C2] dark:hover:bg-destructive/90 active:bg-destructive/80 font-semibold",
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
