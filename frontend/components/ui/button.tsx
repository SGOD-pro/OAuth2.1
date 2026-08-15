import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { Slot } from "radix-ui"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "group relative inline-flex shrink-0 items-center justify-center rounded-pill font-sans text-sm font-medium tracking-wide whitespace-nowrap transition-all duration-300 outline-none select-none disabled:pointer-events-none disabled:opacity-50 cursor-pointer [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default:
          "overflow-hidden bg-primary text-primary-foreground hover:scale-[1.02] active:scale-[0.98]",
        outline:
          "border border-border bg-transparent text-foreground hover:bg-secondary/50 active:scale-[0.98]",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/80 active:scale-[0.98]",
        ghost:
          "bg-transparent text-foreground hover:bg-secondary/50 active:scale-[0.98]",
        destructive:
          "bg-destructive text-destructive-foreground hover:bg-destructive/90 active:scale-[0.98]",
        link: "text-accent underline-offset-4 hover:underline",
      },
      size: {
        default: "h-12 px-6 gap-2",
        sm: "h-9 px-4 text-xs gap-1.5",
        xs: "h-7 px-3 text-xs gap-1",
        lg: "h-14 px-8 text-base gap-2.5",
        icon: "size-10 rounded-full",
        "icon-sm": "size-8 rounded-full",
        "icon-xs": "size-6 rounded-full",
        "icon-lg": "size-12 rounded-full",
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

  if (variant === "default" && !asChild) {
    return (
      <Comp
        data-slot="button"
        data-variant={variant}
        data-size={size}
        className={cn(buttonVariants({ variant, size, className }))}
        {...props}
      >
        <span className="relative z-10 inline-flex items-center justify-center gap-2 group-hover:text-white transition-colors duration-300">
          {children}
        </span>
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 z-0 h-full w-0 bg-[linear-gradient(to_right,#0066B1_0%,#1C69D4_50%,#E22718_100%)] opacity-0 transition-all duration-500 ease-out group-hover:w-full group-hover:opacity-100"
        />
      </Comp>
    )
  }

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
