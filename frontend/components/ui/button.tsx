import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { Slot } from "radix-ui"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center rounded-pill font-sans text-sm font-medium whitespace-nowrap transition-[color,background-color,border-color,box-shadow,transform] duration-140 outline-none select-none disabled:pointer-events-none disabled:opacity-50 cursor-pointer hover:-translate-y-px active:translate-y-0 active:scale-[0.99] focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground hover:bg-primary/90 active:bg-primary/80 shadow-xs",
        outline:
          "border border-border bg-transparent text-foreground hover:bg-secondary/70 active:bg-secondary",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/80 active:bg-secondary/90",
        ghost:
          "bg-transparent text-foreground hover:bg-secondary/60 active:bg-secondary/80 hover:-translate-y-0",
        destructive:
          "bg-destructive text-destructive-foreground hover:bg-destructive/90 active:bg-destructive/80",
        link: "text-accent underline-offset-4 hover:underline p-0 h-auto rounded-none hover:-translate-y-0 active:scale-100",
      },
      size: {
        default: "h-11 px-5 gap-2",
        sm: "h-9 px-3.5 text-xs gap-1.5",
        xs: "h-7 px-2.5 text-xs gap-1",
        lg: "h-12 px-6 text-base gap-2.5 font-medium",
        icon: "size-10 rounded-pill",
        "icon-sm": "size-9 rounded-pill",
        "icon-xs": "size-7 rounded-pill",
        "icon-lg": "size-11 rounded-pill",
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
